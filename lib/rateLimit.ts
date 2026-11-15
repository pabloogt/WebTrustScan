import { createHash } from "node:crypto";

export type RateLimitResult = {
  allowed: boolean;
  /** Segundos hasta que se puede volver a intentar (0 si está permitido). */
  retryAfterSeconds: number;
  /** Qué almacén respondió: útil para detectar que se está en modo degradado. */
  store: "memory" | "upstash";
};

/**
 * Almacén de contadores. `increment` suma 1 al contador de la clave, que
 * caduca solo pasado `ttlMs`, y devuelve el valor resultante.
 */
export interface CounterStore {
  readonly name: "memory" | "upstash";
  increment(key: string, ttlMs: number): Promise<number>;
}

/* ---------- almacén en memoria ---------- */

/**
 * Contadores en memoria del proceso. Válido para desarrollo y para una única
 * instancia. En serverless cada instancia tiene su propia memoria, así que el
 * límite real se multiplica por el número de instancias.
 */
export function createMemoryStore(
  options: { maxKeys?: number; now?: () => number } = {},
): CounterStore {
  const { maxKeys = 10_000, now = Date.now } = options;
  const counters = new Map<string, { count: number; expiresAt: number }>();

  function prune(current: number) {
    for (const [key, entry] of counters) {
      if (entry.expiresAt <= current) counters.delete(key);
    }

    // Si sigue lleno tras limpiar caducados, se descartan los más antiguos.
    while (counters.size >= maxKeys) {
      const oldest = counters.keys().next().value;
      if (oldest === undefined) break;
      counters.delete(oldest);
    }
  }

  return {
    name: "memory",
    async increment(key, ttlMs) {
      const current = now();
      const entry = counters.get(key);

      if (entry && entry.expiresAt > current) {
        entry.count += 1;
        return entry.count;
      }

      if (counters.size >= maxKeys) prune(current);
      counters.set(key, { count: 1, expiresAt: current + ttlMs });
      return 1;
    },
  };
}

/* ---------- almacén compartido: Upstash Redis (REST) ---------- */

export type UpstashConfig = {
  url: string;
  token: string;
  /** Tiempo máximo de espera antes de pasar al modo degradado. */
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
};

/**
 * Contadores en Upstash Redis usando su API REST (sin dependencias ni
 * conexiones TCP, así que funciona en serverless). Cada incremento es una
 * única petición HTTP con dos comandos: INCR y PEXPIRE.
 */
export function createUpstashStore(config: UpstashConfig): CounterStore {
  const { token, timeoutMs = 1_500, fetchImpl = fetch } = config;
  const endpoint = `${config.url.replace(/\/+$/, "")}/pipeline`;

  return {
    name: "upstash",
    async increment(key, ttlMs) {
      const response = await fetchImpl(endpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify([
          ["INCR", key],
          ["PEXPIRE", key, ttlMs],
        ]),
        cache: "no-store",
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!response.ok) {
        throw new Error(`Upstash respondió ${response.status}`);
      }

      const results: unknown = await response.json();
      const count = Array.isArray(results)
        ? (results[0] as { result?: unknown } | undefined)?.result
        : undefined;

      if (typeof count !== "number" || !Number.isInteger(count) || count < 1) {
        throw new Error("Respuesta inesperada de Upstash");
      }

      return count;
    },
  };
}

/** Lee la configuración de Upstash de las variables que crea su integración. */
export function upstashConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): UpstashConfig | null {
  const url = env.UPSTASH_REDIS_REST_URL ?? env.KV_REST_API_URL;
  const token = env.UPSTASH_REDIS_REST_TOKEN ?? env.KV_REST_API_TOKEN;

  if (!url || !token || !/^https:\/\//i.test(url)) return null;

  return { url, token };
}

/* ---------- limitador ---------- */

export type RateLimiterOptions = {
  limit: number;
  windowMs: number;
  /** Prefijo para separar distintos límites en el mismo almacén. */
  prefix: string;
  store: CounterStore;
  /**
   * Almacén de reserva si el principal falla (red, caída, cuota agotada).
   * Así un fallo de Upstash degrada el límite, pero no lo desactiva ni tumba
   * el servicio.
   */
  fallback?: CounterStore;
  now?: () => number;
  onStoreError?: (error: unknown) => void;
};

/** Las IPs no se guardan en claro en el almacén compartido. */
function hashKey(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 32);
}

/**
 * Límite de ventana fija. La ventana va incluida en la clave, de modo que
 * todas las instancias cuentan sobre el mismo contador y este caduca solo.
 */
export function createRateLimiter(options: RateLimiterOptions) {
  const { limit, windowMs, prefix, store, fallback } = options;
  const now = options.now ?? Date.now;

  // Claves ya bloqueadas en la ventana actual. Evita consultar (y pagar) el
  // almacén compartido por cada petición de un cliente que ya superó el límite.
  const blockedUntil = new Map<string, number>();
  const MAX_BLOCKED = 5_000;

  return async function check(key: string): Promise<RateLimitResult> {
    const current = now();
    const windowIndex = Math.floor(current / windowMs);
    const storeKey = `rl:${prefix}:${hashKey(key)}:${windowIndex}`;
    const windowEndsAt = (windowIndex + 1) * windowMs;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((windowEndsAt - current) / 1000),
    );

    const blockedEnd = blockedUntil.get(storeKey);

    if (blockedEnd !== undefined) {
      if (blockedEnd > current) {
        return { allowed: false, retryAfterSeconds, store: store.name };
      }
      blockedUntil.delete(storeKey);
    }

    let count: number;
    let used = store;

    try {
      count = await store.increment(storeKey, windowMs);
    } catch (error) {
      options.onStoreError?.(error);

      if (!fallback) throw error;

      used = fallback;
      count = await fallback.increment(storeKey, windowMs);
    }

    const allowed = count <= limit;

    if (!allowed) {
      if (blockedUntil.size >= MAX_BLOCKED) {
        for (const [blockedKey, end] of blockedUntil) {
          if (end <= current) blockedUntil.delete(blockedKey);
        }
        if (blockedUntil.size >= MAX_BLOCKED) blockedUntil.clear();
      }
      blockedUntil.set(storeKey, windowEndsAt);
    }

    return {
      allowed,
      retryAfterSeconds: allowed ? 0 : retryAfterSeconds,
      store: used.name,
    };
  };
}
