import { createHmac } from "node:crypto";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { getClientIdentity } from "./clientIp";

/**
 * Límites de frecuencia y de concurrencia compartidos entre instancias.
 *
 * - Con Upstash configurado se usa `@upstash/ratelimit` sobre Redis.
 * - En desarrollo y tests, memoria del proceso.
 * - En producción SIN Upstash el servicio NO pasa a funcionar sin límites:
 *   responde 503 (`LimitsUnavailableError`). Solo `RATE_LIMIT_ALLOW_MEMORY=true`
 *   permite, de forma explícita, usar la memoria por instancia.
 *
 * Las claves nunca contienen una IP ni un correo en claro: se guarda un HMAC
 * con una clave secreta del servidor.
 */

type Env = Record<string, string | undefined>;
type HeaderReader = { get(name: string): string | null };

export type LimitResult = {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
};

export class RateLimitedError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super("Demasiadas peticiones.");
    this.name = "RateLimitedError";
  }
}

/** El control de abuso no está disponible: no se atiende la petición. */
export class LimitsUnavailableError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "LimitsUnavailableError";
  }
}

export type LimitsMode = "upstash" | "memory" | "unavailable";

const isProductionLike = (env: Env) =>
  env.NODE_ENV === "production" || env.VERCEL === "1";

/**
 * Credenciales de Upstash. Acepta los nombres de Upstash (`UPSTASH_REDIS_*`)
 * y los que crea la integración de Upstash del Marketplace de Vercel
 * (`KV_REST_API_*`), igual que el limitador del analizador.
 */
export function upstashCredentials(env: Env = process.env): { url: string; token: string } | null {
  const url = env.UPSTASH_REDIS_REST_URL || env.KV_REST_API_URL;
  const token = env.UPSTASH_REDIS_REST_TOKEN || env.KV_REST_API_TOKEN;

  return url && token && /^https:\/\//i.test(url) ? { url, token } : null;
}

/**
 * Qué falta para tener control de abuso en producción. Solo nombres de
 * variables, nunca sus valores: va al log del servidor para diagnosticar.
 */
export function missingLimitsConfig(env: Env = process.env): string[] {
  const missing: string[] = [];

  if (!upstashCredentials(env) && env.RATE_LIMIT_ALLOW_MEMORY !== "true") {
    missing.push(
      "UPSTASH_REDIS_REST_URL y UPSTASH_REDIS_REST_TOKEN (o KV_REST_API_URL y KV_REST_API_TOKEN); la URL debe empezar por https://",
    );
  }
  if (!env.IP_HASH_SECRET || env.IP_HASH_SECRET.length < 32) {
    missing.push("IP_HASH_SECRET (mínimo 32 caracteres)");
  }
  return missing;
}

export function limitsMode(env: Env = process.env): LimitsMode {
  if (upstashCredentials(env)) return "upstash";
  if (isProductionLike(env) && env.RATE_LIMIT_ALLOW_MEMORY !== "true") {
    return "unavailable";
  }
  return "memory";
}

/** Clave fija, solo para desarrollo y tests. Nunca se usa en producción. */
const DEV_HASH_SECRET = "webtrustscan-desarrollo-local-sin-valor";

function hashSecret(env: Env): string {
  const secret = env.IP_HASH_SECRET;

  if (secret && secret.length >= 32) return secret;
  if (isProductionLike(env)) {
    throw new LimitsUnavailableError(
      "IP_HASH_SECRET no está configurada (mínimo 32 caracteres).",
    );
  }
  return DEV_HASH_SECRET;
}

/**
 * Identificador derivado (HMAC-SHA256) de un valor personal: IP o correo.
 * No es reversible sin la clave del servidor y cambia si la clave se rota.
 */
export function pseudonym(kind: "ip" | "email", value: string, env: Env = process.env): string {
  return createHmac("sha256", hashSecret(env))
    .update(`${kind}:${value.trim().toLowerCase()}`)
    .digest("hex");
}

/**
 * Identificador del cliente a partir de la IP que aporta la plataforma
 * (nunca de una cabecera que el cliente pueda escribir: ver lib/clientIp.ts).
 */
export function clientKey(headers: HeaderReader, env: Env = process.env): string {
  return pseudonym("ip", getClientIdentity(headers, env).key, env);
}

/* ---------- backend en memoria ---------- */

type Window = { count: number; resetAt: number };
const memoryWindows = new Map<string, Window>();
const memoryLocks = new Map<string, number>();
const MAX_KEYS = 20_000;

function memoryLimit(key: string, max: number, windowSeconds: number, now: number): LimitResult {
  let window = memoryWindows.get(key);

  if (!window || window.resetAt <= now) {
    if (memoryWindows.size >= MAX_KEYS) {
      for (const [name, entry] of memoryWindows) {
        if (entry.resetAt <= now) memoryWindows.delete(name);
      }
      // Sin sitio aunque se limpie: se rechaza antes que dejar de contar.
      if (memoryWindows.size >= MAX_KEYS) {
        return { allowed: false, remaining: 0, retryAfterSeconds: windowSeconds };
      }
    }
    window = { count: 0, resetAt: now + windowSeconds * 1000 };
    memoryWindows.set(key, window);
  }

  window.count += 1;

  return {
    allowed: window.count <= max,
    remaining: Math.max(0, max - window.count),
    retryAfterSeconds: Math.max(1, Math.ceil((window.resetAt - now) / 1000)),
  };
}

/* ---------- backend Upstash ---------- */

let redis: Redis | null = null;
const limiters = new Map<string, Ratelimit>();
let lastWarning = 0;

function getRedis(env: Env): Redis {
  const credentials = upstashCredentials(env) as { url: string; token: string };
  redis ??= new Redis({
    url: credentials.url,
    token: credentials.token,
    // Si Redis no responde se degrada enseguida a memoria local, en lugar de
    // retener la petición varios segundos con reintentos.
    retry: { retries: 1, backoff: () => 100 },
  });
  return redis;
}

function warnDegraded(error: unknown): void {
  const now = Date.now();
  if (now - lastWarning < 60_000) return;
  lastWarning = now;
  // Nunca se registra la URL ni el token: solo el tipo de fallo.
  console.warn(
    "Límites: Upstash no responde; se limita en memoria local.",
    error instanceof Error ? error.name : "error",
  );
}

/**
 * Cuenta una petición. `name` identifica el límite y `key` a quién se aplica.
 * Si Redis falla en tiempo de ejecución se degrada a memoria local: el límite
 * sigue existiendo (por instancia), nunca se desactiva.
 */
export async function checkLimit(
  name: string,
  key: string,
  rule: { max: number; windowSeconds: number },
  env: Env = process.env,
  now: () => number = Date.now,
): Promise<LimitResult> {
  const mode = limitsMode(env);

  if (mode === "unavailable") {
    throw new LimitsUnavailableError(
      `El control de abuso no está configurado. Falta: ${missingLimitsConfig(env).join("; ")}.`,
    );
  }

  const id = `${name}:${key}`;

  if (mode === "upstash") {
    const cacheKey = `${name}:${rule.max}:${rule.windowSeconds}`;
    let limiter = limiters.get(cacheKey);

    if (!limiter) {
      limiter = new Ratelimit({
        redis: getRedis(env),
        limiter: Ratelimit.fixedWindow(rule.max, `${rule.windowSeconds} s`),
        prefix: `wts:${name}`,
        analytics: false,
      });
      limiters.set(cacheKey, limiter);
    }

    try {
      const result = await limiter.limit(key);

      return {
        allowed: result.success,
        remaining: result.remaining,
        retryAfterSeconds: Math.max(1, Math.ceil((result.reset - now()) / 1000)),
      };
    } catch (error) {
      warnDegraded(error);
    }
  }

  return memoryLimit(id, rule.max, rule.windowSeconds, now());
}

/** Como `checkLimit`, pero lanza `RateLimitedError` si se supera. */
export async function enforceLimit(
  name: string,
  key: string,
  rule: { max: number; windowSeconds: number },
  env: Env = process.env,
): Promise<LimitResult> {
  const result = await checkLimit(name, key, rule, env);

  if (!result.allowed) throw new RateLimitedError(result.retryAfterSeconds);

  return result;
}

/**
 * Reserva una plaza de concurrencia. Devuelve una función para liberarla, o
 * null si ya se alcanzó el máximo. La plaza caduca sola a los `ttlSeconds`
 * por si la función muere sin liberar.
 */
export async function acquireSlot(
  name: string,
  key: string,
  maxConcurrent: number,
  ttlSeconds: number,
  env: Env = process.env,
): Promise<(() => Promise<void>) | null> {
  const mode = limitsMode(env);

  if (mode === "unavailable") {
    throw new LimitsUnavailableError(
      `El control de abuso no está configurado. Falta: ${missingLimitsConfig(env).join("; ")}.`,
    );
  }

  if (mode === "upstash") {
    try {
      const client = getRedis(env);

      for (let slot = 0; slot < maxConcurrent; slot += 1) {
        const lock = `wts:slot:${name}:${key}:${slot}`;
        const acquired = await client.set(lock, "1", { nx: true, ex: ttlSeconds });

        if (acquired === "OK") {
          return async () => {
            await client.del(lock).catch(() => undefined);
          };
        }
      }
      return null;
    } catch (error) {
      warnDegraded(error);
    }
  }

  const now = Date.now();

  for (let slot = 0; slot < maxConcurrent; slot += 1) {
    const lock = `${name}:${key}:${slot}`;
    const expires = memoryLocks.get(lock);

    if (!expires || expires <= now) {
      memoryLocks.set(lock, now + ttlSeconds * 1000);
      return async () => {
        memoryLocks.delete(lock);
      };
    }
  }

  return null;
}

/** Solo para tests. */
export function resetLimitsForTests(): void {
  memoryWindows.clear();
  memoryLocks.clear();
  limiters.clear();
  redis = null;
  lastWarning = 0;
}
