import {
  createMemoryStore,
  createRateLimiter,
  createUpstashStore,
  upstashConfigFromEnv,
  type CounterStore,
  type RateLimitResult,
} from "./rateLimit";

const WINDOW_MS = 60_000;
const DEFAULT_PER_CLIENT = 10;
const DEFAULT_GLOBAL = 120;

type Env = Record<string, string | undefined>;

function positiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export type AnalyzeRateLimit = {
  /** Comprueba el límite por cliente y, si pasa, el límite global. */
  check(
    clientKey: string,
  ): Promise<RateLimitResult & { scope: "client" | "global" }>;
  shared: boolean;
};

/**
 * Límites de /api/analyze:
 * - por cliente (10/min por defecto), para que nadie acapare el servicio;
 * - global (120/min por defecto), que acota el total de peticiones salientes
 *   aunque el atacante reparta la carga entre muchas IPs.
 *
 * Con las variables de Upstash definidas el contador es compartido entre
 * instancias; sin ellas es en memoria (por instancia).
 */
export function createAnalyzeRateLimit(
  env: Env = process.env,
  overrides: { store?: CounterStore; now?: () => number } = {},
): AnalyzeRateLimit {
  const memory = createMemoryStore({ now: overrides.now });
  const upstash = upstashConfigFromEnv(env);
  const store =
    overrides.store ?? (upstash ? createUpstashStore(upstash) : memory);
  const shared = store.name !== "memory";

  let lastWarning = 0;
  const onStoreError = (error: unknown) => {
    const current = Date.now();
    // Como mucho un aviso por minuto para no inundar los logs.
    if (current - lastWarning < 60_000) return;
    lastWarning = current;
    console.warn(
      "Rate limit: fallo del almacén compartido, se usa memoria local.",
      error instanceof Error ? error.message : error,
    );
  };

  if (!shared && env.VERCEL === "1") {
    console.warn(
      "Rate limit: no hay almacén compartido configurado (UPSTASH_REDIS_REST_URL/TOKEN). El límite es por instancia.",
    );
  }

  const common = {
    windowMs: WINDOW_MS,
    store,
    fallback: shared ? memory : undefined,
    now: overrides.now,
    onStoreError,
  };

  const perClient = createRateLimiter({
    ...common,
    prefix: "client",
    limit: positiveInt(env.RATE_LIMIT_PER_MINUTE, DEFAULT_PER_CLIENT),
  });
  const global = createRateLimiter({
    ...common,
    prefix: "global",
    limit: positiveInt(env.RATE_LIMIT_GLOBAL_PER_MINUTE, DEFAULT_GLOBAL),
  });

  return {
    shared,
    async check(clientKey) {
      const client = await perClient(clientKey);
      if (!client.allowed) return { ...client, scope: "client" };

      return { ...(await global("all")), scope: "global" };
    },
  };
}
