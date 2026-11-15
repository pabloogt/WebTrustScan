import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createAnalyzeRateLimit } from "@/lib/analyzeRateLimit";
import {
  createMemoryStore,
  createRateLimiter,
  createUpstashStore,
  upstashConfigFromEnv,
  type CounterStore,
} from "@/lib/rateLimit";
import { startServer, type TestServer } from "./helpers";

const servers: TestServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** Reloj manual para controlar las ventanas. */
function clock(start = 1_000_000) {
  let current = start;
  return { now: () => current, advance: (ms: number) => (current += ms) };
}

type FakeUpstash = TestServer & {
  url: string;
  requests: Array<{ auth: string | undefined; commands: unknown[][] }>;
  keys: () => string[];
  setMode: (mode: "ok" | "error" | "hang") => void;
};

/** Imita el endpoint /pipeline de la API REST de Upstash (INCR y PEXPIRE). */
async function fakeUpstash(token: string): Promise<FakeUpstash> {
  const counters = new Map<string, number>();
  const state = {
    requests: [] as FakeUpstash["requests"],
    mode: "ok" as "ok" | "error" | "hang",
  };

  const handler: http.RequestListener = (req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      if (state.mode === "hang") return;

      if (state.mode === "error") {
        res.writeHead(500).end("{}");
        return;
      }

      if (req.url !== "/pipeline" || req.method !== "POST") {
        res.writeHead(404).end("{}");
        return;
      }

      if (req.headers.authorization !== `Bearer ${token}`) {
        res.writeHead(401).end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }

      const commands = JSON.parse(body) as unknown[][];
      state.requests.push({ auth: req.headers.authorization, commands });

      const results = commands.map(([name, key]) => {
        if (name === "INCR") {
          const next = (counters.get(String(key)) ?? 0) + 1;
          counters.set(String(key), next);
          return { result: next };
        }
        return { result: 1 };
      });

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(results));
    });
  };

  const server = await startServer(handler);
  servers.push(server);

  return {
    ...server,
    url: server.origin,
    keys: () => [...counters.keys()],
    requests: state.requests,
    setMode: (mode) => {
      state.mode = mode;
    },
  };
}

describe("createRateLimiter (memoria)", () => {
  it("permite hasta el límite y luego bloquea con Retry-After", async () => {
    const time = clock(120_000);
    const check = createRateLimiter({
      limit: 3,
      windowMs: 60_000,
      prefix: "t",
      store: createMemoryStore({ now: time.now }),
      now: time.now,
    });

    expect((await check("ip")).allowed).toBe(true);
    expect((await check("ip")).allowed).toBe(true);
    expect((await check("ip")).allowed).toBe(true);

    time.advance(30_000);
    const blocked = await check("ip");
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBe(30);
  });

  it("reinicia el contador en la siguiente ventana", async () => {
    const time = clock(120_000);
    const check = createRateLimiter({
      limit: 1,
      windowMs: 1000,
      prefix: "t",
      store: createMemoryStore({ now: time.now }),
      now: time.now,
    });

    expect((await check("ip")).allowed).toBe(true);
    time.advance(999);
    expect((await check("ip")).allowed).toBe(false);
    time.advance(1);
    expect((await check("ip")).allowed).toBe(true);
  });

  it("cuenta cada clave por separado", async () => {
    const check = createRateLimiter({
      limit: 1,
      windowMs: 60_000,
      prefix: "t",
      store: createMemoryStore(),
    });

    expect((await check("a")).allowed).toBe(true);
    expect((await check("b")).allowed).toBe(true);
    expect((await check("a")).allowed).toBe(false);
  });

  it("el almacén en memoria no crece sin límite", async () => {
    const store = createMemoryStore({ maxKeys: 5 });

    for (let i = 0; i < 50; i += 1) {
      expect(await store.increment(`k-${i}`, 60_000)).toBe(1);
    }

    // k-0 se descartó al llenarse: vuelve a empezar en 1.
    expect(await store.increment("k-0", 60_000)).toBe(1);
  });

  it("un cliente ya bloqueado no genera más consultas al almacén", async () => {
    let calls = 0;
    const memory = createMemoryStore();
    const counting: CounterStore = {
      name: "upstash",
      increment: (key, ttl) => {
        calls += 1;
        return memory.increment(key, ttl);
      },
    };
    const check = createRateLimiter({
      limit: 2,
      windowMs: 60_000,
      prefix: "t",
      store: counting,
    });

    for (let i = 0; i < 100; i += 1) await check("atacante");

    // 2 permitidas + 1 que detecta el bloqueo; las otras 97 no cuestan nada.
    expect(calls).toBe(3);
  });
});

describe("almacén compartido (API REST de Upstash simulada)", () => {
  it("envía INCR + PEXPIRE autenticado y no guarda la IP en claro", async () => {
    const upstash = await fakeUpstash("token-secreto");
    const check = createRateLimiter({
      limit: 5,
      windowMs: 60_000,
      prefix: "client",
      store: createUpstashStore({ url: upstash.url, token: "token-secreto" }),
    });

    const result = await check("203.0.113.9");

    expect(result).toMatchObject({ allowed: true, store: "upstash" });
    expect(upstash.requests).toHaveLength(1);

    const [incr, expire] = upstash.requests[0].commands;
    expect(incr[0]).toBe("INCR");
    expect(expire).toEqual(["PEXPIRE", incr[1], 60_000]);
    expect(String(incr[1])).toMatch(/^rl:client:[0-9a-f]{32}:\d+$/);
    expect(String(incr[1])).not.toContain("203.0.113.9");
  });

  it("dos instancias serverless comparten el mismo contador", async () => {
    const upstash = await fakeUpstash("t");
    const instance = () =>
      createRateLimiter({
        limit: 10,
        windowMs: 60_000,
        prefix: "client",
        store: createUpstashStore({ url: upstash.url, token: "t" }),
      });
    const a = instance();
    const b = instance();

    const results: boolean[] = [];
    for (let i = 0; i < 16; i += 1) {
      results.push((await (i % 2 === 0 ? a : b)("203.0.113.9")).allowed);
    }

    // Con memoria por instancia pasarían las 16 (8 + 8).
    expect(results.filter(Boolean)).toHaveLength(10);
    expect(results.slice(10)).toEqual(Array(6).fill(false));
  });

  it("comparación: en memoria, cada instancia tiene su propio cupo", async () => {
    const instance = () =>
      createRateLimiter({
        limit: 10,
        windowMs: 60_000,
        prefix: "client",
        store: createMemoryStore(),
      });
    const a = instance();
    const b = instance();

    let allowed = 0;
    for (let i = 0; i < 16; i += 1) {
      if ((await (i % 2 === 0 ? a : b)("203.0.113.9")).allowed) allowed += 1;
    }

    expect(allowed).toBe(16);
  });

  it.each(["error", "hang"] as const)(
    "si Upstash falla (%s) sigue limitando en memoria, no abre la puerta",
    async (mode) => {
      const upstash = await fakeUpstash("t");
      upstash.setMode(mode);
      const errors: unknown[] = [];
      const check = createRateLimiter({
        limit: 2,
        windowMs: 60_000,
        prefix: "client",
        store: createUpstashStore({
          url: upstash.url,
          token: "t",
          timeoutMs: 200,
        }),
        fallback: createMemoryStore(),
        onStoreError: (error) => errors.push(error),
      });

      const first = await check("ip");
      const second = await check("ip");
      const third = await check("ip");

      expect(first).toMatchObject({ allowed: true, store: "memory" });
      expect(second.allowed).toBe(true);
      expect(third.allowed).toBe(false);
      expect(errors.length).toBeGreaterThanOrEqual(3);
    },
  );

  it("un token incorrecto se trata como fallo del almacén", async () => {
    const upstash = await fakeUpstash("bueno");
    const check = createRateLimiter({
      limit: 1,
      windowMs: 60_000,
      prefix: "client",
      store: createUpstashStore({ url: upstash.url, token: "malo" }),
      fallback: createMemoryStore(),
    });

    expect(await check("ip")).toMatchObject({ allowed: true, store: "memory" });
    expect((await check("ip")).allowed).toBe(false);
  });

  it("sin almacén de reserva, el fallo se propaga", async () => {
    const upstash = await fakeUpstash("t");
    upstash.setMode("error");
    const check = createRateLimiter({
      limit: 1,
      windowMs: 60_000,
      prefix: "client",
      store: createUpstashStore({ url: upstash.url, token: "t" }),
    });

    await expect(check("ip")).rejects.toThrow(/Upstash/);
  });
});

describe("upstashConfigFromEnv", () => {
  it("acepta los dos pares de nombres de variables", () => {
    expect(
      upstashConfigFromEnv({
        UPSTASH_REDIS_REST_URL: "https://x.upstash.io",
        UPSTASH_REDIS_REST_TOKEN: "a",
      }),
    ).toEqual({ url: "https://x.upstash.io", token: "a" });
    expect(
      upstashConfigFromEnv({
        KV_REST_API_URL: "https://y.upstash.io",
        KV_REST_API_TOKEN: "b",
      }),
    ).toEqual({ url: "https://y.upstash.io", token: "b" });
  });

  it("no envía el token a una URL sin HTTPS ni con configuración a medias", () => {
    expect(
      upstashConfigFromEnv({
        UPSTASH_REDIS_REST_URL: "http://x.upstash.io",
        UPSTASH_REDIS_REST_TOKEN: "a",
      }),
    ).toBeNull();
    expect(
      upstashConfigFromEnv({ UPSTASH_REDIS_REST_URL: "https://x.upstash.io" }),
    ).toBeNull();
    expect(upstashConfigFromEnv({})).toBeNull();
  });
});

describe("createAnalyzeRateLimit", () => {
  it("aplica el límite por cliente y después el global", async () => {
    const limit = createAnalyzeRateLimit({
      RATE_LIMIT_PER_MINUTE: "2",
      RATE_LIMIT_GLOBAL_PER_MINUTE: "5",
    });

    expect(limit.shared).toBe(false);
    expect((await limit.check("a")).allowed).toBe(true);
    expect((await limit.check("a")).allowed).toBe(true);
    expect(await limit.check("a")).toMatchObject({
      allowed: false,
      scope: "client",
    });

    // Muchas IPs distintas: cada una cabe en su cupo, pero el global corta.
    expect((await limit.check("b")).allowed).toBe(true);
    expect((await limit.check("c")).allowed).toBe(true);
    expect((await limit.check("d")).allowed).toBe(true);
    expect(await limit.check("e")).toMatchObject({
      allowed: false,
      scope: "global",
    });
  });

  it("ignora valores de configuración no válidos", async () => {
    const limit = createAnalyzeRateLimit({
      RATE_LIMIT_PER_MINUTE: "0",
      RATE_LIMIT_GLOBAL_PER_MINUTE: "abc",
    });

    for (let i = 0; i < 10; i += 1) {
      expect((await limit.check("a")).allowed).toBe(true);
    }
    expect((await limit.check("a")).allowed).toBe(false);
  });
});
