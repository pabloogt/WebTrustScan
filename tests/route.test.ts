import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type Post = (request: NextRequest) => Promise<Response>;

/**
 * En un entorno tipo Vercel, sin Upstash el analizador ya no funciona con
 * límites en memoria: responde 503 (ver «control de abuso no disponible»).
 * Estas pruebas históricas verifican la identificación de la IP y los
 * límites por minuto, así que declaran de forma explícita la excepción.
 */
const VERCEL = {
  VERCEL: "1",
  RATE_LIMIT_ALLOW_MEMORY: "true",
  IP_HASH_SECRET: "clave-de-pruebas-de-al-menos-32-caracteres",
};

/** Carga el handler con un entorno concreto (el limitador se crea al importar). */
async function loadRoute(env: Record<string, string>): Promise<Post> {
  vi.resetModules();
  for (const [name, value] of Object.entries(env)) vi.stubEnv(name, value);

  return (await import("@/app/api/analyze/route")).POST;
}

function request(body: string, headers: Record<string, string> = {}) {
  return new NextRequest("http://localhost/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

async function statuses(
  post: Post,
  count: number,
  headersFor: (i: number) => Record<string, string>,
) {
  const result: number[] = [];

  for (let i = 0; i < count; i += 1) {
    result.push((await post(request("{}", headersFor(i)))).status);
  }

  return result;
}

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("POST /api/analyze · validación", () => {
  it.each([
    ["JSON inválido", "esto no es json"],
    ["sin url", "{}"],
    ["url no string", '{"url": 123}'],
    ["url vacía", '{"url": "   "}'],
    ["cuerpo no objeto", "null"],
    ["cuerpo enorme", JSON.stringify({ url: "a".repeat(10_000) })],
  ])("responde 400 con %s", async (_name, body) => {
    const post = await loadRoute({});
    const response = await post(request(body));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "La URL es obligatoria." });
  });

  it.each([
    "http://127.0.0.1:9999",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
  ])("responde 400 y no analiza %s", async (url) => {
    const post = await loadRoute({});
    const response = await post(request(JSON.stringify({ url })));
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBeTypeOf("string");
    expect(data.checks).toBeUndefined();
  });
});

describe("POST /api/analyze · límite de peticiones", () => {
  it("sin proxy de confianza, falsear X-Forwarded-For no da cupo extra", async () => {
    const post = await loadRoute({});

    // Antes de esta revisión: 40 peticiones con 40 IPs falsas pasaban todas.
    const result = await statuses(post, 40, (i) => ({
      "x-forwarded-for": `198.51.100.${i}`,
      "x-real-ip": `198.51.100.${i}`,
    }));

    expect(result.slice(0, 10)).toEqual(Array(10).fill(400));
    expect(result.slice(10)).toEqual(Array(30).fill(429));
  });

  it("en Vercel limita por la IP de la plataforma e ignora la falseada", async () => {
    const post = await loadRoute(VERCEL);

    const attacker = await statuses(post, 12, (i) => ({
      "x-forwarded-for": `198.51.100.${i}`,
      "x-vercel-forwarded-for": "203.0.113.50",
    }));
    const other = await statuses(post, 1, () => ({
      "x-vercel-forwarded-for": "203.0.113.51",
    }));

    expect(attacker.slice(0, 10)).toEqual(Array(10).fill(400));
    expect(attacker.slice(10)).toEqual([429, 429]);
    expect(other).toEqual([400]); // otro cliente no se ve afectado
  });

  it("con proxy de confianza, anteponer IPs falsas no cambia la clave", async () => {
    const post = await loadRoute({ TRUSTED_PROXY_HOPS: "1" });

    const result = await statuses(post, 12, (i) => ({
      "x-forwarded-for": `198.51.100.${i}, 203.0.113.60`,
    }));

    expect(result.slice(10)).toEqual([429, 429]);
  });

  it("devuelve Retry-After y un mensaje distinto para el límite global", async () => {
    const post = await loadRoute({
      ...VERCEL,
      RATE_LIMIT_GLOBAL_PER_MINUTE: "3",
    });

    const result: Response[] = [];
    for (let i = 0; i < 4; i += 1) {
      result.push(
        await post(
          request("{}", { "x-vercel-forwarded-for": `203.0.113.${i}` }),
        ),
      );
    }

    expect(result.map((response) => response.status)).toEqual([
      400, 400, 400, 429,
    ]);
    expect(Number(result[3].headers.get("retry-after"))).toBeGreaterThan(0);
    expect((await result[3].json()).error).toMatch(/servicio/);
  });

  it("avisa en Vercel si no hay almacén compartido configurado", async () => {
    await loadRoute({ VERCEL: "1" });

    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining("no hay almacén compartido"),
    );
  });
});
