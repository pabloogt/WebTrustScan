import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST as deleteRoute } from "@/app/api/account/delete/route";
import { POST as emailRoute } from "@/app/api/account/email/route";
import { GET as exportRoute } from "@/app/api/account/export/route";
import { POST as passwordRoute } from "@/app/api/account/password/route";
import { GET as accountRoute, PATCH as profileRoute } from "@/app/api/account/route";
import { GET as auditRoute, DELETE as deleteAuditRoute } from "@/app/api/audits/[id]/route";
import { GET as auditsRoute } from "@/app/api/audits/route";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { POST as recover } from "@/app/api/auth/recover/route";
import { POST as register } from "@/app/api/auth/register/route";
import { GET as confirm } from "@/app/auth/confirm/route";
import { accountsEnabled, appBaseUrl, supabaseConfig } from "@/lib/accounts/config";
import { setAccountDepsForTests } from "@/lib/accounts/http";
import {
  LimitsUnavailableError,
  RateLimitedError,
  acquireSlot,
  checkLimit,
  clientKey,
  enforceLimit,
  limitsMode,
  pseudonym,
  resetLimitsForTests,
} from "@/lib/limits";
import {
  ANONYMOUS,
  PLANS,
  RATE_LIMITS,
  auditLimitsByPlan,
  entitlementsFor,
} from "@/lib/plans";
import { call } from "./fakes";

const SECRET = "clave-de-pruebas-de-al-menos-32-caracteres";
const PROD = { NODE_ENV: "production", IP_HASH_SECRET: SECRET };
const UPSTASH = {
  UPSTASH_REDIS_REST_URL: "https://ejemplo.upstash.test",
  UPSTASH_REDIS_REST_TOKEN: "token-de-prueba",
};
const headers = (values: Record<string, string>) => new Headers(values);

beforeEach(() => {
  resetLimitsForTests();
  vi.spyOn(console, "warn").mockImplementation(() => {});
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("planes · configuración única", () => {
  it("valores provisionales de Free y Pro", () => {
    expect(PLANS.free).toMatchObject({ monthlyAudits: 5, historySize: 10 });
    expect(PLANS.pro).toMatchObject({ monthlyAudits: 100, historySize: 100 });
    expect(ANONYMOUS.auditsPerDay).toBe(2);
    expect(auditLimitsByPlan()).toEqual({ free: 5, pro: 100 });
  });

  it("cualquier plan desconocido o manipulado se trata como Free", () => {
    for (const value of [undefined, null, "", "PRO", "enterprise", "pro ", "admin"]) {
      expect(entitlementsFor(value as string).plan).toBe("free");
    }
    expect(entitlementsFor("pro").plan).toBe("pro");
  });
});

describe("modo de los límites", () => {
  it.each([
    [{ NODE_ENV: "test" }, "memory"],
    [{ NODE_ENV: "development" }, "memory"],
    [{ NODE_ENV: "production" }, "unavailable"],
    [{ VERCEL: "1" }, "unavailable"],
    [{ NODE_ENV: "production", UPSTASH_REDIS_REST_URL: "https://x" }, "unavailable"], // falta el token
    [{ NODE_ENV: "production", ...UPSTASH }, "upstash"],
    [{ NODE_ENV: "production", RATE_LIMIT_ALLOW_MEMORY: "true" }, "memory"],
    [{ NODE_ENV: "production", RATE_LIMIT_ALLOW_MEMORY: "1" }, "unavailable"],
  ])("%j → %s", (env, expected) => {
    expect(limitsMode(env)).toBe(expected);
  });

  it("en producción sin Upstash no se limita en memoria: se rechaza", async () => {
    await expect(checkLimit("x", "k", { max: 5, windowSeconds: 60 }, PROD)).rejects.toBeInstanceOf(LimitsUnavailableError);
    await expect(acquireSlot("x", "k", 1, 30, PROD)).rejects.toBeInstanceOf(LimitsUnavailableError);
  });
});

describe("límite en memoria (desarrollo y tests)", () => {
  it("permite `max` peticiones por ventana y luego rechaza con el tiempo de espera", async () => {
    const rule = { max: 3, windowSeconds: 60 };
    let now = 1_000_000;
    const results = [];
    for (let i = 0; i < 5; i += 1) results.push(await checkLimit("t", "a", rule, {}, () => now));

    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false, false]);
    expect(results.map((r) => r.remaining)).toEqual([2, 1, 0, 0, 0]);
    expect(results[3].retryAfterSeconds).toBe(60);

    // Otra clave y otro límite llevan su propia cuenta.
    expect((await checkLimit("t", "b", rule, {}, () => now)).allowed).toBe(true);
    expect((await checkLimit("otro", "a", rule, {}, () => now)).allowed).toBe(true);

    now += 61_000;
    expect((await checkLimit("t", "a", rule, {}, () => now)).allowed).toBe(true);
  });

  it("enforceLimit lanza un error con Retry-After", async () => {
    await enforceLimit("e", "k", { max: 1, windowSeconds: 30 });
    await expect(enforceLimit("e", "k", { max: 1, windowSeconds: 30 })).rejects.toBeInstanceOf(RateLimitedError);
  });

  it("las plazas de concurrencia se ocupan, se liberan y caducan", async () => {
    const first = await acquireSlot("s", "k", 2, 30);
    const second = await acquireSlot("s", "k", 2, 30);

    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(await acquireSlot("s", "k", 2, 30)).toBeNull();
    expect(await acquireSlot("s", "otro", 2, 30)).not.toBeNull();

    await first?.();
    expect(await acquireSlot("s", "k", 2, 30)).not.toBeNull();

    // Una plaza con caducidad 0 no bloquea para siempre si nunca se libera.
    await acquireSlot("ttl", "k", 1, 0);
    expect(await acquireSlot("ttl", "k", 1, 30)).not.toBeNull();
  });
});

describe("identificación del cliente", () => {
  it("las claves son un HMAC: no contienen la IP ni el correo", () => {
    const ip = pseudonym("ip", "203.0.113.7", { IP_HASH_SECRET: SECRET });
    const email = pseudonym("email", "Persona@Ejemplo.test ", { IP_HASH_SECRET: SECRET });

    expect(ip).toMatch(/^[0-9a-f]{64}$/);
    expect(ip).not.toContain("203");
    expect(email).not.toContain("persona");
    // Determinista, insensible a mayúsculas y espacios.
    expect(email).toBe(pseudonym("email", "persona@ejemplo.test", { IP_HASH_SECRET: SECRET }));
    // Depende de la clave del servidor y del tipo de dato.
    expect(ip).not.toBe(pseudonym("ip", "203.0.113.7", { IP_HASH_SECRET: `${SECRET}-otra` }));
    expect(pseudonym("ip", "x", { IP_HASH_SECRET: SECRET })).not.toBe(pseudonym("email", "x", { IP_HASH_SECRET: SECRET }));
  });

  it("en producción exige una clave propia de al menos 32 caracteres", () => {
    expect(() => pseudonym("ip", "1.2.3.4", { NODE_ENV: "production" })).toThrow(LimitsUnavailableError);
    expect(() => pseudonym("ip", "1.2.3.4", { NODE_ENV: "production", IP_HASH_SECRET: "corta" })).toThrow(LimitsUnavailableError);
    expect(() => pseudonym("ip", "1.2.3.4", { VERCEL: "1" })).toThrow(LimitsUnavailableError);
    // En desarrollo hay una clave fija sin valor.
    expect(pseudonym("ip", "1.2.3.4", { NODE_ENV: "development" })).toMatch(/^[0-9a-f]{64}$/);
  });

  it("en Vercel usa la IP de la plataforma e ignora la que escribe el cliente", () => {
    const env = { VERCEL: "1", IP_HASH_SECRET: SECRET };
    const real = clientKey(headers({ "x-vercel-forwarded-for": "203.0.113.50" }), env);

    expect(clientKey(headers({ "x-vercel-forwarded-for": "203.0.113.50", "x-forwarded-for": "198.51.100.1" }), env)).toBe(real);
    expect(clientKey(headers({ "x-vercel-forwarded-for": "203.0.113.51" }), env)).not.toBe(real);
  });

  it("sin proxy de confianza, falsear X-Forwarded-For no da una identidad nueva", () => {
    const env = { IP_HASH_SECRET: SECRET };

    expect(clientKey(headers({ "x-forwarded-for": "198.51.100.1" }), env)).toBe(
      clientKey(headers({ "x-forwarded-for": "198.51.100.2", "x-real-ip": "198.51.100.3" }), env),
    );
  });
});

describe("Upstash", () => {
  const env = { ...PROD, ...UPSTASH };

  it("usa Redis con la clave derivada, nunca con la IP", async () => {
    const bodies: string[] = [];
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      bodies.push(String(init.body));
      // Respuesta de un EVAL de ventana fija: [peticiones usadas, ...]
      return new Response(JSON.stringify([{ result: [1, 1] }, { result: 1 }]), { status: 200 });
    });

    await checkLimit("anon-day", clientKey(headers({}), env), { max: 2, windowSeconds: 86_400 }, env).catch(() => undefined);

    expect(bodies.length).toBeGreaterThan(0);
    expect(bodies.join(" ")).toContain("wts:anon-day");
    expect(bodies.join(" ")).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
    expect(bodies.join(" ")).not.toContain(UPSTASH.UPSTASH_REDIS_REST_TOKEN);
  });

  it("si Redis falla se degrada a memoria local: el límite no desaparece", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED redis no responde");
    });
    const rule = { max: 2, windowSeconds: 60 };
    const results = [];
    for (let i = 0; i < 4; i += 1) results.push((await checkLimit("caido", "k", rule, env)).allowed);

    expect(results).toEqual([true, true, false, false]);
    expect(console.warn).toHaveBeenCalledTimes(1); // un aviso, no uno por petición

    const warning = vi.mocked(console.warn).mock.calls[0].join(" ");
    expect(warning).not.toContain(UPSTASH.UPSTASH_REDIS_REST_TOKEN);
    expect(warning).not.toContain("upstash.test");
  }, 20_000);

  it("la concurrencia también se degrada a memoria si Redis falla", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("timeout");
    });

    expect(await acquireSlot("slot", "k", 1, 30, env)).not.toBeNull();
    expect(await acquireSlot("slot", "k", 1, 30, env)).toBeNull();
  }, 20_000);
});

describe("configuración", () => {
  it("las cuentas solo se activan con ACCOUNTS_ENABLED exactamente «true»", () => {
    for (const value of [undefined, "", "false", "0", "1", "TRUE", "True", "yes", " true"]) {
      expect(accountsEnabled({ ACCOUNTS_ENABLED: value }), String(value)).toBe(false);
    }
    expect(accountsEnabled({ ACCOUNTS_ENABLED: "true" })).toBe(true);
    expect(accountsEnabled({ NEXT_PUBLIC_ACCOUNTS_ENABLED: "true" })).toBe(false);
  });

  it("Supabase necesita URL y clave pública; la secreta es opcional y solo de servidor", () => {
    expect(supabaseConfig({})).toBeNull();
    expect(supabaseConfig({ NEXT_PUBLIC_SUPABASE_URL: "https://x.supabase.co" })).toBeNull();
    expect(
      supabaseConfig({
        NEXT_PUBLIC_SUPABASE_URL: "https://x.supabase.co",
        NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: "sb_publishable_x",
        SUPABASE_SECRET_KEY: "sb_secret_x",
        // Una clave secreta con prefijo público NO se usa nunca.
        NEXT_PUBLIC_SUPABASE_SECRET_KEY: "no-debe-leerse",
      }),
    ).toEqual({ url: "https://x.supabase.co", publishableKey: "sb_publishable_x", secretKey: "sb_secret_x" });
  });

  it("los enlaces de los correos usan APP_BASE_URL, no la cabecera Host", () => {
    expect(appBaseUrl({ APP_BASE_URL: "https://webtrustscan.example/" })).toBe("https://webtrustscan.example");
    expect(appBaseUrl({ NODE_ENV: "development" })).toBe("http://localhost:3000");
    expect(() => appBaseUrl({ NODE_ENV: "production" })).toThrow();
    expect(() => appBaseUrl({ NODE_ENV: "production", APP_BASE_URL: "javascript:alert(1)" })).toThrow();
  });

  it("los límites contra el abuso están definidos en un solo sitio", () => {
    expect(RATE_LIMITS.register).toEqual({ max: 5, windowSeconds: 3_600 });
    expect(RATE_LIMITS.loginByIp).toEqual({ max: 10, windowSeconds: 60 });
    expect(RATE_LIMITS.recoveryByEmail.max).toBeLessThan(RATE_LIMITS.recoveryByIp.max);
  });
});

describe("cuentas desactivadas (valor por defecto)", () => {
  const ID = "00000000-0000-4000-8000-000000000000";
  const ROUTES: [string, Parameters<typeof call>[0], Parameters<typeof call>[1]][] = [
    ["POST /api/auth/register", register, { method: "POST", body: { email: "x@y.test", password: "una-frase-larga" } }],
    ["POST /api/auth/login", login, { method: "POST", body: { email: "x@y.test", password: "una-frase-larga" } }],
    ["POST /api/auth/logout", logout, { method: "POST", body: {} }],
    ["POST /api/auth/recover", recover, { method: "POST", body: { email: "x@y.test" } }],
    ["GET /auth/confirm", confirm, { path: "/auth/confirm?token_hash=abc&type=email" }],
    ["GET /api/account", accountRoute, {}],
    ["PATCH /api/account", profileRoute, { method: "PATCH", body: { displayName: "x" } }],
    ["POST /api/account/password", passwordRoute, { method: "POST", body: { password: "una-frase-larga" } }],
    ["POST /api/account/email", emailRoute, { method: "POST", body: { email: "x@y.test" } }],
    ["POST /api/account/delete", deleteRoute, { method: "POST", body: {} }],
    ["GET /api/account/export", exportRoute, {}],
    ["GET /api/audits", auditsRoute, {}],
    ["GET /api/audits/[id]", auditRoute, { params: { id: ID } }],
    ["DELETE /api/audits/[id]", deleteAuditRoute, { method: "DELETE", params: { id: ID } }],
  ];

  describe.each([
    ["sin definir", undefined],
    ["con un valor que no es exactamente «true»", "1"],
  ])("ACCOUNTS_ENABLED %s", (_name, value) => {
    it.each(ROUTES)("%s responde 404", async (_route, handler, options) => {
      vi.stubEnv("ACCOUNTS_ENABLED", value as string);
      const result = await call(handler, { ...options, cookie: "sb-proyecto-auth-token=robado" });

      expect(result.status).toBe(404);
      expect(result.data).toEqual({ error: "No encontrado." });
      expect(result.response.headers.get("set-cookie")).toBeNull();
    });

    it("ninguna ruta llega a crear un cliente de Supabase ni a tocar la base de datos", async () => {
      vi.stubEnv("ACCOUNTS_ENABLED", value as string);
      const factory = vi.fn(async () => {
        throw new Error("no debería llamarse");
      });
      setAccountDepsForTests(factory);

      for (const [, handler, options] of ROUTES) await call(handler, options);

      expect(factory).not.toHaveBeenCalled();
      setAccountDepsForTests(null);
    });
  });

  it("activadas pero sin configurar Supabase: 503 controlado, sin detalles", async () => {
    vi.stubEnv("ACCOUNTS_ENABLED", "true");
    setAccountDepsForTests(null);
    const result = await call(accountRoute);

    expect(result.status).toBe(503);
    expect(result.data.error).toMatch(/no están configuradas/);
  });

  it("el analizador público sigue respondiendo con las cuentas desactivadas", async () => {
    vi.stubEnv("ACCOUNTS_ENABLED", "");
    const { POST } = await import("@/app/api/analyze/route");
    const response = await POST(
      new NextRequest("http://localhost/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: "http://127.0.0.1" }),
      }),
    );

    expect(response.status).toBe(400);
    expect((await response.json()).error).toMatch(/no se puede analizar/);
  });
});
