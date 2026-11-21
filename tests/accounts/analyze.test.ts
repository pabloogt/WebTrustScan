import { NextRequest } from "next/server";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditError as AuditErrorType } from "@/lib/audit/errors";
import { ORIGIN, createEnv, requestId, sampleReport, type Env } from "./fakes";

/**
 * Consumo del analizador por la ruta real `/api/analyze`: límite diario de
 * visitantes, cuota por plan, idempotencia y manipulación de peticiones.
 * El motor se sustituye por un doble para no salir a la red; la cuota usa
 * las funciones SQL reales.
 */

const runAudit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/engine/run", () => ({ runAudit }));

type Post = (request: NextRequest) => Promise<Response>;

let env: Env;
let post: Post;
let counter = 0;
// La ruta se recarga en cada prueba (su limitador por minuto vive en el
// módulo), así que la clase de error debe ser la de esa misma carga.
let AuditError: typeof AuditErrorType;

beforeAll(async () => {
  vi.stubEnv("ACCOUNTS_ENABLED", "true");
  env = await createEnv();
});
afterAll(async () => {
  vi.unstubAllEnvs();
  await env.close();
});
beforeEach(async () => {
  vi.resetModules();
  const http = await import("@/lib/accounts/http");
  http.setAccountDepsForTests(async () => env.deps);
  AuditError = (await import("@/lib/audit/errors")).AuditError;
  post = (await import("@/app/api/analyze/route")).POST;

  env.session.userId = null;
  runAudit.mockReset();
  runAudit.mockImplementation(async (url: string) => sampleReport(new URL(url).hostname));
  vi.spyOn(console, "error").mockImplementation(() => {});
});

async function analyze(
  body: Record<string, unknown>,
  options: { origin?: string | null; headers?: Record<string, string> } = {},
) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    host: "localhost",
    ...options.headers,
  };
  if (options.origin !== null) headers.origin = options.origin ?? ORIGIN;

  const response = await post(
    new NextRequest(`${ORIGIN}/api/analyze`, { method: "POST", headers, body: JSON.stringify(body) }),
  );

  return { status: response.status, data: (await response.json()) as Record<string, unknown>, response };
}

/** Recarga solo la ruta: reinicia su limitador por minuto. */
async function reloadRoute(): Promise<Post> {
  vi.resetModules();
  const http = await import("@/lib/accounts/http");
  http.setAccountDepsForTests(async () => env.deps);
  AuditError = (await import("@/lib/audit/errors")).AuditError;
  return (await import("@/app/api/analyze/route")).POST;
}

async function newUser(plan?: "pro"): Promise<string> {
  const id = await env.db.createUser(`u${(counter += 1)}@cuota.test`);
  env.users.set(id, { id, email: `u${counter}@cuota.test`, password: "x", confirmed: true, pendingEmail: null });
  if (plan) {
    await env.db.sql(
      "update public.subscriptions set plan = 'pro', provider = 'manual' where workspace_id = (select id from public.workspaces where owner_id = $1)",
      [id],
    );
  }
  return id;
}

const used = async (userId: string) =>
  (await env.db.sql<{ u: { used: number } }>("select public.workspace_usage($1) as u", [userId]))[0].u.used;

describe("visitantes sin cuenta", () => {
  it("2 análisis al día por IP y después 429 con un mensaje claro", async () => {
    const results = [];
    for (let i = 0; i < 4; i += 1) results.push(await analyze({ url: `sitio${i}.example` }));

    expect(results.map((r) => r.status)).toEqual([200, 200, 429, 429]);
    expect(results[2].data).toMatchObject({ code: "anonymous_limit" });
    expect(results[2].data.error).toMatch(/2 análisis diarios sin cuenta/);
    expect(runAudit).toHaveBeenCalledTimes(2);
  });

  it("una URL inválida o un destino no permitido no gasta el límite", async () => {
    for (const url of ["", "http://127.0.0.1", "http://ejemplo.com:8080", "ftp://ejemplo.com", "http://169.254.169.254/latest/"]) {
      const result = await analyze({ url });
      expect(result.status, url).toBe(400);
    }
    expect(runAudit).not.toHaveBeenCalled();

    expect((await analyze({ url: "a.example" })).status).toBe(200);
    expect((await analyze({ url: "b.example" })).status).toBe(200);
  });

  it("un análisis que falla por el destino también cuenta", async () => {
    runAudit.mockRejectedValue(new AuditError("UNREACHABLE", "No se pudo conectar con la web."));

    expect((await analyze({ url: "caido.example" })).status).toBe(502);
    expect((await analyze({ url: "caido.example" })).status).toBe(502);
    expect((await analyze({ url: "caido.example" })).status).toBe(429);
  });

  it("el límite es por IP: otro visitante tiene el suyo", async () => {
    vi.stubEnv("TRUSTED_PROXY_HOPS", "1");
    const from = (ip: string) => analyze({ url: "x.example" }, { headers: { "x-forwarded-for": ip } });

    expect([(await from("203.0.113.1")).status, (await from("203.0.113.1")).status, (await from("203.0.113.1")).status]).toEqual([200, 200, 429]);
    expect((await from("203.0.113.2")).status).toBe(200);
    // Anteponer una IP falsa no da cupo nuevo.
    expect((await analyze({ url: "x.example" }, { headers: { "x-forwarded-for": "198.51.100.9, 203.0.113.1" } })).status).toBe(429);
    vi.stubEnv("TRUSTED_PROXY_HOPS", "");
  });

  it("un solo análisis a la vez por visitante", async () => {
    let finish: (() => void) | undefined;
    runAudit.mockImplementationOnce(
      (url: string) => new Promise((resolve) => { finish = () => resolve(sampleReport(new URL(url).hostname)); }),
    );

    const first = analyze({ url: "lento.example" });
    await vi.waitFor(() => expect(runAudit).toHaveBeenCalledTimes(1));
    const second = await analyze({ url: "otro.example" });

    expect(second.status).toBe(429);
    expect(second.data).toMatchObject({ code: "concurrent" });

    finish?.();
    expect((await first).status).toBe(200);
    // La plaza se libera al terminar.
    expect((await analyze({ url: "otro.example" })).status).toBe(200);
  });
});

describe("usuarios con cuenta", () => {
  it("Free: 5 análisis guardados y el sexto se rechaza sin ejecutar", async () => {
    env.session.userId = await newUser();
    const results = [];
    for (let i = 0; i < 6; i += 1) results.push(await analyze({ url: `s${i}.example`, requestId: requestId() }));

    expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200, 200, 429]);
    expect(results[0].data.quota).toMatchObject({ plan: "free", used: 1, limit: 5, remaining: 4, windowDays: 7 });
    expect(results[4].data.quota).toMatchObject({ used: 5, remaining: 0 });
    expect(results[5].data).toMatchObject({ code: "quota_exceeded", used: 5, limit: 5, windowDays: 7 });
    expect(results[5].data.error).toMatch(/en los últimos 7 días\. Tendrás uno disponible de nuevo el .* UTC\./);

    // Se libera 7 días después del PRIMER análisis de la ventana (UTC).
    const first = await env.db.sql<{ created_at: Date }>(
      "select min(created_at) as created_at from public.usage_events where user_id = $1",
      [env.session.userId],
    );
    const expected = new Date(new Date(first[0].created_at).getTime() + 7 * 86_400_000).toISOString();
    expect(results[5].data.availableAt).toBe(expected);
    expect(new Date((results[0].data.quota as { nextReleaseAt: string }).nextReleaseAt).getTime()).toBe(new Date(expected).getTime());
    expect(runAudit).toHaveBeenCalledTimes(5);

    const history = await env.db.asUser(env.session.userId, (sql) => sql("select hostname from public.audits"));
    expect(history).toHaveLength(5);
  });

  it("no usa el límite de visitantes: una cuenta puede pasar de 2", async () => {
    env.session.userId = await newUser();

    for (let i = 0; i < 3; i += 1) {
      expect((await analyze({ url: `t${i}.example`, requestId: requestId() })).status).toBe(200);
    }
  });

  it("Pro tiene el límite superior", async () => {
    env.session.userId = await newUser("pro");
    // Hay un tope de 6 por minuto contra automatización: se reinicia entre tandas.
    for (let i = 0; i < 12; i += 1) {
      if (i % 5 === 0) (await import("@/lib/limits")).resetLimitsForTests();
      if (i % 5 === 0) post = await reloadRoute();
      const result = await analyze({ url: `p${i}.example`, requestId: requestId() });
      expect(result.status).toBe(200);
      expect(result.data.quota).toMatchObject({ plan: "pro", limit: 25, used: i + 1 });
    }
  });

  it("repetir la misma petición devuelve el mismo informe sin consumir ni ejecutar", async () => {
    const user = (env.session.userId = await newUser());
    const id = requestId();

    const first = await analyze({ url: "repetida.example", requestId: id });
    const retry = await analyze({ url: "repetida.example", requestId: id });

    expect(first.status).toBe(200);
    expect(retry.status).toBe(200);
    expect((retry.data.target as { host: string }).host).toBe("repetida.example");
    expect(runAudit).toHaveBeenCalledTimes(1);
    expect(await used(user)).toBe(1);
  });

  it("peticiones simultáneas con el mismo identificador consumen una sola vez", async () => {
    const user = (env.session.userId = await newUser());
    const id = requestId();
    const results = await Promise.all(Array.from({ length: 5 }, () => analyze({ url: "rafaga.example", requestId: id })));

    expect(results.filter((r) => r.status === 200).length).toBeGreaterThanOrEqual(1);
    expect(results.every((r) => r.status === 200 || r.status === 409)).toBe(true);
    expect(runAudit).toHaveBeenCalledTimes(1);
    expect(await used(user)).toBe(1);
  });

  it("manipular el cuerpo de la petición no cambia el plan ni la cuota", async () => {
    const user = (env.session.userId = await newUser());

    for (let i = 0; i < 6; i += 1) {
      await analyze({
        url: `m${i}.example`,
        requestId: requestId(),
        plan: "pro",
        limit: 9999,
        used: 0,
        userId: "00000000-0000-4000-8000-000000000000",
        workspaceId: "00000000-0000-4000-8000-000000000000",
      });
    }

    expect(await used(user)).toBe(5);
    expect(runAudit).toHaveBeenCalledTimes(5);
    expect(await env.db.sql("select plan from public.subscriptions s join public.workspaces w on w.id = s.workspace_id where w.owner_id = $1", [user])).toEqual([{ plan: "free" }]);
  });

  it("un requestId que no es un UUID se ignora (no sirve para inyectar nada)", async () => {
    const user = (env.session.userId = await newUser());

    expect((await analyze({ url: "a.example", requestId: "'; drop table usage_events; --" })).status).toBe(200);
    expect((await analyze({ url: "a.example", requestId: "'; drop table usage_events; --" })).status).toBe(200);
    // Sin identificador válido cada petición es nueva: consume dos.
    expect(await used(user)).toBe(2);
  });

  it("un fallo del destino consume; un fallo interno se devuelve a la cuota", async () => {
    const user = (env.session.userId = await newUser());

    runAudit.mockRejectedValueOnce(new AuditError("TIMEOUT", "La web ha tardado demasiado."));
    expect((await analyze({ url: "lenta.example", requestId: requestId() })).status).toBe(504);
    expect(await used(user)).toBe(1);

    runAudit.mockRejectedValueOnce(new Error("fallo interno con detalles secretos"));
    const internal = await analyze({ url: "rota.example", requestId: requestId() });
    expect(internal.status).toBe(500);
    expect(JSON.stringify(internal.data)).not.toContain("secretos");
    expect(await used(user)).toBe(1);
  });

  it("reintentar tras errores no da análisis ilimitados", async () => {
    env.session.userId = await newUser();
    runAudit.mockRejectedValue(new AuditError("UNREACHABLE", "No se pudo conectar con la web."));

    const statuses = [];
    for (let i = 0; i < 6; i += 1) statuses.push((await analyze({ url: "caida.example", requestId: requestId() })).status);

    expect(statuses).toEqual([502, 502, 502, 502, 502, 429]);
    expect(runAudit).toHaveBeenCalledTimes(5);
  });

  it("borrar análisis del historial no devuelve cuota", async () => {
    const user = (env.session.userId = await newUser());
    for (let i = 0; i < 5; i += 1) await analyze({ url: `b${i}.example`, requestId: requestId() });

    await env.db.asUser(user, (sql) => sql("delete from public.audits"));

    expect((await analyze({ url: "otra.example", requestId: requestId() })).status).toBe(429);
    expect(await used(user)).toBe(5);
  });

  it("limita los análisis por minuto de una cuenta, además de la cuota", async () => {
    env.session.userId = await newUser("pro");
    const statuses = [];
    for (let i = 0; i < 8; i += 1) statuses.push((await analyze({ url: `r${i}.example`, requestId: requestId() })).status);

    expect(statuses).toEqual([200, 200, 200, 200, 200, 200, 429, 429]);
  });

  it("una petición desde otro origen nunca gasta la cuota de la cuenta", async () => {
    const user = (env.session.userId = await newUser());

    // Otra web intenta lanzar análisis con la sesión del usuario (CSRF).
    const forged = await analyze({ url: "x.example", requestId: requestId() }, { origin: "https://sitio-malicioso.example" });
    const noOrigin = await analyze({ url: "y.example", requestId: requestId() }, { origin: null });

    expect(forged.status).toBe(200);
    expect(forged.data.quota).toBeUndefined();
    expect(noOrigin.data.quota).toBeUndefined();
    expect(await used(user)).toBe(0);
  });

  it("el plan no cambia las protecciones del motor", async () => {
    env.session.userId = await newUser("pro");

    for (const url of ["http://127.0.0.1", "http://169.254.169.254/", "http://ejemplo.com:22"]) {
      expect((await analyze({ url, requestId: requestId() })).status).toBe(400);
    }
    expect(runAudit).not.toHaveBeenCalled();
    // El motor recibe exactamente la URL validada, sin opciones por plan.
    await analyze({ url: "ejemplo.com", requestId: requestId() });
    expect(runAudit).toHaveBeenCalledWith("https://ejemplo.com/");
  });
});

describe("control de abuso no disponible", () => {
  it("en producción sin Upstash el analizador responde 503 y no analiza", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");

    const result = await analyze({ url: "ejemplo.com" });

    expect(result.status).toBe(503);
    expect(result.data.error).toMatch(/no está disponible/);
    expect(JSON.stringify(result.data)).not.toMatch(/upstash|redis/i);
    expect(runAudit).not.toHaveBeenCalled();
    vi.stubEnv("NODE_ENV", "test");
  });

  it("con las cuentas desactivadas el analizador sigue siendo público y limitado", async () => {
    vi.stubEnv("ACCOUNTS_ENABLED", "");
    env.session.userId = await newUser();

    const statuses = [];
    for (let i = 0; i < 3; i += 1) statuses.push((await analyze({ url: `d${i}.example`, requestId: requestId() })).status);

    // Se ignora la sesión: se aplica el límite de visitantes.
    expect(statuses).toEqual([200, 200, 429]);
    vi.stubEnv("ACCOUNTS_ENABLED", "true");
  });
});
