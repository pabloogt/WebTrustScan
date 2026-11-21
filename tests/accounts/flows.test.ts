import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
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
import { POST as confirm } from "@/app/api/auth/confirm/route";
import { RECOVERY_COOKIE, createRecoveryTicket, verifyRecoveryTicket } from "@/lib/accounts/analyze";
import { safeNextPath } from "@/lib/accounts/http";
import { pseudonym, resetLimitsForTests } from "@/lib/limits";
import { PASSWORD, call, createEnv, sampleReport, type Env, type Mail } from "./fakes";

/**
 * Flujos de cuenta de extremo a extremo por las rutas reales. La
 * autenticación es un doble que imita a Supabase Auth; los datos pasan por
 * PostgreSQL con RLS.
 */

let env: Env;

beforeAll(async () => {
  vi.stubEnv("ACCOUNTS_ENABLED", "true");
  env = await createEnv();
});
afterAll(async () => {
  vi.unstubAllEnvs();
  await env.close();
});
beforeEach(() => {
  resetLimitsForTests();
  env.session.userId = null;
  env.now.value = Date.now();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

const lastMail = (to: string, type: Mail["type"]) =>
  [...env.outbox].reverse().find((mail) => mail.to === to && mail.type === type) as Mail;

/**
 * Pulsar «Continuar» en /auth/confirm tras abrir el enlace del correo. La
 * página no canjea nada por sí sola: lo hace esta petición POST.
 */
const open = (mail: Mail, next?: string) =>
  call(confirm, { method: "POST", body: { tokenHash: mail.tokenHash, type: mail.type, next } });

const EXPIRED = {
  error: "El enlace no es válido, ha caducado o ya se ha usado. Solicita uno nuevo.",
  code: "link_expired",
};

/** Alta + confirmación de correo. Devuelve el identificador del usuario. */
async function signUp(email: string, password = PASSWORD): Promise<string> {
  await call(register, { method: "POST", body: { email, password } });
  await open(lastMail(email, "email"));
  const id = env.session.userId as string;
  env.session.userId = null;
  return id;
}

const signIn = (email: string, password = PASSWORD) =>
  call(login, { method: "POST", body: { email, password } });

async function storeAudit(userId: string, hostname: string): Promise<string> {
  const [{ r }] = await env.db.sql<{ r: { usage_id: string } }>(
    `select public.reserve_audit($1, gen_random_uuid(), '{"free":5,"pro":100}'::jsonb, 5) as r`,
    [userId],
  );
  const [{ id }] = await env.db.sql<{ id: string }>(
    "select public.complete_audit($1, $2, $3::jsonb, 10) as id",
    [r.usage_id, hostname, JSON.stringify(sampleReport(hostname))],
  );
  return id;
}

describe("registro", () => {
  it("crea la cuenta, envía el enlace y no abre sesión hasta confirmar", async () => {
    const result = await call(register, {
      method: "POST",
      body: { email: "Nueva@Ejemplo.test", password: PASSWORD },
    });

    expect(result.status).toBe(200);
    expect(result.data.message).toMatch(/te hemos enviado un correo/);
    expect(env.session.userId).toBeNull();

    const mail = lastMail("nueva@ejemplo.test", "email");
    expect(mail.redirectTo).toBe("http://localhost:3000/auth/confirm?next=%2Fpanel");

    // Sin confirmar no se puede entrar, con el mismo error que una contraseña mala.
    const early = await signIn("nueva@ejemplo.test");
    expect(early.status).toBe(401);
    expect(early.data.error).toBe("Correo o contraseña incorrectos.");
  });

  it("confirmar el correo abre sesión y deja creados perfil, espacio y plan Free", async () => {
    const response = await open(lastMail("nueva@ejemplo.test", "email"), "/panel");

    expect(response.status).toBe(200);
    expect(response.data).toEqual({ next: "/panel" });

    const account = await call(accountRoute);
    expect(account.status).toBe(200);
    expect(account.data).toMatchObject({
      user: { email: "nueva@ejemplo.test" },
      plan: { id: "free", auditsPerWindow: 5, windowDays: 7, historySize: 10 },
      usage: { used: 0, limit: 5, remaining: 5, windowDays: 7, nextReleaseAt: null, availableAt: null },
    });
  });

  it("un correo ya registrado recibe exactamente la misma respuesta", async () => {
    const fresh = await call(register, { method: "POST", body: { email: "otra@ejemplo.test", password: PASSWORD } });
    const sent = env.outbox.length;
    const duplicate = await call(register, { method: "POST", body: { email: "otra@ejemplo.test", password: "otra-clave-distinta" } });

    expect(duplicate.status).toBe(fresh.status);
    expect(duplicate.data).toEqual(fresh.data);
    // Y no se crea nada ni se envía otro correo.
    expect(env.outbox.length).toBe(sent);
    expect([...env.users.values()].filter((u) => u.email === "otra@ejemplo.test")).toHaveLength(1);
  });

  it.each([
    [{ email: "no-es-correo", password: PASSWORD }, /correo válida/],
    [{ email: "a@b.test", password: "corta" }, /entre 10 y 72/],
    [{ email: "a@b.test", password: "x".repeat(73) }, /entre 10 y 72/],
    [{ email: 42, password: PASSWORD }, /correo válida/],
    [{ email: "a@b.test", password: "contraseña123" }, /demasiado débil/],
  ])("valida la entrada %#", async (body, message) => {
    const result = await call(register, { method: "POST", body });

    expect(result.status).toBe(400);
    expect(result.data.error).toMatch(message);
  });

  it("limita las altas por cliente", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i += 1) {
      statuses.push((await call(register, { method: "POST", body: { email: `r${i}@limite.test`, password: PASSWORD } })).status);
    }

    expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429]);
  });
});

describe("enlaces de correo", () => {
  it("un enlace solo sirve una vez", async () => {
    await call(register, { method: "POST", body: { email: "unavez@ejemplo.test", password: PASSWORD } });
    const mail = lastMail("unavez@ejemplo.test", "email");

    expect((await open(mail)).data).toEqual({ next: "/panel" });
    env.session.userId = null;

    const again = await open(mail);
    expect(again.status).toBe(400);
    expect(again.data).toEqual(EXPIRED);
    expect(env.session.userId).toBeNull();
  });

  it("un enlace caducado, inventado o de otro tipo no abre sesión", async () => {
    await call(register, { method: "POST", body: { email: "caduca@ejemplo.test", password: PASSWORD } });
    const mail = lastMail("caduca@ejemplo.test", "email");

    env.now.value += 2 * 3_600_000;
    expect((await open(mail)).data).toEqual(EXPIRED);
    env.now.value = Date.now();

    for (const body of [
      { tokenHash: "inventado", type: "email" },
      { tokenHash: mail.tokenHash, type: "recovery" },
      { tokenHash: mail.tokenHash, type: "magiclink" },
      { type: "email" },
      { tokenHash: "a".repeat(500), type: "email" },
      { code: "inventado" },
      { tokenHash: ["x"], type: "email" },
      {},
    ]) {
      const result = await call(confirm, { method: "POST", body });
      expect(result.status, JSON.stringify(body)).toBe(400);
      expect(result.data).toEqual(EXPIRED);
      expect(result.response.headers.get("set-cookie")).toBeNull();
    }
    expect(env.session.userId).toBeNull();
  });

  it("tras confirmar solo se redirige a rutas internas", async () => {
    for (const [next, expected] of [
      ["/panel", "/panel"],
      ["https://malicioso.example/robar", "/panel"],
      ["//malicioso.example", "/panel"],
      ["/\\malicioso.example", "/panel"],
      ["/panel/../../etc", "/panel"],
      ["javascript:alert(1)", "/panel"],
      [undefined, "/panel"],
    ] as const) {
      expect(safeNextPath(next), String(next)).toBe(expected);
    }

    await call(register, { method: "POST", body: { email: "redir@ejemplo.test", password: PASSWORD } });
    const response = await open(lastMail("redir@ejemplo.test", "email"), "https://malicioso.example");
    expect(response.data).toEqual({ next: "/panel" });
  });

  it("canjear el enlace exige mismo origen: abrirlo desde otra web no lo gasta", async () => {
    await call(register, { method: "POST", body: { email: "origen@ejemplo.test", password: PASSWORD } });
    const mail = lastMail("origen@ejemplo.test", "email");
    const body = { tokenHash: mail.tokenHash, type: mail.type };

    expect((await call(confirm, { method: "POST", body, origin: "https://otra.example" })).status).toBe(403);
    expect((await call(confirm, { method: "POST", body, origin: null })).status).toBe(403);
    expect(mail.used).toBe(false);
    expect((await call(confirm, { method: "POST", body })).data).toEqual({ next: "/panel" });
  });

  it("acepta también el enlace predeterminado de Supabase (?code=, flujo PKCE)", async () => {
    await call(register, { method: "POST", body: { email: "pkce@ejemplo.test", password: PASSWORD } });
    const mail = lastMail("pkce@ejemplo.test", "email");
    const result = await call(confirm, { method: "POST", body: { code: mail.tokenHash, next: "/panel" } });

    expect(result.status).toBe(200);
    expect(result.data).toEqual({ next: "/panel" });
    // Con `code` y destino normal no se concede pase de recuperación.
    expect(result.response.headers.get("set-cookie")).toBeNull();
    expect(env.session.userId).toBe(mail.userId);
  });
});

describe("acceso y sesión", () => {
  it("credenciales correctas abren sesión; el token no viaja en la respuesta", async () => {
    await signUp("ana@ejemplo.test");
    const result = await signIn("ana@ejemplo.test");

    expect(result.status).toBe(200);
    expect(result.data).toEqual({ user: { email: "ana@ejemplo.test" } });
    expect(JSON.stringify(result.data)).not.toMatch(/token|password|id"/i);
  });

  it("mismo error para contraseña incorrecta, cuenta inexistente y entrada malformada", async () => {
    const responses = await Promise.all([
      signIn("ana@ejemplo.test", "contraseña-incorrecta"),
      signIn("nadie@ejemplo.test", "contraseña-incorrecta"),
      call(login, { method: "POST", body: { email: { $ne: "" }, password: ["x"] } }),
      call(login, { method: "POST", body: {} }),
      call(login, { method: "POST", body: { email: "ana@ejemplo.test", password: "x".repeat(5000) } }),
    ]);

    for (const response of responses) {
      expect(response.status).toBe(401);
      expect(response.data).toEqual({ error: "Correo o contraseña incorrectos." });
    }
    expect(env.session.userId).toBeNull();
  });

  it("limita los intentos por cliente y también por cuenta atacada desde muchas IP", async () => {
    const byIp: number[] = [];
    for (let i = 0; i < 12; i += 1) byIp.push((await signIn(`x${i}@ejemplo.test`, "incorrecta-123")).status);
    expect(byIp.slice(0, 10)).toEqual(Array(10).fill(401));
    expect(byIp.slice(10)).toEqual([429, 429]);

    // Fuerza bruta distribuida: cada intento llega desde una IP distinta.
    resetLimitsForTests();
    vi.stubEnv("TRUSTED_PROXY_HOPS", "1");
    const byAccount: number[] = [];
    for (let i = 0; i < 12; i += 1) {
      byAccount.push(
        (
          await call(login, {
            method: "POST",
            body: { email: "ana@ejemplo.test", password: "incorrecta-123" },
            headers: { "x-forwarded-for": `198.51.100.${i}` },
          })
        ).status,
      );
    }
    vi.stubEnv("TRUSTED_PROXY_HOPS", "");

    expect(byAccount.slice(0, 10)).toEqual(Array(10).fill(401));
    expect(byAccount.slice(10)).toEqual([429, 429]);
    // Ni siquiera la contraseña correcta entra mientras dure el bloqueo.
    expect((await signIn("ana@ejemplo.test")).status).toBe(429);
  });

  it("sin sesión las rutas privadas responden 401", async () => {
    const id = "00000000-0000-4000-8000-000000000000";

    expect((await call(accountRoute)).status).toBe(401);
    expect((await call(auditsRoute)).status).toBe(401);
    expect((await call(auditRoute, { params: { id } })).status).toBe(401);
    expect((await call(exportRoute)).status).toBe(401);
    expect((await call(profileRoute, { method: "PATCH", body: { displayName: "x" } })).status).toBe(401);
    expect((await call(passwordRoute, { method: "POST", body: { password: PASSWORD } })).status).toBe(401);
    expect((await call(emailRoute, { method: "POST", body: { email: "a@b.test" } })).status).toBe(401);
    expect((await call(deleteRoute, { method: "POST", body: {} })).status).toBe(401);
    expect((await call(deleteAuditRoute, { method: "DELETE", params: { id } })).status).toBe(401);
  });

  it("cerrar sesión la invalida; «todas» revoca en el proveedor", async () => {
    await signIn("ana@ejemplo.test");
    expect((await call(accountRoute)).status).toBe(200);

    expect((await call(logout, { method: "POST", body: { scope: "all" } })).status).toBe(200);
    expect((await call(accountRoute)).status).toBe(401);
  });

  it("las peticiones que modifican estado exigen mismo origen y cuerpo JSON", async () => {
    await signIn("ana@ejemplo.test");
    const evil = "https://sitio-malicioso.example";

    for (const [handler, method] of [
      [login, "POST"], [register, "POST"], [recover, "POST"], [logout, "POST"], [confirm, "POST"],
      [passwordRoute, "POST"], [emailRoute, "POST"], [deleteRoute, "POST"], [profileRoute, "PATCH"],
    ] as const) {
      expect((await call(handler, { method, body: {}, origin: evil })).status).toBe(403);
      expect((await call(handler, { method, body: {}, origin: null })).status).toBe(403);
    }
    expect(
      (await call(register, { method: "POST", headers: { "content-type": "text/plain" } })).status,
    ).toBe(400);
    // Nada de lo anterior ha cerrado la sesión ni cambiado la cuenta.
    expect((await call(accountRoute)).status).toBe(200);
  });
});

describe("recuperación y cambio de contraseña", () => {
  it("la solicitud responde igual exista o no la cuenta", async () => {
    const known = await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } });
    const sent = env.outbox.length;
    const unknown = await call(recover, { method: "POST", body: { email: "nadie@ejemplo.test" } });

    expect(known.status).toBe(200);
    expect(unknown.data).toEqual(known.data);
    expect(env.outbox.length).toBe(sent); // a la inexistente no se le envía nada
  });

  it("el enlace lleva a fijar una contraseña nueva sin pedir la anterior, una sola vez", async () => {
    await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } });
    const mail = lastMail("ana@ejemplo.test", "recovery");
    expect(mail.redirectTo).toBe("http://localhost:3000/auth/confirm?next=%2Fcuenta%2Fnueva-contrasena");
    // Aunque el enlace diga otra cosa, la recuperación siempre lleva a fijar la contraseña.
    const response = await open(mail, "/panel");

    expect(response.data).toEqual({ next: "/cuenta/nueva-contrasena" });
    const cookie = response.response.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(new RegExp(`^${RECOVERY_COOKIE}=`));
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/Max-Age=900/);

    const ticket = cookie.split(";")[0];
    const changed = await call(passwordRoute, {
      method: "POST",
      body: { password: "contraseña-recuperada-1" },
      cookie: ticket,
    });
    expect(changed.status).toBe(200);
    // El pase se retira al usarse.
    expect(changed.response.headers.get("set-cookie")).toMatch(/Max-Age=0/);

    env.session.userId = null;
    expect((await signIn("ana@ejemplo.test", PASSWORD)).status).toBe(401);
    expect((await signIn("ana@ejemplo.test", "contraseña-recuperada-1")).status).toBe(200);
    expect(env.events.some((event) => event.type === "password_changed")).toBe(true);
  });

  it("el enlace predeterminado de Supabase (?code=) también concede el pase de recuperación", async () => {
    await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } });
    const mail = lastMail("ana@ejemplo.test", "recovery");
    const result = await call(confirm, {
      method: "POST",
      body: { code: mail.tokenHash, next: "/cuenta/nueva-contrasena" },
    });

    expect(result.data).toEqual({ next: "/cuenta/nueva-contrasena" });
    expect(result.response.headers.get("set-cookie")).toMatch(new RegExp(`^${RECOVERY_COOKIE}=`));
    env.session.userId = null;
  });

  it("un enlace de recuperación ya usado o caducado se rechaza con un mensaje claro", async () => {
    await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } });
    const mail = lastMail("ana@ejemplo.test", "recovery");

    env.now.value += 3_600_001; // una hora y un milisegundo
    const late = await open(mail);
    expect(late.status).toBe(400);
    expect(late.data).toEqual(EXPIRED);
    expect(late.response.headers.get("set-cookie")).toBeNull();
    expect(env.session.userId).toBeNull();
  });

  it("entre dos correos a la misma cuenta hay que esperar 60 segundos, sin delatarlo", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
    try {
      resetLimitsForTests();
      const sent = env.outbox.length;
      const ask = (email = "ana@ejemplo.test") =>
        call(recover, { method: "POST", body: { email } });

      const first = await ask();
      expect(first.status).toBe(200);
      expect(first.data.retryAfterSeconds).toBe(60);
      expect(env.outbox.length - sent).toBe(1);

      // Dentro del minuto: misma respuesta, pero no sale ningún correo.
      vi.advanceTimersByTime(30_000);
      const early = await ask();
      expect(early.data).toEqual(first.data);
      expect(env.outbox.length - sent).toBe(1);
      expect(env.events.at(-1)).toMatchObject({ type: "recovery_not_sent", metadata: { reason: "cooldown_60s" } });

      // Pasado el minuto sí se envía otro.
      vi.advanceTimersByTime(31_000);
      await ask();
      expect(env.outbox.length - sent).toBe(2);
      // La espera es por cuenta: otra dirección no espera.
      expect((await ask("nadie@ejemplo.test")).data).toEqual(first.data);
    } finally {
      vi.useRealTimers();
    }
  });

  it("limita las solicitudes de recuperación por hora sin delatarlo", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() });
    try {
      resetLimitsForTests();
      const sent = env.outbox.length;
      const responses = [];
      for (let i = 0; i < 5; i += 1) {
        responses.push(await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } }));
        vi.advanceTimersByTime(61_000);
      }

      expect(responses.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
      expect(new Set(responses.map((r) => JSON.stringify(r.data))).size).toBe(1);
      // Solo se envían 3 correos por hora; los demás se responden igual pero no salen.
      expect(env.outbox.length - sent).toBe(3);
      expect(env.events.at(-1)).toMatchObject({ metadata: { reason: "app_hourly_limit" } });
    } finally {
      vi.useRealTimers();
    }
  });

  it("si el proveedor rechaza el envío, se registra el motivo y la respuesta no cambia", async () => {
    resetLimitsForTests();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    env.resetFailure = { ok: false, reason: "rate_limited", code: "over_email_send_rate_limit" };

    const result = await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } });

    expect(result.status).toBe(200);
    expect(result.data.message).toMatch(/Si existe una cuenta/);
    expect(env.events.at(-1)).toMatchObject({
      type: "recovery_not_sent",
      metadata: { reason: "provider:over_email_send_rate_limit" },
    });
    // El log lleva el motivo, nunca la dirección.
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/ana@ejemplo/);
    warn.mockRestore();
  });

  it("sin pase de recuperación válido hace falta la contraseña actual", async () => {
    const userId = [...env.users.values()].find((u) => u.email === "ana@ejemplo.test")!.id;
    const entered = await signIn("ana@ejemplo.test", "contraseña-recuperada-1");
    expect(entered.data, "inicio de sesión previo").toEqual({ user: { email: "ana@ejemplo.test" } });

    const attempts = [
      {},
      { cookie: `${RECOVERY_COOKIE}=9999999999.${"a".repeat(64)}` }, // firma inventada
      { cookie: `${RECOVERY_COOKIE}=${createRecoveryTicket("00000000-0000-4000-8000-000000000000")}` }, // de otro usuario
      { cookie: `${RECOVERY_COOKIE}=${createRecoveryTicket(userId, Date.now() - 16 * 60_000)}` }, // caducado
    ];
    for (const attempt of attempts) {
      const result = await call(passwordRoute, { method: "POST", body: { password: "robada-por-un-intruso" }, ...attempt });
      expect(result.status).toBe(400);
      expect(result.data.error).toBe("La contraseña actual no es correcta.");
    }

    // Desde la pantalla de recuperación con el pase caducado, el mensaje lo dice
    // y remite a pedir otro enlace (no pide «la contraseña actual»).
    const late = await call(passwordRoute, {
      method: "POST",
      body: { password: "robada-por-un-intruso", recovery: true },
      cookie: `${RECOVERY_COOKIE}=${createRecoveryTicket(userId, Date.now() - 16 * 60_000)}`,
    });
    expect(late.status).toBe(400);
    expect(late.data).toMatchObject({ code: "recovery_expired" });
    expect(late.data.error).toMatch(/ha caducado. Solicita uno nuevo/);

    expect(verifyRecoveryTicket(createRecoveryTicket(userId), userId)).toBe(true);
    expect(verifyRecoveryTicket(undefined, userId)).toBe(false);

    const ok = await call(passwordRoute, {
      method: "POST",
      body: { password: PASSWORD, currentPassword: "contraseña-recuperada-1" },
    });
    expect(ok.status).toBe(200);

    const same = await call(passwordRoute, { method: "POST", body: { password: PASSWORD, currentPassword: PASSWORD } });
    expect(same.status).toBe(400);
    expect(same.data.error).toMatch(/distinta de la actual/);
  });

  it("el cambio de correo exige contraseña y no se aplica hasta confirmar", async () => {
    await signIn("ana@ejemplo.test");

    expect(
      (await call(emailRoute, { method: "POST", body: { email: "ana.nueva@ejemplo.test", currentPassword: "mala" } })).status,
    ).toBe(400);

    const requested = await call(emailRoute, {
      method: "POST",
      body: { email: "ana.nueva@ejemplo.test", currentPassword: PASSWORD },
    });
    expect(requested.status).toBe(200);
    expect((await call(accountRoute)).data.user).toEqual({
      email: "ana@ejemplo.test",
      pendingEmail: "ana.nueva@ejemplo.test",
    });

    await open(lastMail("ana.nueva@ejemplo.test", "email_change"));
    expect((await call(accountRoute)).data.user).toMatchObject({ email: "ana.nueva@ejemplo.test", pendingEmail: null });

    // Pedir el correo de otra cuenta responde igual y no revela que existe.
    const taken = await call(emailRoute, { method: "POST", body: { email: "otra@ejemplo.test", currentPassword: PASSWORD } });
    expect(taken.data).toEqual(requested.data);
  });
});

describe("datos de la cuenta", () => {
  let alice: string;
  let bob: string;
  let auditAlice: string;

  beforeAll(async () => {
    alice = await signUp("alice@datos.test");
    bob = await signUp("bob@datos.test");
    auditAlice = await storeAudit(alice, "empresa-a.test");
    await storeAudit(bob, "empresa-b.test");
  });

  it("cada usuario ve solo su historial y sus informes", async () => {
    env.session.userId = alice;
    const mine = await call(auditsRoute);
    expect((mine.data.audits as { hostname: string }[]).map((a) => a.hostname)).toEqual(["empresa-a.test"]);
    expect((await call(auditRoute, { params: { id: auditAlice } })).status).toBe(200);
    expect(mine.response.headers.get("cache-control")).toBe("no-store");

    env.session.userId = bob;
    const theirs = await call(auditsRoute);
    expect((theirs.data.audits as { hostname: string }[]).map((a) => a.hostname)).toEqual(["empresa-b.test"]);

    // Bob conoce el identificador del informe de Alice: no existe para él.
    const stolen = await call(auditRoute, { params: { id: auditAlice } });
    const missing = await call(auditRoute, { params: { id: "00000000-0000-4000-8000-000000000000" } });
    expect(stolen.status).toBe(404);
    expect(stolen.data).toEqual(missing.data);
    expect(JSON.stringify(stolen.data)).not.toContain("empresa-a");

    expect((await call(deleteAuditRoute, { method: "DELETE", params: { id: auditAlice } })).status).toBe(404);
    env.session.userId = alice;
    expect((await call(auditRoute, { params: { id: auditAlice } })).status).toBe(200);
  });

  it.each(["no-es-uuid", "1 or 1=1", "'; drop table audits; --", "../../etc/passwd"])(
    "identificador malformado (%s) → 404 sin error interno",
    async (id) => {
      env.session.userId = alice;

      expect((await call(auditRoute, { params: { id } })).status).toBe(404);
      expect((await call(deleteAuditRoute, { method: "DELETE", params: { id } })).status).toBe(404);
      expect(console.error).not.toHaveBeenCalled();
    },
  );

  it("la exportación contiene solo los datos de quien la pide", async () => {
    env.session.userId = bob;
    const response = (await call(exportRoute)).response;
    const text = await response.text();

    expect(response.headers.get("content-disposition")).toMatch(/attachment; filename="webtrustscan-mis-datos\.json"/);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(text).toContain("empresa-b.test");
    expect(text).toContain("bob@datos.test");
    expect(text).not.toContain("empresa-a.test");
    expect(text).not.toContain("alice@datos.test");
    expect(text).not.toMatch(/password|token_hash|email_hash/i);
  });

  it("el nombre visible se valida y solo cambia el propio", async () => {
    env.session.userId = bob;

    expect((await call(profileRoute, { method: "PATCH", body: { displayName: "  Bob  " } })).status).toBe(200);
    expect((await call(accountRoute)).data.profile).toMatchObject({ displayName: "Bob" });
    expect((await call(profileRoute, { method: "PATCH", body: { displayName: "x".repeat(81) } })).status).toBe(400);
    expect((await call(profileRoute, { method: "PATCH", body: { displayName: "a\u0000b" } })).status).toBe(400);

    env.session.userId = alice;
    expect((await call(accountRoute)).data.profile).toMatchObject({ displayName: null });
  });

  it("el plan y el consumo no se pueden cambiar desde una petición", async () => {
    env.session.userId = bob;
    await call(profileRoute, {
      method: "PATCH",
      body: { displayName: "Bob", plan: "pro", role: "admin", used: 0, monthlyAudits: 9999 },
    });

    const account = await call(accountRoute);
    expect(account.data.plan).toMatchObject({ id: "free", auditsPerWindow: 5 });
    expect(account.data.usage).toMatchObject({ used: 1, remaining: 4 });
    expect(await env.db.sql("select 1 from public.app_admins where user_id = $1", [bob])).toEqual([]);
  });

  it("Pro solo se asigna desde el servidor y cambia los límites", async () => {
    await env.db.sql(
      "update public.subscriptions set plan = 'pro', provider = 'manual' where workspace_id = (select id from public.workspaces where owner_id = $1)",
      [bob],
    );
    env.session.userId = bob;

    expect((await call(accountRoute)).data).toMatchObject({
      plan: { id: "pro", label: "Pro", auditsPerWindow: 25, historySize: 50 },
      usage: { used: 1, limit: 25, remaining: 24 },
    });
  });

  it("eliminar la cuenta exige contraseña y confirmación, y borra todos sus datos", async () => {
    env.session.userId = alice;

    expect((await call(deleteRoute, { method: "POST", body: { password: "mala", confirm: "ELIMINAR" } })).status).toBe(400);
    expect((await call(deleteRoute, { method: "POST", body: { password: PASSWORD, confirm: "eliminar" } })).status).toBe(400);
    expect((await call(accountRoute)).status).toBe(200);

    expect((await call(deleteRoute, { method: "POST", body: { password: PASSWORD, confirm: "ELIMINAR" } })).status).toBe(200);

    expect(env.session.userId).toBeNull();
    expect((await signIn("alice@datos.test")).status).toBe(401);
    for (const table of ["profiles", "audits", "usage_events", "workspaces"]) {
      const column = table === "profiles" ? "id" : table === "workspaces" ? "owner_id" : "user_id";
      expect(await env.db.sql(`select 1 from public.${table} where ${column} = $1`, [alice]), table).toEqual([]);
    }
    // Queda solo la fecha de cada uso que aún cuenta, bajo un HMAC del correo.
    const carry = await env.db.sql<{ email_hash: string }>("select email_hash from public.usage_carryover_events");
    expect(carry).toEqual([{ email_hash: pseudonym("email", "alice@datos.test") }]);
    expect(JSON.stringify(carry)).not.toContain("alice");
    // Los datos de Bob siguen intactos.
    env.session.userId = bob;
    expect(((await call(auditsRoute)).data.audits as unknown[]).length).toBe(1);
  });

  it("volver a registrarse con el mismo correo no reinicia la cuota", async () => {
    await signUp("alice@datos.test");
    await signIn("alice@datos.test");

    expect((await call(accountRoute)).data.usage).toMatchObject({ used: 1, remaining: 4 });
  });

  it("los eventos de seguridad no guardan IP ni correos en claro", async () => {
    const rows = await env.db.sql<{ type: string; ip_hash: string | null; metadata: unknown }>(
      "select type, ip_hash, metadata from public.security_events",
    );

    expect(rows.length).toBeGreaterThan(5);
    expect(new Set(rows.map((row) => row.type))).toEqual(
      new Set(["register_requested", "login_failed", "recovery_not_sent", "recovery_requested", "password_changed", "email_change_requested", "account_deleted"]),
    );
    for (const row of rows) expect(row.ip_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rows)).not.toMatch(/@|127\.0\.0\.1|198\.51/);
  });
});
