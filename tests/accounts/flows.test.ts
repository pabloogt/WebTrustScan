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
import { GET as confirm } from "@/app/auth/confirm/route";
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

const open = (mail: Mail, extra = "") =>
  call(confirm, { path: `/auth/confirm?token_hash=${mail.tokenHash}&type=${mail.type}${extra}` });

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
    const response = await open(lastMail("nueva@ejemplo.test", "email"), "&next=/panel");

    expect(response.status).toBe(307);
    expect(response.response.headers.get("location")).toBe("http://localhost/panel");

    const account = await call(accountRoute);
    expect(account.status).toBe(200);
    expect(account.data).toMatchObject({
      user: { email: "nueva@ejemplo.test" },
      plan: { id: "free", monthlyAudits: 5, historySize: 10 },
      usage: { used: 0, remaining: 5 },
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

    expect((await open(mail)).response.headers.get("location")).toBe("http://localhost/panel");
    env.session.userId = null;

    const again = await open(mail);
    expect(again.response.headers.get("location")).toBe("http://localhost/acceso?estado=enlace-no-valido");
    expect(env.session.userId).toBeNull();
  });

  it("un enlace caducado, inventado o de otro tipo no abre sesión", async () => {
    await call(register, { method: "POST", body: { email: "caduca@ejemplo.test", password: PASSWORD } });
    const mail = lastMail("caduca@ejemplo.test", "email");
    const failed = "http://localhost/acceso?estado=enlace-no-valido";

    env.now.value += 2 * 3_600_000;
    expect((await open(mail)).response.headers.get("location")).toBe(failed);
    env.now.value = Date.now();

    for (const path of [
      "/auth/confirm?token_hash=inventado&type=email",
      `/auth/confirm?token_hash=${mail.tokenHash}&type=recovery`,
      `/auth/confirm?token_hash=${mail.tokenHash}&type=magiclink`,
      "/auth/confirm?type=email",
      `/auth/confirm?token_hash=${"a".repeat(500)}&type=email`,
    ]) {
      expect((await call(confirm, { path })).response.headers.get("location"), path).toBe(failed);
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
    const response = await open(lastMail("redir@ejemplo.test", "email"), "&next=https://malicioso.example");
    expect(response.response.headers.get("location")).toBe("http://localhost/panel");
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
      [login, "POST"], [register, "POST"], [recover, "POST"], [logout, "POST"],
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
    const response = await open(lastMail("ana@ejemplo.test", "recovery"));

    expect(response.response.headers.get("location")).toBe("http://localhost/cuenta/nueva-contrasena");
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

  it("limita las solicitudes de recuperación por cuenta sin delatarlo", async () => {
    resetLimitsForTests();
    const sent = env.outbox.length;
    const responses = [];
    for (let i = 0; i < 5; i += 1) {
      responses.push(await call(recover, { method: "POST", body: { email: "ana@ejemplo.test" } }));
    }

    expect(responses.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(new Set(responses.map((r) => JSON.stringify(r.data))).size).toBe(1);
    // Solo se envían 3 correos; los demás se responden igual pero no salen.
    expect(env.outbox.length - sent).toBe(3);
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
    expect(account.data.plan).toMatchObject({ id: "free", monthlyAudits: 5 });
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
      plan: { id: "pro", label: "Pro", monthlyAudits: 100, historySize: 100 },
      usage: { used: 1, remaining: 99 },
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
    // Queda solo el consumo del periodo, bajo un HMAC del correo.
    const carry = await env.db.sql<{ email_hash: string; used: number }>("select email_hash, used from public.usage_carryover");
    expect(carry).toEqual([{ email_hash: pseudonym("email", "alice@datos.test"), used: 1 }]);
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
      new Set(["register_requested", "login_failed", "recovery_requested", "password_changed", "email_change_requested", "account_deleted"]),
    );
    for (const row of rows) expect(row.ip_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rows)).not.toMatch(/@|127\.0\.0\.1|198\.51/);
  });
});
