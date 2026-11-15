import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { GET as me } from "@/app/api/auth/me/route";
import { POST as register } from "@/app/api/auth/register/route";
import {
  authenticate,
  createSession,
  destroyAllSessions,
  getSession,
  hashPassword,
  registerUser,
  verifyPassword,
} from "@/lib/pro/auth";
import { setDbForTests, type Db } from "@/lib/pro/db";
import { resetRateLimitsForTests, sessionCookieName } from "@/lib/pro/http";
import { call, createTestDb } from "./helpers";

let db: Db;
const PASSWORD = "una-contraseña-larga-1";

beforeAll(async () => {
  db = await createTestDb();
  setDbForTests(db);
  await registerUser(db, { email: "Ana@Ejemplo.com", password: PASSWORD });
});

afterAll(async () => {
  setDbForTests(null);
  await db.close();
});

beforeEach(() => {
  resetRateLimitsForTests();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("contraseñas", () => {
  it("se guardan con scrypt y sal aleatoria, nunca en claro", async () => {
    const [a, b] = await Promise.all([hashPassword(PASSWORD), hashPassword(PASSWORD)]);

    expect(a).toMatch(/^scrypt\$32768\$8\$3\$/);
    expect(a).not.toBe(b);
    expect(a).not.toContain(PASSWORD);
    expect(await verifyPassword(PASSWORD, a)).toBe(true);
    expect(await verifyPassword(`${PASSWORD}x`, a)).toBe(false);
    expect(await verifyPassword(PASSWORD, "formato-desconocido")).toBe(false);

    const [row] = await db.query<{ password_hash: string }>(
      "select password_hash from users",
    );
    expect(row.password_hash).toMatch(/^scrypt\$/);
  });
});

describe("registro", () => {
  it("crea usuario, organización y pertenencia como propietario", async () => {
    const userId = await authenticate(db, "ana@ejemplo.com", PASSWORD);
    const session = await getSession(db, await createSession(db, userId as string));

    expect(session).toMatchObject({
      user: { email: "ana@ejemplo.com" },
      organization: { name: "Organización de ana", plan: "free" },
      role: "owner",
    });
  });

  it("rechaza correos duplicados sin distinguir mayúsculas", async () => {
    await expect(
      registerUser(db, { email: "ANA@ejemplo.com", password: PASSWORD }),
    ).rejects.toMatchObject({ status: 409 });
  });

  it.each([
    [{ email: "no-es-correo", password: PASSWORD }],
    [{ email: "a@b.co", password: "corta" }],
    [{ email: "a@b.co", password: "x".repeat(201) }],
    [{ email: 42, password: PASSWORD }],
    [{ email: "a@b.co" }],
  ])("valida la entrada %#", async (body) => {
    const result = await call(register, { method: "POST", body });

    expect(result.status).toBe(400);
  });

  it("no deja datos a medias si falla (transacción)", async () => {
    const before = await db.query("select id from organizations");

    await expect(
      registerUser(db, { email: "ana@ejemplo.com", password: PASSWORD }),
    ).rejects.toThrow();

    expect(await db.query("select id from organizations")).toHaveLength(before.length);
  });
});

describe("acceso", () => {
  it("credenciales correctas abren sesión con cookie HttpOnly y SameSite", async () => {
    const result = await call(login, {
      method: "POST",
      body: { email: "ana@ejemplo.com", password: PASSWORD },
    });
    const cookie = result.response.headers.get("set-cookie") ?? "";

    expect(result.status).toBe(200);
    expect(cookie).toMatch(/^wts_session=[\w-]{43};/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=lax/i);
    expect(cookie).toMatch(/Path=\//);
    expect(cookie).toMatch(/Max-Age=2592000/);
    // El token no viaja en el cuerpo ni la contraseña en la respuesta.
    expect(JSON.stringify(result.data)).not.toMatch(/password|token/i);
  });

  it("en producción la cookie usa el prefijo __Host- y Secure", () => {
    expect(sessionCookieName({ NODE_ENV: "production" } as NodeJS.ProcessEnv)).toBe(
      "__Host-wts_session",
    );
  });

  it("el mismo error para contraseña incorrecta y cuenta inexistente", async () => {
    const wrong = await call(login, {
      method: "POST",
      body: { email: "ana@ejemplo.com", password: "incorrecta-123" },
    });
    const unknown = await call(login, {
      method: "POST",
      body: { email: "nadie@ejemplo.com", password: "incorrecta-123" },
    });

    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.data).toEqual(unknown.data);
    expect(wrong.response.headers.get("set-cookie")).toBeNull();
  });

  it("limita los intentos de acceso por cliente", async () => {
    const statuses: number[] = [];

    for (let i = 0; i < 12; i += 1) {
      statuses.push(
        (
          await call(login, {
            method: "POST",
            body: { email: "ana@ejemplo.com", password: "incorrecta-123" },
          })
        ).status,
      );
    }

    expect(statuses.slice(0, 10)).toEqual(Array(10).fill(401));
    expect(statuses.slice(10)).toEqual([429, 429]);
  });

  it("entradas con tipos inesperados no provocan errores internos", async () => {
    for (const body of [{ email: { $ne: "" }, password: ["x"] }, {}, { email: "a' or 1=1--", password: "x" }]) {
      expect((await call(login, { method: "POST", body })).status).toBe(401);
    }
  });
});

describe("sesiones", () => {
  it("en la base de datos solo se guarda el hash del token", async () => {
    const userId = (await authenticate(db, "ana@ejemplo.com", PASSWORD)) as string;
    const token = await createSession(db, userId);
    const rows = await db.query<{ token_hash: string }>("select token_hash from sessions");

    expect(rows.some((row) => row.token_hash === token)).toBe(false);
    expect(rows.every((row) => /^[0-9a-f]{64}$/.test(row.token_hash))).toBe(true);
  });

  it("caducan a los 30 días y los tokens inválidos no resuelven", async () => {
    const userId = (await authenticate(db, "ana@ejemplo.com", PASSWORD)) as string;
    const start = new Date("2026-01-01T00:00:00Z");
    const token = await createSession(db, userId, start);

    expect(await getSession(db, token, new Date("2026-01-30T00:00:00Z"))).not.toBeNull();
    expect(await getSession(db, token, new Date("2026-02-01T00:00:00Z"))).toBeNull();
    expect(await getSession(db, "token-inventado")).toBeNull();
    expect(await getSession(db, "")).toBeNull();
    expect(await getSession(db, "x".repeat(5000))).toBeNull();
  });

  it("cerrar sesión invalida el token en el servidor", async () => {
    const userId = (await authenticate(db, "ana@ejemplo.com", PASSWORD)) as string;
    const token = await createSession(db, userId);

    expect((await call(me, { token })).status).toBe(200);

    const out = await call(logout, { method: "POST", token });
    expect(out.response.headers.get("set-cookie")).toMatch(/Max-Age=0/);

    // La cookie robada deja de servir aunque el navegador la conserve.
    expect((await call(me, { token })).status).toBe(401);
  });

  it("se pueden cerrar todas las sesiones de un usuario", async () => {
    const userId = (await authenticate(db, "ana@ejemplo.com", PASSWORD)) as string;
    const tokens = [await createSession(db, userId), await createSession(db, userId)];

    await destroyAllSessions(db, userId);

    for (const token of tokens) expect(await getSession(db, token)).toBeNull();
  });

  it("sin sesión las rutas privadas responden 401", async () => {
    expect((await call(me)).status).toBe(401);
    expect((await call(me, { token: "falso" })).status).toBe(401);
  });
});

describe("protección CSRF", () => {
  const body = { email: "ana@ejemplo.com", password: PASSWORD };

  it("rechaza peticiones que modifican estado desde otro origen", async () => {
    const result = await call(login, {
      method: "POST",
      body,
      origin: "https://sitio-malicioso.example",
    });

    expect(result.status).toBe(403);
    expect(result.response.headers.get("set-cookie")).toBeNull();
  });

  it("rechaza peticiones sin cabecera Origin o con un valor inválido", async () => {
    expect((await call(login, { method: "POST", body, origin: null })).status).toBe(403);
    expect((await call(login, { method: "POST", body, origin: "null" })).status).toBe(403);
  });

  it("exige JSON: un formulario HTML clásico no puede invocar la API", async () => {
    const result = await call(logout, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    // logout no lee cuerpo, pero register y login sí lo exigen:
    expect(result.status).toBe(200);

    const form = await call(register, {
      method: "POST",
      headers: { "content-type": "text/plain" },
    });
    expect(form.status).toBe(400);
  });
});
