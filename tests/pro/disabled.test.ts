import { NextRequest } from "next/server";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { POST as analyze } from "@/app/api/analyze/route";
import { GET as compareRoute } from "@/app/api/audits/compare/route";
import { GET as auditRoute } from "@/app/api/audits/[id]/route";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { GET as me } from "@/app/api/auth/me/route";
import { POST as register } from "@/app/api/auth/register/route";
import {
  GET as historyRoute,
  POST as runRoute,
} from "@/app/api/domains/[id]/audits/route";
import {
  DELETE as deleteRoute,
  GET as domainRoute,
} from "@/app/api/domains/[id]/route";
import { POST as verifyRoute } from "@/app/api/domains/[id]/verify/route";
import { GET as listRoute, POST as addRoute } from "@/app/api/domains/route";
import { accountsEnabled } from "@/lib/pro/config";
import { setDbForTests, type Db } from "@/lib/pro/db";
import { call, createAccount, createTestDb, type Account } from "./helpers";

/**
 * Cuentas desactivadas (el valor por defecto). La protección está en el
 * servidor: todas las rutas responden 404 antes de tocar la base de datos,
 * incluso con una sesión que era válida.
 */

let db: Db;
let account: Account;
const queries: string[] = [];

beforeAll(async () => {
  const real = await createTestDb();
  account = await createAccount(real, "antes@ejemplo.com");

  // Envoltorio que registra cualquier consulta hecha durante las pruebas.
  db = {
    query: (sql, params) => {
      queries.push(sql);
      return real.query(sql, params);
    },
    transaction: (work) => {
      queries.push("transaction");
      return real.transaction(work);
    },
    close: () => real.close(),
  };
  setDbForTests(db);
});

afterAll(async () => {
  setDbForTests(null);
  await db.close();
});

afterEach(() => {
  vi.unstubAllEnvs();
  queries.length = 0;
});

const ID = "00000000-0000-4000-8000-000000000000";
const ROUTES: [string, Parameters<typeof call>[0], Parameters<typeof call>[1]][] = [
  ["POST /api/auth/register", register, { method: "POST", body: { email: "x@y.com", password: "contraseña-larga-1" } }],
  ["POST /api/auth/login", login, { method: "POST", body: { email: "antes@ejemplo.com", password: "contraseña-de-prueba-1" } }],
  ["POST /api/auth/logout", logout, { method: "POST" }],
  ["GET /api/auth/me", me, {}],
  ["GET /api/domains", listRoute, {}],
  ["POST /api/domains", addRoute, { method: "POST", body: { hostname: "ejemplo.com" } }],
  ["GET /api/domains/[id]", domainRoute, { params: { id: ID } }],
  ["DELETE /api/domains/[id]", deleteRoute, { method: "DELETE", params: { id: ID } }],
  ["POST /api/domains/[id]/verify", verifyRoute, { method: "POST", params: { id: ID } }],
  ["GET /api/domains/[id]/audits", historyRoute, { params: { id: ID } }],
  ["POST /api/domains/[id]/audits", runRoute, { method: "POST", params: { id: ID } }],
  ["GET /api/audits/[id]", auditRoute, { params: { id: ID } }],
  ["GET /api/audits/compare", compareRoute, { path: `/api/audits/compare?from=${ID}&to=${ID}` }],
];

describe("interruptor de cuentas", () => {
  it.each([
    [undefined, false],
    ["", false],
    ["false", false],
    ["0", false],
    ["1", false],
    ["TRUE", false],
    ["True", false],
    ["yes", false],
    [" true", false],
    ["true", true],
  ])("ACCOUNTS_ENABLED=%j → activadas: %s", (value, expected) => {
    expect(accountsEnabled({ ACCOUNTS_ENABLED: value })).toBe(expected);
  });

  it("no depende de ninguna variable pública del navegador", () => {
    expect(accountsEnabled({ NEXT_PUBLIC_ACCOUNTS_ENABLED: "true" })).toBe(false);
  });
});

describe.each([
  ["sin definir (valor por defecto)", undefined],
  ["con un valor que no es exactamente «true»", "1"],
])("cuentas desactivadas · %s", (_name, value) => {
  const disable = () => vi.stubEnv("ACCOUNTS_ENABLED", value as string);

  it.each(ROUTES)("%s responde 404 con y sin sesión", async (_route, handler, options) => {
    disable();

    for (const token of [undefined, account.token]) {
      const result = await call(handler, { ...options, token });

      expect(result.status).toBe(404);
      expect(result.data).toEqual({ error: "No encontrado." });
      expect(result.response.headers.get("set-cookie")).toBeNull();
    }
  });

  it("ninguna ruta llega a consultar la base de datos", async () => {
    disable();

    for (const [, handler, options] of ROUTES) {
      await call(handler, { ...options, token: account.token });
    }

    expect(queries).toEqual([]);
  });

  it("no se puede crear una cuenta ni abrir sesión", async () => {
    disable();

    await call(register, {
      method: "POST",
      body: { email: "intruso@ejemplo.com", password: "contraseña-larga-1" },
    });

    vi.unstubAllEnvs();
    const users = await db.query<{ email: string }>("select email from users");

    expect(users.map((user) => user.email)).toEqual(["antes@ejemplo.com"]);
  });

  it("el analizador público sigue respondiendo", async () => {
    disable();

    const response = await analyze(
      new NextRequest("http://localhost/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: "http://127.0.0.1" }),
      }),
    );

    // Llega al motor y este rechaza el destino interno: la ruta funciona.
    expect(response.status).toBe(400);
    expect((await response.json()).error).toMatch(/no se puede analizar/);
  });
});

describe("cuentas activadas explícitamente", () => {
  it("con ACCOUNTS_ENABLED=true las rutas vuelven a funcionar", async () => {
    vi.stubEnv("ACCOUNTS_ENABLED", "true");

    expect((await call(me, { token: account.token })).status).toBe(200);
    expect((await call(me)).status).toBe(401);
  });
});
