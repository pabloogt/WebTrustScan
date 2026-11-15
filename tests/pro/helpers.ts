import { NextRequest } from "next/server";
import {
  createSession,
  getSession,
  registerUser,
  type SessionContext,
} from "@/lib/pro/auth";
import { createPgliteDb, type Db } from "@/lib/pro/db";
import type { Plan, Role } from "@/lib/pro/plans";

export const ORIGIN = "http://localhost";

/** PostgreSQL embebido en memoria, con las migraciones aplicadas. */
export const createTestDb = (): Promise<Db> => createPgliteDb();

export type Account = { session: SessionContext; token: string; password: string };

export async function createAccount(
  db: Db,
  email: string,
  options: { plan?: Plan; role?: Role } = {},
): Promise<Account> {
  const password = "contraseña-de-prueba-1";
  const { userId, organizationId } = await registerUser(db, { email, password });

  if (options.plan) {
    await db.query("update organizations set plan = $1 where id = $2", [
      options.plan,
      organizationId,
    ]);
  }
  if (options.role) {
    await db.query("update memberships set role = $1 where user_id = $2", [
      options.role,
      userId,
    ]);
  }

  const token = await createSession(db, userId);
  const session = await getSession(db, token);

  if (!session) throw new Error("No se pudo crear la sesión de prueba");

  return { session, token, password };
}

// `Promise<never>` es asignable a los parámetros de cualquier ruta.
type Handler = (
  request: NextRequest,
  context: { params: Promise<never> },
) => Promise<Response>;

/** Invoca un handler de ruta como lo haría el navegador. */
export async function call(
  handler: Handler,
  options: {
    method?: string;
    path?: string;
    body?: unknown;
    token?: string;
    origin?: string | null;
    params?: Record<string, string>;
    headers?: Record<string, string>;
  } = {},
): Promise<{ status: number; data: Record<string, unknown>; response: Response }> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { host: "localhost", ...options.headers };

  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token) headers.cookie = `wts_session=${options.token}`;
  if (method !== "GET" && options.origin !== null) {
    headers.origin = options.origin ?? ORIGIN;
  }

  const request = new NextRequest(`${ORIGIN}${options.path ?? "/api/test"}`, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const response = await handler(request, {
    params: Promise.resolve(options.params ?? {}) as Promise<never>,
  });

  return {
    status: response.status,
    data: (await response.json().catch(() => ({}))) as Record<string, unknown>,
    response,
  };
}
