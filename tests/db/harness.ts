import fs from "node:fs";
import path from "node:path";
import { PGlite } from "@electric-sql/pglite";

/**
 * Arnés de pruebas de la base de datos.
 *
 * Aplica las MISMAS migraciones de `supabase/migrations/` sobre un
 * PostgreSQL embebido (PGlite), con un esquema `auth` mínimo que imita lo
 * que Supabase aporta: la tabla `auth.users`, la función `auth.uid()` y los
 * roles `anon`, `authenticated` y `service_role`.
 *
 * Sirve para probar de verdad RLS, permisos, restricciones y funciones,
 * porque todo eso lo ejecuta PostgreSQL. NO prueba Supabase Auth ni la API
 * de Supabase: para eso hace falta Supabase local (Docker).
 *
 * PGlite solo se usa aquí. No forma parte de la aplicación.
 */

const MIGRATIONS = path.join(__dirname, "..", "..", "supabase", "migrations");

/** Lo que Supabase ya trae y las migraciones dan por hecho. */
const SUPABASE_SHIM = `
  create role anon nologin;
  create role authenticated nologin;
  create role service_role nologin bypassrls;

  create schema auth;
  create table auth.users (
    id uuid primary key default gen_random_uuid(),
    email text unique,
    email_confirmed_at timestamptz,
    created_at timestamptz not null default now()
  );
  create function auth.uid() returns uuid language sql stable as $$
    select nullif(
      nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub', ''
    )::uuid
  $$;

  grant usage on schema public to anon, authenticated, service_role;
  grant usage on schema auth to anon, authenticated, service_role;
  grant execute on function auth.uid() to anon, authenticated, service_role;
`;

export type Sql = <T = Record<string, unknown>>(
  text: string,
  params?: unknown[],
) => Promise<T[]>;

export type TestDb = {
  /** Consulta como superusuario (prepara datos; no pasa por RLS). */
  sql: Sql;
  /** Ejecuta consultas con la identidad de un usuario autenticado (RLS activo). */
  asUser: <T>(userId: string, work: (sql: Sql) => Promise<T>) => Promise<T>;
  /** Ejecuta consultas como visitante sin sesión. */
  asAnon: <T>(work: (sql: Sql) => Promise<T>) => Promise<T>;
  /** Ejecuta consultas como el servidor (clave secreta). */
  asService: <T>(work: (sql: Sql) => Promise<T>) => Promise<T>;
  createUser: (email: string) => Promise<string>;
  close: () => Promise<void>;
};

export function migrationFiles(): string[] {
  return fs
    .readdirSync(MIGRATIONS)
    .filter((file) => file.endsWith(".sql"))
    .sort()
    .map((file) => path.join(MIGRATIONS, file));
}

export async function createTestDb(): Promise<TestDb> {
  const db = new PGlite();

  await db.exec(SUPABASE_SHIM);
  for (const file of migrationFiles()) {
    await db.exec(fs.readFileSync(file, "utf8"));
  }

  const sql: Sql = async (text, params = []) =>
    (await db.query(text, params)).rows as never;

  /** Igual que hace PostgREST: cambia de rol y fija los datos del JWT. */
  const withRole = async <T>(
    role: string,
    claims: Record<string, string>,
    work: (sql: Sql) => Promise<T>,
  ): Promise<T> =>
    db.transaction(async (tx) => {
      await tx.query("select set_config('request.jwt.claims', $1, true)", [
        JSON.stringify(claims),
      ]);
      await tx.exec(`set local role ${role}`);

      return work(async (text, params = []) =>
        (await tx.query(text, params)).rows as never,
      );
    }) as Promise<T>;

  return {
    sql,
    asUser: (userId, work) =>
      withRole("authenticated", { sub: userId, role: "authenticated" }, work),
    asAnon: (work) => withRole("anon", { role: "anon" }, work),
    asService: (work) => withRole("service_role", { role: "service_role" }, work),
    createUser: async (email) => {
      const [row] = await sql<{ id: string }>(
        "insert into auth.users (email, email_confirmed_at) values ($1, now()) returning id",
        [email],
      );
      return row.id;
    },
    close: () => db.close(),
  };
}

/** ¿La promesa falla con un error de permisos o de RLS de PostgreSQL? */
export async function denied(work: Promise<unknown>): Promise<string | null> {
  try {
    await work;
    return null;
  } catch (error) {
    return (error as { code?: string }).code ?? String(error);
  }
}
