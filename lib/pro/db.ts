import { MIGRATIONS } from "./schema";

/**
 * Acceso a datos de WebTrustScan Pro.
 *
 * Se usa SQL parametrizado sobre PostgreSQL, sin ORM, con dos adaptadores:
 * - `pg` cuando existe DATABASE_URL (producción: cualquier PostgreSQL).
 * - PGlite (PostgreSQL embebido) para desarrollo local y tests, de modo que
 *   el proyecto funciona sin contratar ningún servicio.
 */

export type Row = Record<string, unknown>;

export interface Queryable {
  query<T extends Row = Row>(sql: string, params?: unknown[]): Promise<T[]>;
}

export interface Db extends Queryable {
  /** Ejecuta `work` dentro de una transacción (se revierte si lanza). */
  transaction<T>(work: (tx: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

async function migrate(db: Db): Promise<void> {
  await db.query(
    "create table if not exists schema_migrations (id text primary key, applied_at timestamptz not null default now())",
  );
  const applied = new Set(
    (await db.query<{ id: string }>("select id from schema_migrations")).map(
      (row) => row.id,
    ),
  );

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.id)) continue;

    await db.transaction(async (tx) => {
      for (const statement of migration.statements) await tx.query(statement);
      await tx.query("insert into schema_migrations (id) values ($1)", [
        migration.id,
      ]);
    });
  }
}

/** PostgreSQL embebido. Sin `dataDir` vive solo en memoria (tests). */
export async function createPgliteDb(dataDir?: string): Promise<Db> {
  const { PGlite } = await import("@electric-sql/pglite");

  if (dataDir) {
    // PGlite no crea los directorios intermedios.
    const [{ mkdirSync }, { dirname }] = await Promise.all([
      import("node:fs"),
      import("node:path"),
    ]);
    mkdirSync(dirname(dataDir), { recursive: true });
  }

  const client = new PGlite(dataDir);

  const db: Db = {
    async query<T extends Row>(sql: string, params: unknown[] = []) {
      return (await client.query<T>(sql, params)).rows;
    },
    transaction: (work) =>
      client.transaction((tx) =>
        work({
          async query<T extends Row>(sql: string, params: unknown[] = []) {
            return (await tx.query<T>(sql, params)).rows;
          },
        }),
      ),
    close: () => client.close(),
  };

  await migrate(db);
  return db;
}

export async function createPostgresDb(connectionString: string): Promise<Db> {
  const { Pool } = await import("pg");
  // Pocas conexiones: en serverless cada instancia abre su propio pool.
  const pool = new Pool({ connectionString, max: 3 });

  const db: Db = {
    async query<T extends Row>(sql: string, params: unknown[] = []) {
      return (await pool.query(sql, params)).rows as T[];
    },
    async transaction(work) {
      const client = await pool.connect();

      try {
        await client.query("begin");
        const result = await work({
          async query<T extends Row>(sql: string, params: unknown[] = []) {
            return (await client.query(sql, params)).rows as T[];
          },
        });
        await client.query("commit");
        return result;
      } catch (error) {
        await client.query("rollback");
        throw error;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };

  await migrate(db);
  return db;
}

let shared: Promise<Db> | null = null;

/** true si las funciones Pro pueden usarse en este entorno. */
export function isProConfigured(env = process.env): boolean {
  return Boolean(env.DATABASE_URL) || env.NODE_ENV !== "production";
}

/**
 * Base de datos de la aplicación. En producción exige DATABASE_URL; en
 * desarrollo usa PGlite en `.data/pglite` para no depender de nada externo.
 */
export function getDb(): Promise<Db> {
  if (!shared) {
    const url = process.env.DATABASE_URL;

    if (url) {
      shared = createPostgresDb(url);
    } else if (process.env.NODE_ENV !== "production") {
      shared = createPgliteDb(
        process.env.NODE_ENV === "test" ? undefined : ".data/pglite",
      );
    } else {
      throw new Error("DATABASE_URL no está configurada.");
    }

    shared.catch(() => {
      shared = null;
    });
  }

  return shared;
}

/** Solo para tests: sustituye la base de datos compartida. */
export function setDbForTests(db: Db | null): void {
  shared = db ? Promise.resolve(db) : null;
}

/** ¿El error es una violación de restricción UNIQUE? */
export function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === "23505";
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Evita pasar a PostgreSQL identificadores que no son UUID. */
export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value);
}
