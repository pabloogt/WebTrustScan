import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, denied, type Sql, type TestDb } from "./harness";

/**
 * Aislamiento entre usuarios aplicado por PostgreSQL (RLS + permisos).
 * Cada consulta «como usuario» se ejecuta con el rol `authenticated` y el
 * identificador del usuario en el JWT, igual que las hace Supabase.
 */

const LIMITS = JSON.stringify({ free: 5, pro: 100 });
const REPORT = JSON.stringify({
  engineVersion: "2.0.0",
  web: { score: 80, grade: "B", coverage: 100 },
  dnsEmail: { score: 59 },
  findings: [{ status: "fail" }, { status: "pass" }],
});
const DENIED = "42501"; // insufficient_privilege

let db: TestDb;
let alice: string;
let bob: string;
let wsAlice: string;
let wsBob: string;
let auditAlice: string;

async function storeAudit(user: string, hostname: string): Promise<string> {
  const [{ r }] = await db.sql<{ r: { usage_id: string } }>(
    "select public.reserve_audit($1, gen_random_uuid(), $2::jsonb, 5) as r",
    [user, LIMITS],
  );
  const [{ id }] = await db.sql<{ id: string }>(
    "select public.complete_audit($1, $2, $3::jsonb, 10) as id",
    [r.usage_id, hostname, REPORT],
  );
  return id;
}

const workspaceOf = async (user: string) =>
  (await db.sql<{ id: string }>("select id from public.workspaces where owner_id = $1", [user]))[0].id;

beforeAll(async () => {
  db = await createTestDb();
  alice = await db.createUser("alice@a.test");
  bob = await db.createUser("bob@b.test");
  wsAlice = await workspaceOf(alice);
  wsBob = await workspaceOf(bob);
  auditAlice = await storeAudit(alice, "empresa-a.test");
  await storeAudit(bob, "empresa-b.test");
});
afterAll(() => db.close());

const asAlice = <T>(work: (sql: Sql) => Promise<T>) => db.asUser(alice, work);
const asBob = <T>(work: (sql: Sql) => Promise<T>) => db.asUser(bob, work);

describe("RLS · cada usuario ve solo lo suyo", () => {
  it("todas las tablas tienen RLS activado", async () => {
    const tables = await db.sql<{ relname: string; relrowsecurity: boolean }>(
      `select c.relname, c.relrowsecurity from pg_class c
         join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind = 'r' order by 1`,
    );

    expect(tables.length).toBe(11);
    expect(tables.filter((table) => !table.relrowsecurity)).toEqual([]);
  });

  it("A ve su análisis, su espacio, su suscripción y su consumo", async () => {
    await asAlice(async (sql) => {
      expect((await sql("select hostname from public.audits")).map((r) => r.hostname)).toEqual(["empresa-a.test"]);
      expect((await sql("select id from public.workspaces")).map((r) => r.id)).toEqual([wsAlice]);
      expect(await sql("select plan from public.subscriptions")).toEqual([{ plan: "free" }]);
      expect(await sql("select count(*)::int as n from public.usage_events")).toEqual([{ n: 1 }]);
      expect((await sql("select id from public.profiles")).map((r) => r.id)).toEqual([alice]);
    });
  });

  it("B no puede consultar el análisis de A, ni conociendo su identificador", async () => {
    await asBob(async (sql) => {
      expect(await sql("select id from public.audits where id = $1", [auditAlice])).toEqual([]);
      expect(await sql("select id from public.audits where workspace_id = $1", [wsAlice])).toEqual([]);
      expect(await sql("select id from public.audits where hostname = 'empresa-a.test'")).toEqual([]);
      // B solo ve el suyo.
      expect((await sql("select hostname from public.audits")).map((r) => r.hostname)).toEqual(["empresa-b.test"]);
    });
  });

  it("B no puede modificar el análisis de A", async () => {
    expect(
      await denied(asBob((sql) => sql("update public.audits set hostname = 'x.test' where id = $1", [auditAlice]))),
    ).toBe(DENIED);
    expect(
      await denied(asBob((sql) => sql("update public.audits set report = '{}'::jsonb where id = $1", [auditAlice]))),
    ).toBe(DENIED);

    // Borrar no da error, pero no afecta a ninguna fila ajena.
    const deleted = await asBob((sql) =>
      sql("delete from public.audits where id = $1 returning id", [auditAlice]),
    );
    expect(deleted).toEqual([]);

    const [row] = await db.sql("select hostname from public.audits where id = $1", [auditAlice]);
    expect(row).toEqual({ hostname: "empresa-a.test" });
  });

  it("B no puede acceder al espacio de trabajo de A ni a nada que cuelgue de él", async () => {
    await asBob(async (sql) => {
      expect(await sql("select id from public.workspaces where id = $1", [wsAlice])).toEqual([]);
      expect(await sql("select user_id from public.workspace_members where workspace_id = $1", [wsAlice])).toEqual([]);
      expect(await sql("select plan from public.subscriptions where workspace_id = $1", [wsAlice])).toEqual([]);
      expect(await sql("select id from public.usage_events where workspace_id = $1", [wsAlice])).toEqual([]);
      expect(await sql("select id from public.profiles where id = $1", [alice])).toEqual([]);
    });
  });

  it("B no puede añadirse al espacio de A ni crear espacios o pertenencias", async () => {
    expect(
      await denied(
        asBob((sql) =>
          sql("insert into public.workspace_members (workspace_id, user_id, role) values ($1, $2, 'owner')", [wsAlice, bob]),
        ),
      ),
    ).toBe(DENIED);
    expect(
      await denied(asBob((sql) => sql("update public.workspace_members set workspace_id = $1 where user_id = $2", [wsAlice, bob]))),
    ).toBe(DENIED);
    expect(
      await denied(asBob((sql) => sql("insert into public.workspaces (owner_id, name) values ($1, 'otro')", [bob]))),
    ).toBe(DENIED);
    // Renombrar el espacio ajeno no afecta a ninguna fila.
    expect(
      await asBob((sql) => sql("update public.workspaces set name = 'robado' where id = $1 returning id", [wsAlice])),
    ).toEqual([]);
    // Y no puede traspasarse la propiedad: esa columna no es editable.
    expect(
      await denied(asBob((sql) => sql("update public.workspaces set owner_id = $1 where id = $2", [alice, wsBob]))),
    ).toBe(DENIED);
  });
});

describe("RLS · plan, rol y consumo no son modificables por el usuario", () => {
  it("un usuario no puede cambiar su plan ni su suscripción", async () => {
    for (const statement of [
      "update public.subscriptions set plan = 'pro'",
      "update public.subscriptions set status = 'active', current_period_end = now() + interval '10 years'",
      "update public.subscriptions set provider_customer_id = 'cus_falso'",
      "delete from public.subscriptions",
      `insert into public.subscriptions (workspace_id, plan) values ('${wsBob}', 'pro')`,
    ]) {
      expect(await denied(asBob((sql) => sql(statement))), statement).toBe(DENIED);
    }

    expect(await db.sql("select plan from public.subscriptions where workspace_id = $1", [wsBob])).toEqual([
      { plan: "free" },
    ]);
  });

  it("un usuario no puede concederse el rol de administrador ni ver quién lo es", async () => {
    await db.sql("insert into public.app_admins (user_id) values ($1)", [alice]);

    expect(await denied(asBob((sql) => sql("insert into public.app_admins (user_id) values ($1)", [bob])))).toBe(DENIED);
    expect(await denied(asBob((sql) => sql("select user_id from public.app_admins")))).toBe(DENIED);
    expect(await denied(asAlice((sql) => sql("delete from public.app_admins")))).toBe(DENIED);
    // Tampoco puede cambiar su rol dentro del espacio.
    expect(await denied(asBob((sql) => sql("update public.workspace_members set role = 'owner'")))).toBe(DENIED);
  });

  it("un usuario no puede alterar el registro de consumo", async () => {
    for (const statement of [
      "delete from public.usage_events",
      "update public.usage_events set status = 'released'",
      "update public.usage_events set period_start = '2000-01-01'",
      `insert into public.usage_events (workspace_id, request_id, period_start, status) values ('${wsBob}', gen_random_uuid(), now(), 'released')`,
      "delete from public.usage_carryover",
      "select * from public.usage_carryover",
      "select * from public.usage_carryover_events",
      "delete from public.usage_carryover_events",
      `insert into public.usage_carryover_events (email_hash, used_at) values ('${"a".repeat(64)}', now())`,
    ]) {
      expect(await denied(asBob((sql) => sql(statement))), statement).toBe(DENIED);
    }
  });

  it("un usuario no puede ejecutar las funciones de consumo del servidor", async () => {
    for (const call of [
      `select public.reserve_audit('${bob}', gen_random_uuid(), '{"free": 999999}'::jsonb, 99)`,
      `select public.complete_audit(gen_random_uuid(), 'x.test', '{}'::jsonb, 10)`,
      `select public.finish_audit(gen_random_uuid(), 'released')`,
      `select public.workspace_usage('${alice}')`,
      `select public.record_account_deletion('${alice}', repeat('a', 64))`,
      `select public.purge_security_events()`,
      // Funciones de la ventana móvil de 7 días.
      `select public.reserve_audit_rolling('${bob}', gen_random_uuid(), '{"free": 999999}'::jsonb, 7, 99)`,
      `select public.workspace_usage_rolling('${alice}', '{"free": 5, "pro": 25}'::jsonb, 7)`,
      `select public.record_account_deletion_rolling('${alice}', repeat('a', 64), 7)`,
      `select public.rolling_usage(gen_random_uuid(), null, now(), interval '7 days', 5)`,
      `select public.quota_window(7)`,
    ]) {
      expect(await denied(asBob((sql) => sql(call))), call).toBe(DENIED);
    }
  });

  it("un usuario no puede insertar análisis por su cuenta", async () => {
    expect(
      await denied(
        asBob((sql) =>
          sql(
            `insert into public.audits (workspace_id, hostname, engine_version, web_coverage, open_findings, report)
             values ($1, 'x.test', '2.0.0', 100, 0, '{}'::jsonb)`,
            [wsBob],
          ),
        ),
      ),
    ).toBe(DENIED);
  });

  it("del perfil solo es editable el nombre visible, y solo el propio", async () => {
    await asBob((sql) => sql("update public.profiles set display_name = 'Bob'"));
    expect(await db.sql("select display_name from public.profiles where id = $1", [bob])).toEqual([{ display_name: "Bob" }]);
    expect(await db.sql("select display_name from public.profiles where id = $1", [alice])).toEqual([{ display_name: null }]);

    expect(await denied(asBob((sql) => sql("update public.profiles set id = $1", [alice])))).toBe(DENIED);
    expect(await denied(asBob((sql) => sql("update public.profiles set created_at = now()")))).toBe(DENIED);
    expect(await denied(asBob((sql) => sql("delete from public.profiles")))).toBe(DENIED);
    expect(
      await denied(asBob((sql) => sql("update public.profiles set display_name = $1", ["x".repeat(81)]))),
    ).toBe("23514"); // restricción de longitud
  });

  it("los registros internos no son accesibles para ningún usuario", async () => {
    for (const table of ["security_events", "billing_webhook_events"]) {
      expect(await denied(asBob((sql) => sql(`select * from public.${table}`)))).toBe(DENIED);
      expect(await denied(asBob((sql) => sql(`delete from public.${table}`)))).toBe(DENIED);
    }
  });
});

describe("RLS · sin sesión y servidor", () => {
  it("un visitante sin sesión no puede leer ni escribir ninguna tabla", async () => {
    for (const table of [
      "profiles", "workspaces", "workspace_members", "subscriptions", "audits",
      "usage_events", "usage_carryover", "usage_carryover_events", "app_admins", "security_events",
      "billing_webhook_events",
    ]) {
      expect(await denied(db.asAnon((sql) => sql(`select * from public.${table}`))), table).toBe(DENIED);
    }
    expect(
      await denied(db.asAnon((sql) => sql(`select public.reserve_audit('${bob}', gen_random_uuid(), '{"free": 5}'::jsonb, 2)`))),
    ).toBe(DENIED);
  });

  it("un usuario autenticado sin identificador en el JWT no ve nada", async () => {
    // Token manipulado sin «sub»: auth.uid() es null y ninguna política casa.
    const rows = await db.asUser("", (sql) => sql("select id from public.audits")).catch(() => "error");
    expect(rows === "error" || (Array.isArray(rows) && rows.length === 0)).toBe(true);
  });

  it("el servidor (service_role) sí puede operar", async () => {
    const usage = await db.asService((sql) =>
      sql<{ u: { outcome: string; plan: string; used: number } }>("select public.workspace_usage($1) as u", [alice]),
    );
    expect(usage[0].u).toMatchObject({ outcome: "ok", plan: "free", used: 1 });
  });
});

describe("integridad y borrado", () => {
  it("el dueño puede borrar un análisis de su historial y eso NO devuelve cuota", async () => {
    const extra = await storeAudit(alice, "borrable.test");
    const before = (await db.sql<{ u: { used: number } }>("select public.workspace_usage($1) as u", [alice]))[0].u.used;

    const deleted = await asAlice((sql) => sql("delete from public.audits where id = $1 returning id", [extra]));
    expect(deleted).toEqual([{ id: extra }]);

    const after = (await db.sql<{ u: { used: number } }>("select public.workspace_usage($1) as u", [alice]))[0].u.used;
    expect(after).toBe(before);
    // El evento de consumo sigue ahí, ya sin análisis asociado.
    expect(
      await db.sql("select count(*)::int as n from public.usage_events where workspace_id = $1 and audit_id is null", [wsAlice]),
    ).toEqual([{ n: 1 }]);
  });

  it("no se puede tener dos espacios personales ni dos consumos para la misma petición", async () => {
    expect(
      await denied(db.sql("insert into public.workspaces (owner_id, name, is_personal) values ($1, 'otro', true)", [alice])),
    ).toBe("23505");

    const request = "11111111-1111-4111-8111-111111111111";
    await db.sql("select public.reserve_audit($1, $2, $3::jsonb, 5)", [bob, request, LIMITS]);
    expect(
      await denied(
        db.sql(
          "insert into public.usage_events (workspace_id, request_id, period_start, status) values ($1, $2, now(), 'reserved')",
          [wsBob, request],
        ),
      ),
    ).toBe("23505");
  });

  it("los informes tienen un tamaño máximo y deben ser un objeto JSON", async () => {
    const [{ r }] = await db.sql<{ r: { usage_id: string } }>(
      "select public.reserve_audit($1, gen_random_uuid(), $2::jsonb, 5) as r",
      [bob, LIMITS],
    );
    const huge = JSON.stringify({ ...JSON.parse(REPORT), relleno: "x".repeat(410_000) });

    expect(await denied(db.sql("select public.complete_audit($1, 'x.test', $2::jsonb, 10)", [r.usage_id, huge]))).toBe("23514");
    expect(
      await denied(
        db.sql(
          `insert into public.audits (workspace_id, hostname, engine_version, web_coverage, open_findings, report)
           values ($1, 'x.test', '2.0.0', 100, 0, '[]'::jsonb)`,
          [wsBob],
        ),
      ),
    ).toBe("23514");
  });

  it("al borrar el usuario desaparecen su perfil, espacio, análisis y consumo", async () => {
    const carol = await db.createUser("carol@c.test");
    const wsCarol = await workspaceOf(carol);
    await storeAudit(carol, "carol.test");

    await db.sql("delete from auth.users where id = $1", [carol]);

    for (const [table, column] of [
      ["profiles", "id"], ["workspaces", "owner_id"], ["workspace_members", "user_id"],
    ] as const) {
      expect(await db.sql(`select 1 from public.${table} where ${column} = $1`, [carol]), table).toEqual([]);
    }
    for (const table of ["subscriptions", "audits", "usage_events"]) {
      expect(await db.sql(`select 1 from public.${table} where workspace_id = $1`, [wsCarol]), table).toEqual([]);
    }
    // Los datos de los demás siguen intactos.
    expect(await db.sql("select 1 from public.audits where id = $1", [auditAlice])).toHaveLength(1);
  });
});
