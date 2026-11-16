import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, denied, type TestDb } from "./harness";

/**
 * Consumo de análisis: reserva atómica, idempotencia, periodos y planes.
 * Se prueban las funciones SQL reales que ejecutará Supabase.
 */

const LIMITS = { free: 5, pro: 100 };
const REPORT = JSON.stringify({
  engineVersion: "2.0.0",
  web: { score: 61, grade: "C", coverage: 100 },
  dnsEmail: { score: null },
  findings: [],
});

type Reservation = {
  outcome: string;
  usage_id?: string;
  used?: number;
  limit?: number;
  plan?: string;
  status?: string;
  audit_id?: string | null;
  period_start?: string;
  period_end?: string;
};

let db: TestDb;
let counter = 0;

beforeAll(async () => {
  db = await createTestDb();
});
afterAll(() => db.close());

const newUser = () => db.createUser(`u${(counter += 1)}@cuota.test`);

async function reserve(
  user: string,
  options: { request?: string; now?: string; maxConcurrent?: number; emailHash?: string; limits?: object } = {},
): Promise<Reservation> {
  const [{ r }] = await db.sql<{ r: Reservation }>(
    "select public.reserve_audit($1, $2, $3::jsonb, $4, $5, $6::timestamptz) as r",
    [
      user,
      options.request ?? randomUUID(),
      JSON.stringify(options.limits ?? LIMITS),
      options.maxConcurrent ?? 50,
      options.emailHash ?? null,
      options.now ?? new Date().toISOString(),
    ],
  );
  return r;
}

const complete = async (usageId: string, historyLimit = 10, now = new Date().toISOString()) =>
  (await db.sql<{ id: string }>(
    "select public.complete_audit($1, 'ejemplo.test', $2::jsonb, $3, $4::timestamptz) as id",
    [usageId, REPORT, historyLimit, now],
  ))[0].id;

const finish = (usageId: string, status: string) =>
  db.sql("select public.finish_audit($1, $2)", [usageId, status]);

const usage = async (user: string, now = new Date().toISOString(), emailHash: string | null = null) =>
  (await db.sql<{ u: { used: number; plan: string; period_start: string; period_end: string } }>(
    "select public.workspace_usage($1, $2, $3::timestamptz) as u",
    [user, emailHash, now],
  ))[0].u;

const setPlan = (user: string, fields: string) =>
  db.sql(
    `update public.subscriptions set ${fields}
      where workspace_id = (select id from public.workspaces where owner_id = $1)`,
    [user],
  );

describe("cuota Free", () => {
  it("un usuario nuevo empieza con cero análisis consumidos", async () => {
    const user = await newUser();

    expect(await usage(user)).toMatchObject({ used: 0, plan: "free" });
  });

  it("permite exactamente 5 y rechaza el sexto", async () => {
    const user = await newUser();
    const outcomes: string[] = [];

    for (let i = 0; i < 7; i += 1) {
      const result = await reserve(user);
      outcomes.push(result.outcome);
      if (result.usage_id) await complete(result.usage_id);
    }

    expect(outcomes).toEqual([
      "reserved", "reserved", "reserved", "reserved", "reserved",
      "quota_exceeded", "quota_exceeded",
    ]);
    expect(await usage(user)).toMatchObject({ used: 5 });

    const rejected = await reserve(user);
    expect(rejected).toMatchObject({ outcome: "quota_exceeded", used: 5, limit: 5, plan: "free" });
    expect(rejected.period_end).toBeTruthy();
  });

  it("peticiones simultáneas no superan el límite", async () => {
    const user = await newUser();
    const results = await Promise.all(Array.from({ length: 20 }, () => reserve(user)));

    expect(results.filter((r) => r.outcome === "reserved")).toHaveLength(5);
    expect(results.filter((r) => r.outcome === "quota_exceeded")).toHaveLength(15);
    expect(await usage(user)).toMatchObject({ used: 5 });
  });

  it("repetir la misma petición no consume dos veces", async () => {
    const user = await newUser();
    const request = randomUUID();

    const first = await reserve(user, { request });
    const retry = await reserve(user, { request });
    expect(first.outcome).toBe("reserved");
    expect(retry).toMatchObject({ outcome: "duplicate", usage_id: first.usage_id, status: "reserved" });

    const audit = await complete(first.usage_id as string);
    // El reintento tras terminar devuelve el análisis ya hecho.
    expect(await reserve(user, { request })).toMatchObject({
      outcome: "duplicate", status: "completed", audit_id: audit,
    });
    expect(await usage(user)).toMatchObject({ used: 1 });

    // Diez reintentos simultáneos del mismo identificador: un solo consumo.
    const other = randomUUID();
    const burst = await Promise.all(Array.from({ length: 10 }, () => reserve(user, { request: other })));
    expect(burst.filter((r) => r.outcome === "reserved")).toHaveLength(1);
    expect(burst.filter((r) => r.outcome === "duplicate")).toHaveLength(9);
    expect(await usage(user)).toMatchObject({ used: 2 });
  });

  it("un fallo del destino consume; un fallo interno se libera", async () => {
    const user = await newUser();
    const failed = await reserve(user);
    const internal = await reserve(user);

    await finish(failed.usage_id as string, "failed");
    await finish(internal.usage_id as string, "released");

    expect(await usage(user)).toMatchObject({ used: 1 });
    // Una reserva ya cerrada no se puede reabrir ni liberar después.
    await finish(failed.usage_id as string, "released");
    expect(await usage(user)).toMatchObject({ used: 1 });
    expect(await denied(finish(internal.usage_id as string, "completed"))).not.toBeNull();
  });

  it("reintentar tras un error no permite análisis ilimitados", async () => {
    const user = await newUser();

    for (let i = 0; i < 5; i += 1) {
      await finish((await reserve(user)).usage_id as string, "failed");
    }

    expect((await reserve(user)).outcome).toBe("quota_exceeded");
  });

  it("no se puede cerrar dos veces la misma reserva", async () => {
    const user = await newUser();
    const { usage_id } = await reserve(user);

    await complete(usage_id as string);
    expect(await denied(complete(usage_id as string))).not.toBeNull();
    expect(
      await db.sql("select count(*)::int as n from public.audits a join public.workspaces w on w.id = a.workspace_id where w.owner_id = $1", [user]),
    ).toEqual([{ n: 1 }]);
  });

  it("limita los análisis simultáneos de una cuenta", async () => {
    const user = await newUser();
    const now = "2026-11-15T12:00:00Z";

    expect((await reserve(user, { now, maxConcurrent: 2 })).outcome).toBe("reserved");
    expect((await reserve(user, { now, maxConcurrent: 2 })).outcome).toBe("reserved");
    expect((await reserve(user, { now, maxConcurrent: 2 })).outcome).toBe("too_many_concurrent");
    // Pasado el tiempo máximo de un análisis, las reservas colgadas ya no
    // bloquean... pero siguen contando como consumo.
    const later = await reserve(user, { now: "2026-11-15T12:03:00Z", maxConcurrent: 2 });
    expect(later).toMatchObject({ outcome: "reserved", used: 3 });
  });

  it("exige un límite definido para el plan", async () => {
    const user = await newUser();

    expect(await denied(reserve(user, { limits: { pro: 100 } }))).not.toBeNull();
    expect(await denied(reserve(user, { limits: { free: -1 } }))).not.toBeNull();
    expect(await reserve("00000000-0000-4000-8000-000000000000")).toEqual({ outcome: "no_workspace" });
  });
});

describe("periodos", () => {
  it("Free usa el mes natural en UTC y se reinicia al cambiar de mes", async () => {
    const user = await newUser();
    const lastSecond = "2026-01-31T23:59:59Z";
    const firstSecond = "2026-02-01T00:00:00Z";

    for (let i = 0; i < 5; i += 1) await reserve(user, { now: lastSecond });

    expect((await reserve(user, { now: lastSecond })).outcome).toBe("quota_exceeded");
    expect(await usage(user, lastSecond)).toMatchObject({
      used: 5,
      period_start: "2026-01-01T00:00:00+00:00",
      period_end: "2026-02-01T00:00:00+00:00",
    });

    // Un segundo después empieza febrero: cuota nueva.
    expect(await reserve(user, { now: firstSecond })).toMatchObject({ outcome: "reserved", used: 1 });
    expect(await usage(user, firstSecond)).toMatchObject({ used: 1, period_end: "2026-03-01T00:00:00+00:00" });
  });

  it("el periodo no depende de la zona horaria: 31 de enero 23:30 en Madrid es enero en UTC", async () => {
    const user = await newUser();
    // 00:30 del 1 de febrero en Madrid (UTC+1) sigue siendo 31 de enero en UTC.
    const reservation = await reserve(user, { now: "2026-02-01T00:30:00+01:00" });

    expect(reservation.period_start).toBe("2026-01-01T00:00:00+00:00");
  });
});

describe("plan Pro", () => {
  it("un usuario Pro tiene el límite superior", async () => {
    const user = await newUser();
    await setPlan(user, "plan = 'pro', provider = 'manual'");

    for (let i = 0; i < 5; i += 1) await reserve(user);

    expect(await reserve(user)).toMatchObject({ outcome: "reserved", plan: "pro", used: 6, limit: 100 });
    expect(await usage(user)).toMatchObject({ plan: "pro", used: 6 });
  });

  it("Pro deja de aplicarse si la suscripción no está activa", async () => {
    const user = await newUser();
    await setPlan(user, "plan = 'pro', status = 'past_due'");

    expect(await usage(user)).toMatchObject({ plan: "free" });
    for (let i = 0; i < 5; i += 1) await reserve(user);
    expect((await reserve(user)).outcome).toBe("quota_exceeded");

    await setPlan(user, "status = 'canceled'");
    expect(await usage(user)).toMatchObject({ plan: "free" });
    await setPlan(user, "status = 'trialing'");
    expect(await usage(user)).toMatchObject({ plan: "pro" });
  });

  it("con un ciclo de facturación vigente, el periodo es ese ciclo", async () => {
    const user = await newUser();
    await setPlan(
      user,
      "plan = 'pro', current_period_start = '2026-03-10T00:00:00Z', current_period_end = '2026-04-10T00:00:00Z'",
    );

    const inside = await reserve(user, { now: "2026-03-20T00:00:00Z" });
    expect(inside).toMatchObject({
      period_start: "2026-03-10T00:00:00+00:00",
      period_end: "2026-04-10T00:00:00+00:00",
    });
    // 5 de abril sigue en el mismo ciclo aunque haya cambiado el mes natural.
    expect(await reserve(user, { now: "2026-04-05T00:00:00Z" })).toMatchObject({ used: 2 });
    // Fuera del ciclo (no renovado) se vuelve al mes natural.
    expect((await reserve(user, { now: "2026-04-20T00:00:00Z" })).period_start).toBe("2026-04-01T00:00:00+00:00");
  });

  it("la base de datos no admite planes ni estados inventados", async () => {
    const user = await newUser();

    expect(await denied(setPlan(user, "plan = 'enterprise'"))).toBe("23514");
    expect(await denied(setPlan(user, "status = 'gratis-para-siempre'"))).toBe("23514");
    expect(
      await denied(setPlan(user, "current_period_start = '2026-02-01', current_period_end = '2026-01-01'")),
    ).toBe("23514");
  });
});

describe("historial", () => {
  it("conserva los N análisis más recientes sin devolver cuota", async () => {
    const user = await newUser();
    await setPlan(user, "plan = 'pro'");
    const ids: string[] = [];

    for (let i = 0; i < 6; i += 1) {
      const now = `2026-05-0${i + 1}T10:00:00Z`;
      const { usage_id } = await reserve(user, { now });
      ids.push(await complete(usage_id as string, 4, now));
    }

    const kept = await db.sql<{ id: string }>(
      "select a.id from public.audits a join public.workspaces w on w.id = a.workspace_id where w.owner_id = $1 order by a.created_at desc",
      [user],
    );
    expect(kept.map((row) => row.id)).toEqual(ids.slice(2).reverse());
    // Los 6 siguen contando aunque 2 ya no estén en el historial.
    expect(await usage(user, "2026-05-06T10:00:00Z")).toMatchObject({ used: 6 });
  });

  it("borrar todo el historial no recupera análisis", async () => {
    const user = await newUser();

    for (let i = 0; i < 5; i += 1) await complete((await reserve(user)).usage_id as string);
    await db.asUser(user, (sql) => sql("delete from public.audits"));

    expect(await usage(user)).toMatchObject({ used: 5 });
    expect((await reserve(user)).outcome).toBe("quota_exceeded");
  });

  it("del informe se extraen puntuaciones y hallazgos abiertos", async () => {
    const user = await newUser();
    const { usage_id } = await reserve(user);
    const report = JSON.stringify({
      engineVersion: "2.0.0",
      web: { score: 82, grade: "B", coverage: 100 },
      dnsEmail: { score: 100 },
      findings: [{ status: "fail" }, { status: "warning" }, { status: "pass" }, { status: "info" }],
    });
    await db.sql("select public.complete_audit($1, 'ejemplo.test', $2::jsonb, 10)", [usage_id, report]);

    expect(
      await db.sql("select hostname, web_score, web_grade, web_coverage, mail_score, open_findings, engine_version from public.audits where workspace_id = (select id from public.workspaces where owner_id = $1)", [user]),
    ).toEqual([
      { hostname: "ejemplo.test", web_score: 82, web_grade: "B", web_coverage: 100, mail_score: 100, open_findings: 2, engine_version: "2.0.0" },
    ]);
  });
});

describe("baja y nuevo registro", () => {
  const HASH = "a".repeat(64);

  it("darse de baja y registrarse con el mismo correo no reinicia la cuota", async () => {
    const now = "2026-07-10T10:00:00Z";
    const first = await newUser();
    for (let i = 0; i < 4; i += 1) await reserve(first, { now });

    await db.sql("select public.record_account_deletion($1, $2, $3::timestamptz)", [first, HASH, now]);
    await db.sql("delete from auth.users where id = $1", [first]);

    const again = await newUser();
    expect(await usage(again, now, HASH)).toMatchObject({ used: 4 });
    expect(await reserve(again, { now, emailHash: HASH })).toMatchObject({ outcome: "reserved", used: 5 });
    expect((await reserve(again, { now, emailHash: HASH })).outcome).toBe("quota_exceeded");

    // Segunda baja en el mismo periodo: el arrastre se actualiza, no se duplica.
    await db.sql("select public.record_account_deletion($1, $2, $3::timestamptz)", [again, HASH, now]);
    expect(await db.sql("select used from public.usage_carryover where email_hash = $1", [HASH])).toEqual([{ used: 5 }]);
  });

  it("el arrastre solo vale para su periodo y otro correo no lo hereda", async () => {
    const user = await newUser();

    expect(await usage(user, "2026-07-20T00:00:00Z", HASH)).toMatchObject({ used: 5 });
    expect(await usage(user, "2026-08-01T00:00:00Z", HASH)).toMatchObject({ used: 0 });
    expect(await usage(user, "2026-07-20T00:00:00Z", "b".repeat(64))).toMatchObject({ used: 0 });
  });

  it("una baja sin consumo no deja rastro y los arrastres antiguos se purgan", async () => {
    const user = await newUser();

    await db.sql("select public.record_account_deletion($1, $2, '2026-12-01T00:00:00Z')", [user, "c".repeat(64)]);

    expect(await db.sql("select 1 from public.usage_carryover where email_hash = $1", ["c".repeat(64)])).toEqual([]);
    // El arrastre de julio ya tiene más de 62 días en diciembre.
    expect(await db.sql("select 1 from public.usage_carryover where email_hash = $1", [HASH])).toEqual([]);
  });
});
