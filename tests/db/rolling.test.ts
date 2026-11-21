import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, type TestDb } from "./harness";

/**
 * Cuota en ventana móvil de 7 días (migración 20261117020000_rolling_quota).
 * Se prueban las funciones SQL reales sobre PostgreSQL embebido.
 */

const LIMITS = { free: 5, pro: 25 };
const DAY = 86_400_000;
const WINDOW = 7;
const REPORT = JSON.stringify({
  engineVersion: "2.0.0",
  web: { score: 70, grade: "C", coverage: 100 },
  dnsEmail: { score: null },
  findings: [],
});

type Result = {
  outcome: string;
  usage_id?: string;
  used?: number;
  limit?: number;
  plan?: string;
  status?: string;
  next_release_at?: string | null;
  available_at?: string | null;
};

let db: TestDb;
let counter = 0;

beforeAll(async () => {
  db = await createTestDb();
});
afterAll(() => db.close());

const newUser = () => db.createUser(`r${(counter += 1)}@ventana.test`);
const at = (base: number, days: number, ms = 0) => new Date(base + days * DAY + ms).toISOString();
const iso = (value: string | null | undefined) => (value ? new Date(value).toISOString() : null);

async function reserve(
  user: string,
  now: string,
  options: { request?: string; emailHash?: string | null; window?: number; maxConcurrent?: number } = {},
): Promise<Result> {
  const [{ r }] = await db.sql<{ r: Result }>(
    `select public.reserve_audit_rolling(
       p_user => $1, p_request => $2, p_limits => $3::jsonb, p_window_days => $4,
       p_max_concurrent => $5, p_email_hash => $6, p_now => $7::timestamptz) as r`,
    [
      user,
      options.request ?? randomUUID(),
      JSON.stringify(LIMITS),
      options.window ?? WINDOW,
      options.maxConcurrent ?? 50,
      options.emailHash ?? null,
      now,
    ],
  );
  return r;
}

async function usage(user: string, now: string, emailHash: string | null = null): Promise<Result> {
  const [{ r }] = await db.sql<{ r: Result }>(
    `select public.workspace_usage_rolling(
       p_user => $1, p_limits => $2::jsonb, p_window_days => $3,
       p_email_hash => $4, p_now => $5::timestamptz) as r`,
    [user, JSON.stringify(LIMITS), WINDOW, emailHash, now],
  );
  return r;
}

/** Reserva y completa: un análisis terminado en el instante `now`. */
async function audit(user: string, now: string): Promise<Result> {
  const r = await reserve(user, now);
  if (r.outcome === "reserved") {
    await db.sql("select public.complete_audit($1, 'ejemplo.test', $2::jsonb, 50, $3::timestamptz)", [
      r.usage_id,
      REPORT,
      now,
    ]);
  }
  return r;
}

const setPlan = (user: string, plan: "free" | "pro") =>
  db.sql(
    `update public.subscriptions set plan = $2, status = 'active', provider = 'manual'
      where workspace_id = (select id from public.workspaces where owner_id = $1)`,
    [user, plan],
  );

describe("ventana móvil de 7 días · Free", () => {
  it("permite 5 en 7 días y el sexto indica cuándo se libera el primero", async () => {
    const user = await newUser();
    const t0 = Date.parse("2026-11-10T09:00:00Z");

    for (let i = 0; i < 5; i += 1) {
      expect((await audit(user, at(t0, i * 0.5))).outcome).toBe("reserved");
    }
    const sixth = await reserve(user, at(t0, 3));

    expect(sixth).toMatchObject({ outcome: "quota_exceeded", used: 5, limit: 5, plan: "free" });
    // El primero se hizo el 10 a las 09:00 UTC: se libera el 17 a las 09:00 UTC.
    expect(iso(sixth.available_at)).toBe("2026-11-17T09:00:00.000Z");
  });

  it("cada uso se libera exactamente 7 días después, ni un milisegundo antes", async () => {
    const user = await newUser();
    const t0 = Date.parse("2026-11-01T12:00:00Z");
    for (let i = 0; i < 5; i += 1) await audit(user, at(t0, i)); // días 0, 1, 2, 3, 4

    expect((await reserve(user, at(t0, 7, -1))).outcome).toBe("quota_exceeded");
    expect((await usage(user, at(t0, 7, -1))).used).toBe(5);

    // A los 7 días justos el del día 0 deja de contar: queda uno libre.
    expect((await usage(user, at(t0, 7))).used).toBe(4);
    expect((await reserve(user, at(t0, 7))).outcome).toBe("reserved");
    expect((await reserve(user, at(t0, 7, 1))).outcome).toBe("quota_exceeded");

    // Al día 8 se libera el del día 1.
    expect((await reserve(user, at(t0, 8))).outcome).toBe("reserved");
  });

  it("informa del próximo uso que se libera aunque queden análisis", async () => {
    const user = await newUser();
    const t0 = Date.parse("2026-11-03T08:30:00Z");
    await audit(user, at(t0, 0));
    await audit(user, at(t0, 2));

    const now = await usage(user, at(t0, 3));
    expect(now).toMatchObject({ outcome: "ok", used: 2, limit: 5, plan: "free" });
    expect(iso(now.next_release_at)).toBe("2026-11-10T08:30:00.000Z");
    expect(now.available_at).toBeNull();

    const fresh = await usage(await newUser(), at(t0, 0));
    expect(fresh).toMatchObject({ used: 0, next_release_at: null, available_at: null });
  });

  it("las fechas son instantes absolutos: la zona horaria de la petición no cambia nada", async () => {
    const user = await newUser();
    await audit(user, "2026-11-20T23:30:00+01:00"); // = 22:30 UTC

    expect(iso((await usage(user, "2026-11-21T10:00:00Z")).next_release_at)).toBe("2026-11-27T22:30:00.000Z");
    expect((await usage(user, "2026-11-27T23:29:59+01:00")).used).toBe(1);
    expect((await usage(user, "2026-11-27T23:30:00+01:00")).used).toBe(0);
  });
});

describe("ventana móvil · reglas de consumo", () => {
  it("peticiones simultáneas no superan el límite", async () => {
    const user = await newUser();
    const now = "2026-11-12T10:00:00Z";
    const results = await Promise.all(Array.from({ length: 12 }, () => reserve(user, now)));

    expect(results.filter((r) => r.outcome === "reserved")).toHaveLength(5);
    expect(results.filter((r) => r.outcome === "quota_exceeded")).toHaveLength(7);
    expect(new Set(results.filter((r) => r.used).map((r) => r.used)).size).toBeGreaterThan(1);
  });

  it("repetir la misma petición no consume dos veces", async () => {
    const user = await newUser();
    const request = randomUUID();
    const now = "2026-11-12T10:00:00Z";

    expect((await reserve(user, now, { request })).outcome).toBe("reserved");
    expect((await reserve(user, now, { request })).outcome).toBe("duplicate");
    expect((await usage(user, now)).used).toBe(1);
  });

  it("borrar análisis del historial no devuelve usos", async () => {
    const user = await newUser();
    const now = "2026-11-12T10:00:00Z";
    for (let i = 0; i < 5; i += 1) await audit(user, now);

    await db.asUser(user, (sql) => sql("delete from public.audits"));

    expect(await db.sql("select 1 from public.audits a join public.workspaces w on w.id = a.workspace_id where w.owner_id = $1", [user])).toEqual([]);
    expect((await usage(user, now)).used).toBe(5);
    expect((await reserve(user, now)).outcome).toBe("quota_exceeded");
  });

  it("un fallo del destino cuenta; un fallo interno se libera", async () => {
    const user = await newUser();
    const now = "2026-11-12T10:00:00Z";
    const failed = await reserve(user, now);
    const released = await reserve(user, now);

    await db.sql("select public.finish_audit($1, 'failed')", [failed.usage_id]);
    await db.sql("select public.finish_audit($1, 'released')", [released.usage_id]);

    expect((await usage(user, now)).used).toBe(1);
  });

  it("el consumo registrado antes del cambio cuenta por su fecha real", async () => {
    // Fila creada por la versión mensual: period_start = mes UTC.
    const user = await newUser();
    await db.sql(
      `insert into public.usage_events (workspace_id, user_id, request_id, period_start, status, created_at)
       select w.id, $1, gen_random_uuid(), '2026-11-01T00:00:00Z', 'completed', '2026-11-09T15:00:00Z'
         from public.workspaces w where w.owner_id = $1`,
      [user],
    );

    expect((await usage(user, "2026-11-12T00:00:00Z")).used).toBe(1);
    expect((await usage(user, "2026-11-16T15:00:00Z")).used).toBe(0);
  });

  it("los nuevos consumos siguen guardando el mes UTC en period_start (compatibilidad)", async () => {
    const user = await newUser();
    const r = await reserve(user, "2026-11-30T23:30:00Z");
    const [row] = await db.sql<{ period_start: Date }>("select period_start from public.usage_events where id = $1", [r.usage_id]);

    expect(new Date(row.period_start).toISOString()).toBe("2026-11-01T00:00:00.000Z");
  });

  it("la ventana debe estar entre 1 y 31 días", async () => {
    const user = await newUser();
    await expect(reserve(user, "2026-11-12T10:00:00Z", { window: 0 })).rejects.toThrow(/Ventana de cuota no válida/);
    await expect(reserve(user, "2026-11-12T10:00:00Z", { window: 32 })).rejects.toThrow(/Ventana de cuota no válida/);
  });

  it("sigue limitando los análisis simultáneos", async () => {
    const user = await newUser();
    const now = "2026-11-12T10:00:00Z";
    expect((await reserve(user, now, { maxConcurrent: 1 })).outcome).toBe("reserved");
    expect((await reserve(user, now, { maxConcurrent: 1 })).outcome).toBe("too_many_concurrent");
  });
});

describe("ventana móvil · Pro y cambios de plan", () => {
  it("Pro permite 25 en 7 días", async () => {
    const user = await newUser();
    await setPlan(user, "pro");
    const now = "2026-11-12T10:00:00Z";
    const results = [];
    for (let i = 0; i < 26; i += 1) results.push(await reserve(user, now));

    expect(results.filter((r) => r.outcome === "reserved")).toHaveLength(25);
    expect(results[25]).toMatchObject({ outcome: "quota_exceeded", plan: "pro", used: 25, limit: 25 });
  });

  it("al pasar de Pro a Free con más usos que el límite, indica cuándo vuelve a haber uno", async () => {
    const user = await newUser();
    await setPlan(user, "pro");
    const t0 = Date.parse("2026-11-01T00:00:00Z");
    for (let i = 0; i < 8; i += 1) await audit(user, at(t0, i * 0.25)); // cada 6 horas

    await setPlan(user, "free");
    const r = await reserve(user, at(t0, 3));

    expect(r).toMatchObject({ outcome: "quota_exceeded", plan: "free", used: 8, limit: 5 });
    // Deben caducar 4 usos (8 → 4): el cuarto se hizo a las 18:00 del día 1.
    expect(iso(r.available_at)).toBe("2026-11-08T18:00:00.000Z");
  });
});

describe("ventana móvil · baja y nuevo registro", () => {
  const HASH = "c".repeat(64);
  const OTHER = "d".repeat(64);

  it("darse de baja y volver con el mismo correo no reinicia la cuota; cada uso se libera a su hora", async () => {
    const t0 = Date.parse("2026-11-05T10:00:00Z");
    const first = await newUser();
    for (let i = 0; i < 3; i += 1) await audit(first, at(t0, i)); // días 0, 1, 2

    await db.sql("select public.record_account_deletion_rolling($1, $2, 7, $3::timestamptz)", [first, HASH, at(t0, 3)]);
    await db.sql("delete from auth.users where id = $1", [first]);

    const again = await newUser();
    expect((await usage(again, at(t0, 3), HASH)).used).toBe(3);
    expect((await usage(again, at(t0, 3), OTHER)).used).toBe(0);
    // El del día 0 se libera el día 7.
    expect((await usage(again, at(t0, 7), HASH)).used).toBe(2);
    expect((await usage(again, at(t0, 10), HASH)).used).toBe(0);
  });

  it("los arrastres del sistema mensual cuentan 7 días desde la baja y no se borran", async () => {
    const user = await newUser();
    const hash = "e".repeat(64);
    await db.sql(
      "insert into public.usage_carryover (email_hash, period_start, used, created_at) values ($1, '2026-11-01', 4, '2026-11-10T00:00:00Z')",
      [hash],
    );

    expect((await usage(user, "2026-11-12T00:00:00Z", hash)).used).toBe(4);
    expect((await usage(user, "2026-11-17T00:00:00Z", hash)).used).toBe(0);
    expect(await db.sql("select 1 from public.usage_carryover where email_hash = $1", [hash])).toHaveLength(1);
  });

  it("los arrastres de más de 31 días se purgan", async () => {
    const hash = "f".repeat(64);
    await db.sql("insert into public.usage_carryover_events (email_hash, used_at) values ($1, '2026-09-01T00:00:00Z')", [hash]);
    const user = await newUser();

    await db.sql("select public.record_account_deletion_rolling($1, $2, 7, '2026-11-12T00:00:00Z')", [user, OTHER]);

    expect(await db.sql("select 1 from public.usage_carryover_events where email_hash = $1", [hash])).toEqual([]);
  });
});
