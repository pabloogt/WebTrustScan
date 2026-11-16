import { randomBytes, randomUUID } from "node:crypto";
import { NextRequest } from "next/server";
import { setAccountDepsForTests } from "@/lib/accounts/http";
import type {
  AccountDeps,
  AuditSummary,
  AuthPort,
  AuthResult,
  DataPort,
  OtpType,
  QuotaPort,
} from "@/lib/accounts/ports";
import type { AuditReport } from "@/lib/engine/types";
import { ACCOUNT_MAX_CONCURRENT_AUDITS, auditLimitsByPlan } from "@/lib/plans";
import { createTestDb, type Sql, type TestDb } from "../db/harness";

/**
 * Entorno de pruebas de la capa de cuentas.
 *
 * - Los DATOS y el CONSUMO usan PostgreSQL de verdad (el arnés de tests/db):
 *   las lecturas del usuario se hacen con su rol y RLS activo, y la cuota
 *   con las funciones SQL reales.
 * - La AUTENTICACIÓN es un doble de pruebas que imita el comportamiento
 *   documentado de Supabase Auth (alta que no revela duplicados, correo sin
 *   confirmar no entra, enlaces de un solo uso que caducan). NO es Supabase:
 *   estas pruebas verifican nuestra lógica, no la del proveedor.
 */

export const ORIGIN = "http://localhost";

type FakeUser = {
  id: string;
  email: string;
  password: string;
  confirmed: boolean;
  pendingEmail: string | null;
};

export type Mail = {
  to: string;
  type: OtpType;
  tokenHash: string;
  userId: string;
  expiresAt: number;
  used: boolean;
  redirectTo: string;
};

export type Env = {
  db: TestDb;
  /** Usuario de la «cookie de sesión» de la petición en curso. */
  session: { userId: string | null };
  users: Map<string, FakeUser>;
  outbox: Mail[];
  events: { type: string; userId: string | null; ipHash: string | null }[];
  now: { value: number };
  /** Puertos del entorno, para volver a entregarlos si un módulo se recarga. */
  deps: AccountDeps;
  close: () => Promise<void>;
};

const ok: AuthResult = { ok: true };
const WEAK = new Set(["contraseña123", "1234567890"]);

export async function createEnv(): Promise<Env> {
  const db = await createTestDb();
  const env: Env = {
    db,
    session: { userId: null },
    users: new Map(),
    outbox: [],
    events: [],
    now: { value: Date.now() },
    deps: undefined as unknown as AccountDeps,
    close: async () => {
      setAccountDepsForTests(null);
      await db.close();
    },
  };

  const byEmail = (email: string) =>
    [...env.users.values()].find((user) => user.email === email);
  const send = (user: FakeUser, to: string, type: OtpType, redirectTo: string) =>
    env.outbox.push({
      to,
      type,
      tokenHash: randomBytes(16).toString("hex"),
      userId: user.id,
      expiresAt: env.now.value + 3_600_000,
      used: false,
      redirectTo,
    });

  const auth: AuthPort = {
    async getUser() {
      const user = env.session.userId ? env.users.get(env.session.userId) : undefined;
      return user?.confirmed
        ? { id: user.id, email: user.email, pendingEmail: user.pendingEmail }
        : null;
    },
    async signUp(email, password, redirectTo) {
      if (WEAK.has(password)) return { ok: false, reason: "weak_password" };
      // Como Supabase con confirmación activada: un correo ya registrado no
      // produce error ni crea nada.
      if (byEmail(email)) return ok;

      const [{ id }] = await db.sql<{ id: string }>(
        "insert into auth.users (email) values ($1) returning id",
        [email],
      );
      const user: FakeUser = { id, email, password, confirmed: false, pendingEmail: null };
      env.users.set(id, user);
      send(user, email, "email", redirectTo);
      return ok;
    },
    async signIn(email, password) {
      const user = byEmail(email);
      if (!user || user.password !== password || !user.confirmed) {
        return { ok: false, reason: "invalid_credentials" };
      }
      env.session.userId = user.id;
      return ok;
    },
    async signOut(scope) {
      // "others" cierra las demás sesiones y conserva la de esta petición.
      if (scope !== "others") env.session.userId = null;
    },
    async requestPasswordReset(email, redirectTo) {
      const user = byEmail(email);
      if (user?.confirmed) send(user, email, "recovery", redirectTo);
      return ok; // nunca revela si existe
    },
    async verifyLink(type, tokenHash) {
      const mail = env.outbox.find((entry) => entry.tokenHash === tokenHash && entry.type === type);
      const user = mail ? env.users.get(mail.userId) : undefined;

      if (!mail || !user || mail.used || mail.expiresAt < env.now.value) {
        return { ok: false, reason: "invalid_link" };
      }

      mail.used = true;
      if (type === "email" || type === "signup") {
        user.confirmed = true;
        await db.sql("update auth.users set email_confirmed_at = now() where id = $1", [user.id]);
      }
      if (type === "email_change" && user.pendingEmail) {
        user.email = user.pendingEmail;
        user.pendingEmail = null;
      }
      env.session.userId = user.id;
      return ok;
    },
    async verifyPassword(email, password) {
      return byEmail(email)?.password === password;
    },
    async updatePassword(password) {
      const user = env.session.userId ? env.users.get(env.session.userId) : undefined;
      if (!user) return { ok: false, reason: "invalid_credentials" };
      if (WEAK.has(password)) return { ok: false, reason: "weak_password" };
      if (user.password === password) return { ok: false, reason: "same_password" };
      user.password = password;
      return ok;
    },
    async updateEmail(email, redirectTo) {
      const user = env.session.userId ? env.users.get(env.session.userId) : undefined;
      if (!user) return { ok: false, reason: "invalid_credentials" };
      // Si la dirección es de otra cuenta, no se envía nada ni se avisa.
      if (!byEmail(email)) {
        user.pendingEmail = email;
        send(user, email, "email_change", redirectTo);
      }
      return ok;
    },
    async deleteUser(userId) {
      await db.sql("delete from auth.users where id = $1", [userId]);
      env.users.delete(userId);
      return ok;
    },
  };

  /** Lecturas con la identidad del usuario: RLS decide qué devuelve. */
  const asSession = <T>(work: (sql: Sql) => Promise<T>): Promise<T> =>
    env.session.userId ? db.asUser(env.session.userId, work) : db.asAnon(work);

  const SUMMARY =
    "id, hostname, engine_version, web_score, web_grade, web_coverage, mail_score, open_findings, created_at";
  const summary = (row: Record<string, unknown>): AuditSummary => ({
    id: row.id as string,
    hostname: row.hostname as string,
    engineVersion: row.engine_version as string,
    webScore: row.web_score as number | null,
    webGrade: row.web_grade as string | null,
    webCoverage: row.web_coverage as number,
    mailScore: row.mail_score as number | null,
    openFindings: row.open_findings as number,
    createdAt: new Date(row.created_at as string).toISOString(),
  });

  const data: DataPort = {
    async getProfile(userId) {
      const [row] = await asSession((sql) =>
        sql<{ display_name: string | null; created_at: string }>(
          "select display_name, created_at from public.profiles where id = $1",
          [userId],
        ),
      );
      return row ? { displayName: row.display_name, createdAt: String(row.created_at) } : null;
    },
    async updateDisplayName(userId, displayName) {
      await asSession((sql) =>
        sql("update public.profiles set display_name = $2 where id = $1", [userId, displayName]),
      );
    },
    async listAudits() {
      return (
        await asSession((sql) => sql(`select ${SUMMARY} from public.audits order by created_at desc`))
      ).map(summary);
    },
    async getAudit(id) {
      const [row] = await asSession((sql) =>
        sql(`select ${SUMMARY}, report from public.audits where id = $1`, [id]),
      );
      return row ? { summary: summary(row), report: row.report as AuditReport } : null;
    },
    async deleteAudit(id) {
      return (
        (await asSession((sql) => sql("delete from public.audits where id = $1 returning id", [id])))
          .length > 0
      );
    },
    async exportAll(userId) {
      return asSession(async (sql) => ({
        profile: await sql("select * from public.profiles where id = $1", [userId]),
        workspaces: await sql("select * from public.workspaces"),
        subscriptions: await sql("select plan, status from public.subscriptions"),
        audits: await sql("select * from public.audits order by created_at desc"),
        usage: await sql("select status, period_start from public.usage_events"),
      }));
    },
  };

  const { toReservation, toUsage } = await import("@/lib/accounts/supabasePorts");
  const service = <T>(work: (sql: Sql) => Promise<T>) => db.asService(work);

  const quota: QuotaPort = {
    async usage(userId, emailHash) {
      const [{ r }] = await service((sql) =>
        sql<{ r: never }>("select public.workspace_usage($1, $2) as r", [userId, emailHash]),
      );
      return toUsage(r);
    },
    async reserve(userId, requestId, emailHash) {
      const [{ r }] = await service((sql) =>
        sql<{ r: never }>("select public.reserve_audit($1, $2, $3::jsonb, $4, $5) as r", [
          userId,
          requestId,
          JSON.stringify(auditLimitsByPlan()),
          ACCOUNT_MAX_CONCURRENT_AUDITS,
          emailHash,
        ]),
      );
      return toReservation(r);
    },
    async complete(usageId, hostname, report, historySize) {
      const [{ id }] = await service((sql) =>
        sql<{ id: string }>("select public.complete_audit($1, $2, $3::jsonb, $4) as id", [
          usageId,
          hostname,
          JSON.stringify(report),
          historySize,
        ]),
      );
      return id;
    },
    async finish(usageId, status) {
      await service((sql) => sql("select public.finish_audit($1, $2)", [usageId, status]));
    },
    async reportOf(auditId) {
      const [row] = await service((sql) =>
        sql<{ report: AuditReport }>("select report from public.audits where id = $1", [auditId]),
      );
      return row?.report ?? null;
    },
    async recordDeletion(userId, emailHash) {
      await service((sql) =>
        sql("select public.record_account_deletion($1, $2)", [userId, emailHash]),
      );
    },
    async logSecurityEvent(event) {
      env.events.push({ type: event.type, userId: event.userId, ipHash: event.ipHash });
      await service((sql) =>
        sql("insert into public.security_events (user_id, type, ip_hash) values ($1, $2, $3)", [
          event.userId,
          event.type,
          event.ipHash,
        ]),
      );
    },
  };

  env.deps = { auth, data, quota };
  setAccountDepsForTests(async () => env.deps);

  return env;
}

type Handler = (
  request: NextRequest,
  context: { params: Promise<never> },
) => Promise<Response>;

/** Invoca un handler de ruta como lo haría el navegador de la aplicación. */
export async function call(
  handler: Handler,
  options: {
    method?: string;
    path?: string;
    body?: unknown;
    origin?: string | null;
    params?: Record<string, string>;
    headers?: Record<string, string>;
    cookie?: string;
  } = {},
): Promise<{ status: number; data: Record<string, unknown>; response: Response }> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { host: "localhost", ...options.headers };

  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.cookie) headers.cookie = options.cookie;
  if (method !== "GET" && options.origin !== null) headers.origin = options.origin ?? ORIGIN;

  const response = await handler(
    new NextRequest(`${ORIGIN}${options.path ?? "/api/test"}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    }),
    { params: Promise.resolve(options.params ?? {}) as Promise<never> },
  );

  return {
    status: response.status,
    data: (await response
      .clone()
      .json()
      .catch(() => ({}))) as Record<string, unknown>,
    response,
  };
}

/** Informe mínimo con la forma que produce el motor. */
export function sampleReport(hostname: string): AuditReport {
  return {
    engineVersion: "2.0.0",
    scannedAt: new Date().toISOString(),
    durationMs: 10,
    target: {
      input: hostname,
      url: `https://${hostname}/`,
      host: hostname,
      httpStatus: 200,
      contentType: "text/html",
      redirects: [],
      edge: null,
      condition: "ok",
    },
    notices: [],
    web: { score: 80, grade: "B", coverage: 100 },
    dnsEmail: { score: null, grade: null, coverage: 0 },
    findings: [{ id: "transport.https", status: "pass" }],
  } as unknown as AuditReport;
}

export const requestId = () => randomUUID();
export const PASSWORD = "una-frase-larga-de-prueba";
