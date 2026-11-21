import { createServerClient } from "@supabase/ssr";
import { createClient, type SupabaseClient, type User } from "@supabase/supabase-js";
import { cookies } from "next/headers";
import { quotaRpc } from "./quotaRpc";
import type { AuditReport } from "../engine/types";
import type { Plan } from "../plans";
import type { SupabaseConfig } from "./config";
import type {
  AccountDeps,
  AuditSummary,
  AuthFailure,
  AuthPort,
  AuthResult,
  DataPort,
  QuotaPort,
  Reservation,
  SessionUser,
  Usage,
} from "./ports";

/**
 * Implementación de los puertos sobre Supabase.
 *
 * - El cliente de sesión usa la clave PÚBLICA y las cookies de la petición:
 *   todo lo que lee o escribe pasa por RLS con la identidad del usuario.
 * - El cliente de servicio usa la clave SECRETA y se salta RLS. Solo se usa
 *   para el consumo de cuota, el registro de eventos y el borrado de cuenta.
 *
 * El navegador nunca habla con Supabase directamente: no hay claves ni
 * tokens accesibles desde JavaScript del cliente.
 */

/** Cookies de sesión: HttpOnly, SameSite=Lax y Secure en producción. */
function cookieOptions() {
  return {
    path: "/",
    sameSite: "lax" as const,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  };
}

async function createSessionClient(config: SupabaseConfig): Promise<SupabaseClient> {
  const store = await cookies();

  return createServerClient(config.url, config.publishableKey, {
    cookieOptions: cookieOptions(),
    cookies: {
      getAll: () => store.getAll(),
      setAll: (list) => {
        try {
          for (const { name, value, options } of list) {
            store.set(name, value, { ...options, ...cookieOptions() });
          }
        } catch {
          // En un componente de servidor no se pueden escribir cookies; la
          // renovación de la sesión la hace entonces proxy.ts.
        }
      },
    },
  });
}

function createServiceClient(config: SupabaseConfig): SupabaseClient {
  if (typeof window !== "undefined") {
    throw new Error("El cliente de servicio solo puede usarse en el servidor.");
  }
  if (!config.secretKey) {
    throw new Error("SUPABASE_SECRET_KEY no está configurada.");
  }

  return createClient(config.url, config.secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

/** Traduce los códigos de error de Supabase Auth a un conjunto cerrado. */
function failure(error: { code?: string; status?: number } | null): AuthResult {
  if (!error) return { ok: true };

  const code = error.code ?? "";
  let reason: AuthFailure = "unavailable";

  if (["invalid_credentials", "email_not_confirmed", "user_banned", "user_not_found"].includes(code)) {
    reason = "invalid_credentials";
  } else if (code === "weak_password") reason = "weak_password";
  else if (code === "same_password") reason = "same_password";
  else if (["reauthentication_needed", "reauthentication_not_valid", "session_not_found"].includes(code)) {
    reason = "reauth_required";
  } else if (code.includes("rate_limit") || error.status === 429) reason = "rate_limited";
  else if (["otp_expired", "otp_disabled", "flow_state_expired", "flow_state_not_found", "bad_code_verifier"].includes(code)) {
    reason = "invalid_link";
  }

  return { ok: false, reason, code: code || `http_${error.status ?? "?"}` };
}

function toSessionUser(user: User | null): SessionUser | null {
  // Sin correo confirmado no hay acceso normal a la cuenta.
  if (!user?.email || !user.email_confirmed_at) return null;

  return { id: user.id, email: user.email, pendingEmail: user.new_email ?? null };
}

function authPort(config: SupabaseConfig, session: SupabaseClient): AuthPort {
  return {
    async getUser() {
      const { data, error } = await session.auth.getUser();
      return error ? null : toSessionUser(data.user);
    },
    async signUp(email, password, redirectTo) {
      const { error } = await session.auth.signUp({
        email,
        password,
        options: { emailRedirectTo: redirectTo },
      });
      return failure(error);
    },
    async signIn(email, password) {
      const { error } = await session.auth.signInWithPassword({ email, password });
      return failure(error);
    },
    async signOut(scope) {
      await session.auth.signOut({ scope });
    },
    async requestPasswordReset(email, redirectTo) {
      const { error } = await session.auth.resetPasswordForEmail(email, { redirectTo });
      return failure(error);
    },
    async verifyLink(type, tokenHash) {
      const { error } = await session.auth.verifyOtp({ type, token_hash: tokenHash });
      return failure(error);
    },
    async exchangeCode(code) {
      const { error } = await session.auth.exchangeCodeForSession(code);
      return failure(error);
    },
    async verifyPassword(email, password) {
      // Cliente aparte y sin persistencia: no toca las cookies del usuario.
      const probe = createClient(config.url, config.publishableKey, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      const { data, error } = await probe.auth.signInWithPassword({ email, password });

      if (error || !data.session) return false;

      // La sesión creada para la comprobación se cierra de inmediato.
      await probe.auth.signOut({ scope: "local" }).catch(() => undefined);
      return true;
    },
    async updatePassword(password) {
      const { error } = await session.auth.updateUser({ password });
      return failure(error);
    },
    async updateEmail(email, redirectTo) {
      const { error } = await session.auth.updateUser({ email }, { emailRedirectTo: redirectTo });
      return failure(error);
    },
    async deleteUser(userId) {
      const { error } = await createServiceClient(config).auth.admin.deleteUser(userId);
      return failure(error);
    },
  };
}

type AuditRow = {
  id: string;
  hostname: string;
  engine_version: string;
  web_score: number | null;
  web_grade: string | null;
  web_coverage: number;
  mail_score: number | null;
  open_findings: number;
  created_at: string;
  report?: AuditReport;
};

const SUMMARY =
  "id, hostname, engine_version, web_score, web_grade, web_coverage, mail_score, open_findings, created_at";

export function toSummary(row: AuditRow): AuditSummary {
  return {
    id: row.id,
    hostname: row.hostname,
    engineVersion: row.engine_version,
    webScore: row.web_score,
    webGrade: row.web_grade,
    webCoverage: row.web_coverage,
    mailScore: row.mail_score,
    openFindings: row.open_findings,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

/** Lanza si Supabase devuelve un error de base de datos. */
function unwrap<T>(result: { data: T; error: { message: string } | null }): T {
  if (result.error) throw new Error(`Supabase: ${result.error.message}`);
  return result.data;
}

function dataPort(session: SupabaseClient): DataPort {
  return {
    async getProfile(userId) {
      const row = unwrap(
        await session.from("profiles").select("display_name, created_at").eq("id", userId).maybeSingle(),
      );
      return row ? { displayName: row.display_name, createdAt: row.created_at } : null;
    },
    async updateDisplayName(userId, displayName) {
      unwrap(await session.from("profiles").update({ display_name: displayName }).eq("id", userId));
    },
    async listAudits() {
      // Sin filtro por usuario: RLS devuelve solo los de sus espacios.
      const rows = unwrap(
        await session.from("audits").select(SUMMARY).order("created_at", { ascending: false }).limit(200),
      );
      return (rows as AuditRow[]).map(toSummary);
    },
    async getAudit(id) {
      const row = unwrap(
        await session.from("audits").select(`${SUMMARY}, report`).eq("id", id).maybeSingle(),
      ) as AuditRow | null;
      return row?.report ? { summary: toSummary(row), report: row.report } : null;
    },
    async deleteAudit(id) {
      const rows = unwrap(await session.from("audits").delete().eq("id", id).select("id"));
      return (rows ?? []).length > 0;
    },
    async exportAll(userId) {
      const [profile, workspaces, subscriptions, audits, usage] = await Promise.all([
        session.from("profiles").select("*").eq("id", userId),
        session.from("workspaces").select("*"),
        session.from("subscriptions").select("plan, status, current_period_start, current_period_end, created_at"),
        session.from("audits").select("*").order("created_at", { ascending: false }),
        session.from("usage_events").select("status, period_start, created_at").order("created_at", { ascending: false }),
      ]);

      return {
        profile: unwrap(profile),
        workspaces: unwrap(workspaces),
        subscriptions: unwrap(subscriptions),
        audits: unwrap(audits),
        usage: unwrap(usage),
      };
    },
  };
}

type RpcReservation = {
  outcome: string;
  usage_id?: string;
  plan?: Plan;
  used?: number;
  limit?: number;
  next_release_at?: string | null;
  available_at?: string | null;
  status?: string;
  audit_id?: string | null;
};

/** Fecha de PostgreSQL (con cualquier desfase) → ISO 8601 en UTC. */
const isoOrNull = (value: string | null | undefined) =>
  value ? new Date(value).toISOString() : null;

export function toReservation(raw: RpcReservation): Reservation {
  switch (raw.outcome) {
    case "reserved":
      return {
        outcome: "reserved",
        usageId: raw.usage_id as string,
        plan: raw.plan as Plan,
        used: raw.used as number,
        limit: raw.limit as number,
        nextReleaseAt: isoOrNull(raw.next_release_at),
      };
    case "duplicate":
      return {
        outcome: "duplicate",
        usageId: raw.usage_id as string,
        status: raw.status as string,
        auditId: raw.audit_id ?? null,
      };
    case "quota_exceeded":
      return {
        outcome: "quota_exceeded",
        plan: raw.plan as Plan,
        used: raw.used as number,
        limit: raw.limit as number,
        availableAt: isoOrNull(raw.available_at),
      };
    case "too_many_concurrent":
      return { outcome: "too_many_concurrent" };
    default:
      return { outcome: "no_workspace" };
  }
}

export function toUsage(raw: {
  outcome: string;
  plan?: Plan;
  used?: number;
  limit?: number;
  next_release_at?: string | null;
  available_at?: string | null;
}): Usage | null {
  return raw.outcome === "ok"
    ? {
        plan: raw.plan as Plan,
        used: raw.used as number,
        limit: raw.limit as number,
        nextReleaseAt: isoOrNull(raw.next_release_at),
        availableAt: isoOrNull(raw.available_at),
      }
    : null;
}

function quotaPort(config: SupabaseConfig): QuotaPort {
  // Se crea al primer uso: sin clave secreta el resto de la cuenta funciona.
  let client: SupabaseClient | null = null;
  const service = () => (client ??= createServiceClient(config));

  return {
    async usage(userId, emailHash) {
      const { fn, args } = quotaRpc.usage(userId, emailHash);
      return toUsage(unwrap(await service().rpc(fn, args)));
    },
    async reserve(userId, requestId, emailHash) {
      const { fn, args } = quotaRpc.reserve(userId, requestId, emailHash);
      return toReservation(unwrap(await service().rpc(fn, args)));
    },
    async complete(usageId, hostname, report, historySize) {
      const { fn, args } = quotaRpc.complete(usageId, hostname, report, historySize);
      return unwrap(await service().rpc(fn, args)) as string;
    },
    async finish(usageId, status) {
      const { fn, args } = quotaRpc.finish(usageId, status);
      unwrap(await service().rpc(fn, args));
    },
    async reportOf(auditId) {
      const row = unwrap(
        await service().from("audits").select("report").eq("id", auditId).maybeSingle(),
      ) as { report: AuditReport } | null;
      return row?.report ?? null;
    },
    async recordDeletion(userId, emailHash) {
      const { fn, args } = quotaRpc.recordDeletion(userId, emailHash);
      unwrap(await service().rpc(fn, args));
    },
    async logSecurityEvent(event) {
      // El registro es auxiliar: un fallo al escribirlo no rompe la operación.
      const { error } = await service().from("security_events").insert({
        user_id: event.userId,
        type: event.type,
        ip_hash: event.ipHash,
        metadata: event.metadata ?? {},
      });
      if (error) console.warn("No se pudo registrar un evento de seguridad:", event.type);
    },
  };
}

/** Puertos reales para la petición en curso. */
export async function createSupabaseDeps(config: SupabaseConfig): Promise<AccountDeps> {
  const session = await createSessionClient(config);

  return {
    auth: authPort(config, session),
    data: dataPort(session),
    quota: quotaPort(config),
  };
}
