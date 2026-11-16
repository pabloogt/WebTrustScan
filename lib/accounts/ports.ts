import type { AuditReport } from "../engine/types";
import type { Plan } from "../plans";

/**
 * Puertos de la capa de cuentas. La lógica de la aplicación depende de
 * estas interfaces; la implementación real habla con Supabase
 * (`supabasePorts.ts`) y los tests usan otra sobre PostgreSQL embebido.
 */

export type SessionUser = {
  id: string;
  email: string;
  /** Correo nuevo pendiente de confirmar, si hay un cambio en curso. */
  pendingEmail: string | null;
};

export type AuthFailure =
  /** Credenciales incorrectas o cuenta sin confirmar (no se distingue). */
  | "invalid_credentials"
  | "weak_password"
  | "same_password"
  | "rate_limited"
  | "invalid_link"
  /** El proveedor exige un inicio de sesión reciente para esta operación. */
  | "reauth_required"
  | "unavailable";

export type AuthResult = { ok: true } | { ok: false; reason: AuthFailure };

export type OtpType = "email" | "signup" | "recovery" | "email_change";

/** Autenticación. La fuente de verdad es Supabase Auth. */
export interface AuthPort {
  /** Usuario de la sesión actual, validado contra el servidor de Auth. */
  getUser(): Promise<SessionUser | null>;
  signUp(email: string, password: string, redirectTo: string): Promise<AuthResult>;
  signIn(email: string, password: string): Promise<AuthResult>;
  signOut(scope: "local" | "global" | "others"): Promise<void>;
  requestPasswordReset(email: string, redirectTo: string): Promise<AuthResult>;
  /** Canjea el enlace de un correo (confirmación, recuperación, cambio). */
  verifyLink(type: OtpType, tokenHash: string): Promise<AuthResult>;
  /** Comprueba una contraseña sin alterar la sesión actual. */
  verifyPassword(email: string, password: string): Promise<boolean>;
  updatePassword(password: string): Promise<AuthResult>;
  updateEmail(email: string, redirectTo: string): Promise<AuthResult>;
  /** Borra el usuario. Requiere la clave secreta del servidor. */
  deleteUser(userId: string): Promise<AuthResult>;
}

export type AuditSummary = {
  id: string;
  hostname: string;
  engineVersion: string;
  webScore: number | null;
  webGrade: string | null;
  webCoverage: number;
  mailScore: number | null;
  openFindings: number;
  createdAt: string;
};

export type Profile = { displayName: string | null; createdAt: string };

/** Datos del usuario. Se leen con SU sesión: RLS decide qué ve. */
export interface DataPort {
  getProfile(userId: string): Promise<Profile | null>;
  updateDisplayName(userId: string, displayName: string | null): Promise<void>;
  listAudits(): Promise<AuditSummary[]>;
  getAudit(id: string): Promise<{ summary: AuditSummary; report: AuditReport } | null>;
  deleteAudit(id: string): Promise<boolean>;
  /** Todo lo que la cuenta tiene guardado, para la exportación. */
  exportAll(userId: string): Promise<Record<string, unknown>>;
}

export type Usage = {
  plan: Plan;
  used: number;
  periodStart: string;
  periodEnd: string;
};

export type Reservation =
  | { outcome: "reserved"; usageId: string; plan: Plan; used: number; limit: number; periodEnd: string }
  | { outcome: "duplicate"; usageId: string; status: string; auditId: string | null }
  | { outcome: "quota_exceeded"; plan: Plan; used: number; limit: number; periodEnd: string }
  | { outcome: "too_many_concurrent" }
  | { outcome: "no_workspace" };

/** Consumo de análisis. Solo servidor (clave secreta). */
export interface QuotaPort {
  usage(userId: string, emailHash: string): Promise<Usage | null>;
  reserve(userId: string, requestId: string, emailHash: string): Promise<Reservation>;
  complete(usageId: string, hostname: string, report: AuditReport, historySize: number): Promise<string>;
  finish(usageId: string, status: "failed" | "released"): Promise<void>;
  /** Informe de un análisis ya hecho (reintento de una petición idempotente). */
  reportOf(auditId: string): Promise<AuditReport | null>;
  /** Guarda el consumo del periodo bajo un HMAC del correo antes de la baja. */
  recordDeletion(userId: string, emailHash: string): Promise<void>;
  logSecurityEvent(event: {
    userId: string | null;
    type: string;
    ipHash: string | null;
    metadata?: Record<string, string | number | boolean>;
  }): Promise<void>;
}

export type AccountDeps = { auth: AuthPort; data: DataPort; quota: QuotaPort };
