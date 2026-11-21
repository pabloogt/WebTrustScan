/**
 * ÚNICA fuente de verdad de planes, cuotas y límites contra el abuso.
 *
 * Todo el producto consulta estos valores desde aquí; ninguna página ni
 * ruta los repite. Son valores técnicos PROVISIONALES para poder probar:
 * no son precios ni una decisión comercial.
 *
 * Este fichero no importa nada de Node: lo comparten servidor e interfaz.
 */

export type Plan = "free" | "pro";

/**
 * Ventana móvil de la cuota, en días. Cada análisis consumido cuenta durante
 * los QUOTA_WINDOW_DAYS días siguientes al momento en que se hizo (UTC) y
 * después se libera. La base de datos la valida (1–31 días).
 */
export const QUOTA_WINDOW_DAYS = 7;

export type Entitlements = {
  plan: Plan;
  label: string;
  /** Análisis permitidos en cualquier ventana de QUOTA_WINDOW_DAYS días. */
  auditsPerWindow: number;
  /** Análisis que se conservan en el historial (los más recientes). */
  historySize: number;
  /** Informe completo y descarga en PDF. */
  fullReports: boolean;
  pdfExport: boolean;
};

export const PLANS: Record<Plan, Entitlements> = {
  free: {
    plan: "free",
    label: "Free",
    auditsPerWindow: 5,
    historySize: 10,
    fullReports: true,
    pdfExport: true,
  },
  pro: {
    plan: "pro",
    label: "Pro",
    auditsPerWindow: 25,
    historySize: 50,
    fullReports: true,
    pdfExport: true,
  },
};

/**
 * Lo que una cuenta puede hacer según su plan. El resto de la aplicación
 * pregunta aquí; nunca mira directamente la suscripción ni el proveedor de
 * pagos. Un plan desconocido se trata como Free.
 */
export function entitlementsFor(plan: string | null | undefined): Entitlements {
  return plan === "pro" ? PLANS.pro : PLANS.free;
}

/** Límites por plan en el formato que esperan las funciones SQL de consumo. */
export function auditLimitsByPlan(): Record<Plan, number> {
  return { free: PLANS.free.auditsPerWindow, pro: PLANS.pro.auditsPerWindow };
}

/** Análisis simultáneos por cuenta. Los planes no cambian la seguridad. */
export const ACCOUNT_MAX_CONCURRENT_AUDITS = 2;

/** Visitantes sin cuenta: límite independiente del de las cuentas. */
export const ANONYMOUS = {
  auditsPerDay: 2,
  maxConcurrentAudits: 1,
};

/** Límites de frecuencia contra automatización y fuerza bruta. */
export const RATE_LIMITS = {
  /** Altas por IP. */
  register: { max: 5, windowSeconds: 3_600 },
  /** Intentos de acceso por IP. */
  loginByIp: { max: 10, windowSeconds: 60 },
  /** Intentos de acceso contra una misma cuenta, vengan de donde vengan. */
  loginByEmail: { max: 10, windowSeconds: 900 },
  /** Solicitudes de recuperación por IP y por cuenta. */
  recoveryByIp: { max: 5, windowSeconds: 3_600 },
  recoveryByEmail: { max: 3, windowSeconds: 3_600 },
  /** Análisis por minuto de una cuenta (además de su cuota semanal). */
  auditsByUser: { max: 6, windowSeconds: 60 },
  /** Cambios de cuenta (contraseña, correo, borrado…) por usuario. */
  accountChanges: { max: 10, windowSeconds: 600 },
  /** Lecturas del panel por usuario. */
  accountReads: { max: 120, windowSeconds: 60 },
} as const;

export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 72; // límite de bcrypt en Supabase Auth
