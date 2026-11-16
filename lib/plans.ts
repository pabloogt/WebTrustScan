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

export type Entitlements = {
  plan: Plan;
  label: string;
  /** Análisis por periodo (mes natural UTC en Free). */
  monthlyAudits: number;
  /** Análisis que se conservan en el historial. */
  historySize: number;
};

export const PLANS: Record<Plan, Entitlements> = {
  free: { plan: "free", label: "Free", monthlyAudits: 5, historySize: 10 },
  pro: { plan: "pro", label: "Pro", monthlyAudits: 100, historySize: 100 },
};

/**
 * Lo que una cuenta puede hacer según su plan. El resto de la aplicación
 * pregunta aquí; nunca mira directamente la suscripción ni el proveedor de
 * pagos. Un plan desconocido se trata como Free.
 */
export function entitlementsFor(plan: string | null | undefined): Entitlements {
  return plan === "pro" ? PLANS.pro : PLANS.free;
}

/** Límites por plan en el formato que espera la función SQL `reserve_audit`. */
export function auditLimitsByPlan(): Record<Plan, number> {
  return { free: PLANS.free.monthlyAudits, pro: PLANS.pro.monthlyAudits };
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
  /** Análisis por minuto de una cuenta (además de su cuota mensual). */
  auditsByUser: { max: 6, windowSeconds: 60 },
  /** Cambios de cuenta (contraseña, correo, borrado…) por usuario. */
  accountChanges: { max: 10, windowSeconds: 600 },
  /** Lecturas del panel por usuario. */
  accountReads: { max: 120, windowSeconds: 60 },
} as const;

export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 72; // límite de bcrypt en Supabase Auth
