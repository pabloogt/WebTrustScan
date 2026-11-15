export type Plan = "free" | "pro" | "agency";
export type Role = "owner" | "admin" | "member" | "viewer";

export type PlanLimits = {
  /** Dominios guardados por organización. */
  domains: number;
  /** Auditorías que se conservan por dominio (las más antiguas se borran). */
  storedAuditsPerDomain: number;
  /** Auditorías guardadas que una organización puede lanzar por hora. */
  auditsPerHour: number;
};

/**
 * Límites por plan. Free incluye UN dominio con un historial corto para que
 * se pueda probar el valor de Pro (historial y comparación) antes de pagar.
 * Las cifras son una hipótesis inicial: ver docs/PRO_PRODUCT_SPEC.md.
 */
export const PLAN_LIMITS: Record<Plan, PlanLimits> = {
  free: { domains: 1, storedAuditsPerDomain: 5, auditsPerHour: 5 },
  pro: { domains: 10, storedAuditsPerDomain: 200, auditsPerHour: 30 },
  agency: { domains: 100, storedAuditsPerDomain: 500, auditsPerHour: 120 },
};

const RANK: Record<Role, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };

/** ¿El rol alcanza el nivel mínimo requerido? */
export function hasRole(role: Role, minimum: Role): boolean {
  return RANK[role] >= RANK[minimum];
}
