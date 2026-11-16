import type { Plan } from "../plans";

/**
 * Capa de facturación. HOY NO HAY NINGÚN PROVEEDOR CONECTADO: este fichero
 * solo define los tipos y la interfaz que deberá cumplir la integración con
 * Stripe (ver docs/STRIPE_NEXT_PHASE.md).
 *
 * El resto de la aplicación no depende de esto: consulta lo que una cuenta
 * puede hacer con `entitlementsFor()` (lib/plans.ts), a partir del plan
 * efectivo que calcula la base de datos.
 */

/** Estados de `subscriptions.status`. Coinciden con la restricción SQL. */
export type SubscriptionStatus =
  | "active"
  | "trialing"
  | "past_due"
  | "canceled"
  | "incomplete";

export type BillingProviderName = "none" | "manual" | "stripe";

/** Fila de `public.subscriptions`. */
export type Subscription = {
  workspaceId: string;
  plan: Plan;
  status: SubscriptionStatus;
  provider: BillingProviderName;
  providerCustomerId: string | null;
  providerSubscriptionId: string | null;
  currentPeriodStart: string | null;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
};

/** Pro solo cuenta si la suscripción está activa o en periodo de prueba. */
export function effectivePlan(
  subscription: Pick<Subscription, "plan" | "status"> | null,
): Plan {
  return subscription?.plan === "pro" &&
    (subscription.status === "active" || subscription.status === "trialing")
    ? "pro"
    : "free";
}

/** Cambio de estado ya verificado que un proveedor comunica al sistema. */
export type SubscriptionChange = {
  /** Identificador único del evento en el proveedor (idempotencia). */
  eventId: string;
  eventType: string;
  workspaceId: string;
  plan: Plan;
  status: SubscriptionStatus;
  providerCustomerId: string;
  providerSubscriptionId: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
};

/**
 * Lo que tendrá que implementar el proveedor de pagos. Ninguna
 * implementación existe todavía.
 */
export interface BillingProvider {
  readonly name: BillingProviderName;
  /** URL de pago alojada por el proveedor para contratar un plan. */
  createCheckout(input: {
    workspaceId: string;
    plan: Plan;
    successUrl: string;
    cancelUrl: string;
  }): Promise<{ url: string }>;
  /** URL del portal donde el cliente gestiona o cancela su suscripción. */
  createPortalSession(input: {
    providerCustomerId: string;
    returnUrl: string;
  }): Promise<{ url: string }>;
  /**
   * Verifica la firma criptográfica de un webhook y lo traduce. Debe LANZAR
   * si la firma no es válida: un evento sin verificar nunca cambia un plan.
   */
  parseWebhook(rawBody: string, signature: string): Promise<SubscriptionChange | null>;
}
