import type { AuditReport } from "../engine/types";
import { ACCOUNT_MAX_CONCURRENT_AUDITS, QUOTA_WINDOW_DAYS, auditLimitsByPlan } from "../plans";

/**
 * Llamadas a las funciones SQL de consumo, con sus argumentos con nombre.
 *
 * Las usan el adaptador real (`supabase.rpc(fn, args)`) y las pruebas (que
 * ejecutan la misma función sobre PostgreSQL embebido), así que lo que se
 * prueba es exactamente lo que se envía a Supabase. Los límites y la
 * ventana salen siempre de `lib/plans.ts`, nunca de la petición.
 */
export type RpcCall = { fn: string; args: Record<string, unknown> };

export const quotaRpc = {
  usage: (userId: string, emailHash: string): RpcCall => ({
    fn: "workspace_usage_rolling",
    args: {
      p_user: userId,
      p_limits: auditLimitsByPlan(),
      p_window_days: QUOTA_WINDOW_DAYS,
      p_email_hash: emailHash,
    },
  }),
  reserve: (userId: string, requestId: string, emailHash: string): RpcCall => ({
    fn: "reserve_audit_rolling",
    args: {
      p_user: userId,
      p_request: requestId,
      p_limits: auditLimitsByPlan(),
      p_window_days: QUOTA_WINDOW_DAYS,
      p_max_concurrent: ACCOUNT_MAX_CONCURRENT_AUDITS,
      p_email_hash: emailHash,
    },
  }),
  complete: (usageId: string, hostname: string, report: AuditReport, historySize: number): RpcCall => ({
    fn: "complete_audit",
    args: { p_usage: usageId, p_hostname: hostname, p_report: report, p_history_limit: historySize },
  }),
  finish: (usageId: string, status: "failed" | "released"): RpcCall => ({
    fn: "finish_audit",
    args: { p_usage: usageId, p_status: status },
  }),
  recordDeletion: (userId: string, emailHash: string): RpcCall => ({
    fn: "record_account_deletion_rolling",
    args: { p_user: userId, p_email_hash: emailHash, p_window_days: QUOTA_WINDOW_DAYS },
  }),
};
