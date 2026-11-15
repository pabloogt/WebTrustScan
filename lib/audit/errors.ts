export type AuditErrorCode =
  | "INVALID_URL"
  | "BLOCKED_TARGET"
  | "UNREACHABLE"
  | "TLS_ERROR"
  | "TIMEOUT"
  | "TOO_MANY_REDIRECTS";

const HTTP_STATUS: Record<AuditErrorCode, number> = {
  INVALID_URL: 400,
  BLOCKED_TARGET: 400,
  UNREACHABLE: 502,
  TLS_ERROR: 502,
  TIMEOUT: 504,
  TOO_MANY_REDIRECTS: 502,
};

/**
 * Error esperado durante un análisis. El mensaje es seguro para mostrarlo
 * al usuario (no contiene detalles internos).
 */
export class AuditError extends Error {
  readonly code: AuditErrorCode;
  /**
   * Causa técnica de bajo nivel (p. ej. "ECONNREFUSED", "ENOTFOUND"). Permite
   * al motor distinguir "puerto cerrado" de "no responde" sin exponer detalles
   * al usuario.
   */
  readonly reason: string | null;

  constructor(code: AuditErrorCode, message: string, reason?: string | null) {
    super(message);
    this.name = "AuditError";
    this.code = code;
    this.reason = reason ?? null;
  }

  get httpStatus(): number {
    return HTTP_STATUS[this.code];
  }
}
