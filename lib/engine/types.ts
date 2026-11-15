/**
 * Tipos del WebTrustScan Engine 2.0.
 *
 * Este fichero no importa nada de Node: lo comparten el motor (servidor) y la
 * interfaz (cliente).
 */

export const ENGINE_VERSION = "2.0.0";

/**
 * Estado de una comprobación.
 * - pass / warning / fail: el control se pudo evaluar y PUNTÚA.
 * - info: dato útil que no es ni bueno ni malo. No puntúa.
 * - not_applicable: el control no tiene sentido para este sitio. No puntúa.
 * - not_tested: no se pudo comprobar por causas ajenas al sitio o por alcance.
 * - error: la comprobación falló por un problema del propio análisis.
 *
 * `not_tested` y `error` NUNCA restan puntos: reducen la cobertura.
 */
export type CheckStatus =
  | "pass"
  | "fail"
  | "warning"
  | "info"
  | "not_applicable"
  | "not_tested"
  | "error";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Confianza en la conclusión de un hallazgo. */
export type Confidence = "high" | "medium" | "low";

/** Informes independientes: no se mezclan riesgos de naturaleza distinta. */
export type ReportId = "web" | "dns-email";

export type CategoryId =
  | "transport"
  | "headers"
  | "cookies"
  | "cors"
  | "content"
  | "disclosure"
  | "dns"
  | "email";

/**
 * Tipo de comprobación según la metodología:
 * - passive: se deduce de la respuesta normal que recibiría cualquier visitante.
 * - active: requiere una petición adicional, inocua, formulada a propósito.
 */
export type CheckMethod = "passive" | "active";

export type CheckDefinition = {
  id: string;
  report: ReportId;
  category: CategoryId;
  title: string;
  /** Qué comprueba, en una frase (para el catálogo y la interfaz). */
  summary: string;
  /** Severidad máxima que puede alcanzar un fallo de este control. */
  severity: Severity;
  /** Peso relativo en la puntuación de su informe. 0 = solo informativo. */
  weight: number;
  method: CheckMethod;
  /** Tope de la puntuación global si el control falla (riesgos críticos). */
  capOnFail?: number;
  references: string[];
};

export type Evidence = { label: string; value: string };

export type Finding = {
  id: string;
  report: ReportId;
  category: CategoryId;
  title: string;
  status: CheckStatus;
  /** Severidad de ESTE resultado (puede ser menor que la máxima del control). */
  severity: Severity;
  confidence: Confidence;
  /** Fracción del peso conseguida (0–1). null si el estado no puntúa. */
  credit: number | null;
  weight: number;
  description: string;
  remediation: string | null;
  evidence: Evidence[];
  references: string[];
  method: CheckMethod;
};

export type CategoryScore = {
  category: CategoryId;
  label: string;
  /** null cuando ninguna comprobación de la categoría ha podido puntuar. */
  score: number | null;
  scored: number;
  total: number;
};

export type Grade = "A" | "B" | "C" | "D" | "F";

export type ReportScore = {
  report: ReportId;
  /** 0–100. null si la cobertura es insuficiente para dar una cifra honesta. */
  score: number | null;
  grade: Grade | null;
  /** Puntuación antes de aplicar topes por riesgos críticos. */
  rawScore: number | null;
  cap: { value: number; checkId: string; reason: string } | null;
  /** % (ponderado) de los controles aplicables que se pudieron comprobar. */
  coverage: number;
  /** true si la cobertura es parcial y la cifra debe leerse con cautela. */
  provisional: boolean;
  confidence: Confidence;
  categories: CategoryScore[];
  counts: {
    status: Record<CheckStatus, number>;
    /** Hallazgos abiertos (fail/warning) por severidad. */
    severity: Record<Severity, number>;
  };
  summary: string;
};

/** Cómo respondió el sitio y cuánto se puede confiar en esa respuesta. */
export type ResponseCondition =
  | "ok"
  | "client-error"
  | "auth-required"
  | "rate-limited"
  | "server-error"
  | "blocked";

export type AuditReport = {
  engineVersion: string;
  scannedAt: string;
  durationMs: number;
  target: {
    input: string;
    /** URL final analizada tras seguir redirecciones. */
    url: string;
    host: string;
    httpStatus: number;
    contentType: string | null;
    redirects: { url: string; status: number }[];
    /** CDN / WAF detectado por sus cabeceras, si lo hay. */
    edge: string | null;
    condition: ResponseCondition;
  };
  /** Avisos sobre el propio análisis (no son hallazgos del sitio). */
  notices: string[];
  web: ReportScore;
  dnsEmail: ReportScore;
  findings: Finding[];
};
