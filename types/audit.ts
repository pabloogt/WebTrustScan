export type CheckStatus = "pass" | "warn" | "fail";

export type AuditCheck = {
  key: string;
  title: string;
  status: CheckStatus;
  description: string;
  fix: string | null;
};

export type AuditResult = {
  /** URL final analizada tras seguir redirecciones. */
  url: string;
  /** Código HTTP con el que respondió la URL final. */
  httpStatus: number;
  score: number;
  summary: string;
  checks: AuditCheck[];
};
