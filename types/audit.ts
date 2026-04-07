export type CheckStatus = "pass" | "warn" | "fail";

export type AuditCheck = {
  key: string;
  title: string;
  status: CheckStatus;
  description: string;
  fix: string | null;
};

export type AuditResult = {
  url: string;
  score: number;
  summary: string;
  checks: AuditCheck[];
};