import { randomUUID } from "node:crypto";
import { AuditError } from "../audit/errors";
import { runAudit } from "../engine/run";
import type { AuditReport } from "../engine/types";
import type { SessionContext } from "./auth";
import { compareReports, type AuditComparison } from "./compare";
import { isUuid, type Db } from "./db";
import { getDomain } from "./domains";
import { ProError, notFound } from "./errors";
import { PLAN_LIMITS, hasRole } from "./plans";

export type AuditSummary = {
  id: string;
  domainId: string;
  engineVersion: string;
  webScore: number | null;
  webGrade: string | null;
  webCoverage: number;
  mailScore: number | null;
  openFindings: number;
  createdAt: string;
};

type AuditRow = {
  id: string;
  domain_id: string;
  engine_version: string;
  web_score: number | null;
  web_grade: string | null;
  web_coverage: number;
  mail_score: number | null;
  open_findings: number;
  created_at: Date | string;
  report?: AuditReport | string;
};

const SUMMARY_COLUMNS =
  "id, domain_id, engine_version, web_score, web_grade, web_coverage, mail_score, open_findings, created_at";

function toSummary(row: AuditRow): AuditSummary {
  return {
    id: row.id,
    domainId: row.domain_id,
    engineVersion: row.engine_version,
    webScore: row.web_score,
    webGrade: row.web_grade,
    webCoverage: row.web_coverage,
    mailScore: row.mail_score,
    openFindings: row.open_findings,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

const parseReport = (value: AuditReport | string): AuditReport =>
  typeof value === "string" ? (JSON.parse(value) as AuditReport) : value;

export type AuditDeps = {
  /** Ejecuta el análisis. Inyectable para el laboratorio. */
  run?: (hostname: string) => Promise<AuditReport>;
  now?: () => Date;
};

/**
 * Analiza un dominio de la organización y guarda el informe.
 * El destino es siempre el nombre de host guardado, nunca una URL libre.
 */
export async function runDomainAudit(
  db: Db,
  session: SessionContext,
  domainId: unknown,
  deps: AuditDeps = {},
): Promise<{ summary: AuditSummary; report: AuditReport }> {
  if (!hasRole(session.role, "member")) {
    throw new ProError(403, "Tu rol no permite lanzar auditorías.");
  }

  const { id: organizationId, plan } = session.organization;
  const limits = PLAN_LIMITS[plan];
  const domain = await getDomain(db, organizationId, domainId);
  const now = (deps.now ?? (() => new Date()))();

  const [{ count }] = await db.query<{ count: number }>(
    "select count(*)::int as count from audits where organization_id = $1 and created_at > $2",
    [organizationId, new Date(now.getTime() - 3_600_000).toISOString()],
  );

  if (count >= limits.auditsPerHour) {
    throw new ProError(
      429,
      `Tu plan permite ${limits.auditsPerHour} auditorías guardadas por hora. Vuelve a intentarlo más tarde.`,
    );
  }

  let report: AuditReport;

  try {
    report = await (deps.run ?? runAudit)(domain.hostname);
  } catch (error) {
    if (error instanceof AuditError) {
      // No se guarda nada: no hay informe que conservar.
      throw new ProError(error.httpStatus === 400 ? 400 : 409, error.message);
    }
    throw error;
  }

  const id = randomUUID();
  const open = report.findings.filter(
    (finding) => finding.status === "fail" || finding.status === "warning",
  ).length;

  await db.query(
    `insert into audits (id, organization_id, domain_id, created_by, engine_version,
                         web_score, web_grade, web_coverage, mail_score, open_findings, report, created_at)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)`,
    [
      id,
      organizationId,
      domain.id,
      session.user.id,
      report.engineVersion,
      report.web.score,
      report.web.grade,
      report.web.coverage,
      report.dnsEmail.score,
      open,
      JSON.stringify(report),
      now.toISOString(),
    ],
  );

  // Retención: solo se conservan las N auditorías más recientes del dominio.
  await db.query(
    `delete from audits
      where domain_id = $1 and organization_id = $2 and id not in (
        select id from audits
         where domain_id = $1 and organization_id = $2
         order by created_at desc
         limit $3
      )`,
    [domain.id, organizationId, limits.storedAuditsPerDomain],
  );

  const [row] = await db.query<AuditRow>(
    `select ${SUMMARY_COLUMNS} from audits where id = $1 and organization_id = $2`,
    [id, organizationId],
  );

  return { summary: toSummary(row), report };
}

export async function listAudits(
  db: Db,
  organizationId: string,
  domainId: unknown,
): Promise<AuditSummary[]> {
  const domain = await getDomain(db, organizationId, domainId);
  const rows = await db.query<AuditRow>(
    `select ${SUMMARY_COLUMNS} from audits
      where domain_id = $1 and organization_id = $2
      order by created_at desc`,
    [domain.id, organizationId],
  );

  return rows.map(toSummary);
}

/** Devuelve la auditoría SOLO si pertenece a la organización indicada. */
export async function getAudit(
  db: Db,
  organizationId: string,
  auditId: unknown,
): Promise<{ summary: AuditSummary; report: AuditReport }> {
  if (!isUuid(auditId)) throw notFound("La auditoría");

  const [row] = await db.query<AuditRow>(
    `select ${SUMMARY_COLUMNS}, report from audits where id = $1 and organization_id = $2`,
    [auditId, organizationId],
  );

  if (!row?.report) throw notFound("La auditoría");

  return { summary: toSummary(row), report: parseReport(row.report) };
}

export async function compareAudits(
  db: Db,
  organizationId: string,
  fromId: unknown,
  toId: unknown,
): Promise<AuditComparison> {
  const [from, to] = await Promise.all([
    getAudit(db, organizationId, fromId),
    getAudit(db, organizationId, toId),
  ]);

  if (from.summary.domainId !== to.summary.domainId) {
    throw new ProError(400, "Solo se pueden comparar auditorías del mismo dominio.");
  }

  // Siempre de la más antigua a la más reciente.
  return from.summary.createdAt <= to.summary.createdAt
    ? compareReports(from.report, to.report)
    : compareReports(to.report, from.report);
}
