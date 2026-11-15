import type { AuditReport, CheckStatus, Finding, Severity } from "../engine/types";

export type FindingChange = {
  id: string;
  title: string;
  from: CheckStatus | null;
  to: CheckStatus | null;
  severity: Severity;
  description: string;
};

export type AuditComparison = {
  from: { scannedAt: string; engineVersion: string };
  to: { scannedAt: string; engineVersion: string };
  /** Diferencia de puntuación (null si alguna de las dos no tiene cifra). */
  webScoreDelta: number | null;
  mailScoreDelta: number | null;
  /** Controles que han empeorado. */
  regressions: FindingChange[];
  /** Controles que han pasado a estar correctos. */
  resolved: FindingChange[];
  /** Controles que siguen abiertos pero han mejorado (fallo → mejorable). */
  improved: FindingChange[];
  /** Controles que antes se evaluaron y ahora no se han podido comprobar. */
  unverified: FindingChange[];
  /** Otros cambios de estado sin efecto en la puntuación. */
  other: FindingChange[];
  unchanged: number;
  /** true si los motores difieren: parte de los cambios pueden deberse a ello. */
  engineChanged: boolean;
};

/** Gravedad de un estado evaluado. null = el estado no puntúa. */
const RANK: Partial<Record<CheckStatus, number>> = { pass: 0, warning: 1, fail: 2 };

const delta = (a: number | null, b: number | null) =>
  a === null || b === null ? null : b - a;

/**
 * Compara dos informes del mismo dominio control a control.
 *
 * Un control que pasa a «no comprobado» NO es una regresión: significa que
 * el análisis no pudo verlo (bloqueo, error temporal), no que la web haya
 * empeorado. Se informa aparte para no generar falsas alarmas.
 */
export function compareReports(
  before: AuditReport,
  after: AuditReport,
): AuditComparison {
  const previous = new Map(before.findings.map((finding) => [finding.id, finding]));
  const comparison: AuditComparison = {
    from: { scannedAt: before.scannedAt, engineVersion: before.engineVersion },
    to: { scannedAt: after.scannedAt, engineVersion: after.engineVersion },
    webScoreDelta: delta(before.web.score, after.web.score),
    mailScoreDelta: delta(before.dnsEmail.score, after.dnsEmail.score),
    regressions: [],
    resolved: [],
    improved: [],
    unverified: [],
    other: [],
    unchanged: 0,
    engineChanged: before.engineVersion !== after.engineVersion,
  };

  const change = (finding: Finding, from: Finding | undefined): FindingChange => ({
    id: finding.id,
    title: finding.title,
    from: from?.status ?? null,
    to: finding.status,
    severity: finding.severity,
    description: finding.description,
  });

  for (const finding of after.findings) {
    const old = previous.get(finding.id);
    previous.delete(finding.id);

    if (old && old.status === finding.status) {
      comparison.unchanged += 1;
      continue;
    }

    const was = old ? RANK[old.status] : undefined;
    const is = RANK[finding.status];
    const entry = change(finding, old);

    if (is !== undefined && was !== undefined) {
      if (is > was) comparison.regressions.push(entry);
      else if (is === 0) comparison.resolved.push(entry);
      else comparison.improved.push(entry);
    } else if (
      was !== undefined &&
      (finding.status === "not_tested" || finding.status === "error")
    ) {
      comparison.unverified.push(entry);
    } else if (is !== undefined && is > 0 && old) {
      // Antes no se evaluaba (no aplicaba, no comprobado) y ahora falla.
      comparison.regressions.push(entry);
    } else {
      comparison.other.push(entry);
    }
  }

  // Controles que existían en el informe antiguo y ya no (cambio de motor).
  for (const old of previous.values()) {
    comparison.other.push({
      id: old.id,
      title: old.title,
      from: old.status,
      to: null,
      severity: old.severity,
      description: "Este control ya no forma parte del catálogo del motor.",
    });
  }

  return comparison;
}
