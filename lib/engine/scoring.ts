import { CATALOG, CATEGORY_LABELS, CATEGORY_ORDER, getDefinition } from "./catalog";
import type { CheckId } from "./catalog";
import type {
  CategoryScore,
  CheckStatus,
  Confidence,
  Finding,
  Grade,
  ReportId,
  ReportScore,
  Severity,
} from "./types";

/**
 * Modelo de puntuación del Engine 2.0 (ver SCORING_MODEL.md).
 *
 * 1. Solo puntúan los controles evaluados: pass, warning y fail.
 * 2. Cada control aporta `peso × crédito`. Lo que se pierde se atenúa por la
 *    confianza del hallazgo: una conclusión dudosa penaliza menos.
 * 3. La puntuación es lo conseguido entre lo aplicable y comprobado, así que
 *    un control no aplicable ni suma ni resta.
 * 4. Lo que no se pudo comprobar (not_tested / error) no resta puntos: baja
 *    la COBERTURA. Con cobertura insuficiente no se da cifra.
 * 5. Un fallo crítico limita la nota máxima (tope), para que el resto de
 *    aciertos no lo diluyan.
 */

export const CONFIDENCE_FACTOR: Record<Confidence, number> = {
  high: 1,
  medium: 0.75,
  low: 0.5,
};

/** Por debajo de esta cobertura no se publica una puntuación. */
export const MIN_COVERAGE_FOR_SCORE = 50;
/** Por debajo de esta cobertura la puntuación se marca como provisional. */
export const FULL_COVERAGE_THRESHOLD = 85;

/**
 * Un fallo confirmado de severidad alta es incompatible con la nota máxima,
 * por muchos otros controles que se cumplan.
 */
export const HIGH_SEVERITY_CAP = 89;

/**
 * Mínimo de controles evaluados para publicar una puntuación. Con menos, una
 * cifra de 0 a 100 aparenta una precisión que no tiene (p. ej. un informe de
 * correo con un único control daría 0 o 100).
 */
export const MIN_SCORED_CHECKS: Record<ReportId, number> = {
  web: 6,
  "dns-email": 2,
};

/** Mínimo de controles evaluados para dar un porcentaje por categoría. */
export const MIN_SCORED_PER_CATEGORY = 3;

const SCORED: ReadonlySet<CheckStatus> = new Set(["pass", "warning", "fail"]);
const UNVERIFIED: ReadonlySet<CheckStatus> = new Set(["not_tested", "error"]);

export function gradeFor(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

/** Puntos conseguidos por un hallazgo que puntúa. */
function earned(finding: Finding): number {
  const credit = finding.credit ?? 0;
  const lost = finding.weight * (1 - credit);

  return finding.weight - lost * CONFIDENCE_FACTOR[finding.confidence];
}

function ratio(findings: Finding[]): number | null {
  const scored = findings.filter(
    (finding) => SCORED.has(finding.status) && finding.weight > 0,
  );
  const total = scored.reduce((sum, finding) => sum + finding.weight, 0);

  if (total === 0) return null;

  return (scored.reduce((sum, finding) => sum + earned(finding), 0) / total) * 100;
}

function emptyCounts() {
  return {
    status: {
      pass: 0,
      fail: 0,
      warning: 0,
      info: 0,
      not_applicable: 0,
      not_tested: 0,
      error: 0,
    } as Record<CheckStatus, number>,
    severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<
      Severity,
      number
    >,
  };
}

function summarize(
  report: ReportId,
  score: number | null,
  grade: Grade | null,
  coverage: number,
  cap: ReportScore["cap"],
  withheld: ReportScore["withheld"],
  evaluated: number,
): string {
  if (withheld === "controls") {
    return evaluated === 0
      ? "Ningún control de este informe ha podido evaluarse."
      : `Solo ${evaluated === 1 ? "se ha evaluado 1 control" : `se han evaluado ${evaluated} controles`} con peso en este informe. Son demasiado pocos para resumirlos en una nota: consulta el resultado de cada uno.`;
  }

  if (score === null || grade === null) {
    return coverage === 0
      ? "No se ha podido comprobar ningún control de este informe."
      : `Solo se ha podido comprobar el ${coverage}% de los controles aplicables. No es suficiente para dar una puntuación fiable.`;
  }

  if (cap) {
    return `Puntuación limitada a ${cap.value} por un problema ${cap.value < HIGH_SEVERITY_CAP ? "crítico" : "de severidad alta"}: ${cap.reason}`;
  }

  const subject =
    report === "web" ? "La configuración de seguridad web" : "La autenticación del correo";

  switch (grade) {
    case "A":
      return `${subject} es sólida en los controles comprobados.`;
    case "B":
      return `${subject} es buena, con algunos puntos de mejora.`;
    case "C":
      return `${subject} cubre lo esencial, pero deja protecciones importantes sin activar.`;
    case "D":
      return `${subject} tiene carencias relevantes que conviene corregir.`;
    default:
      return `${subject} presenta debilidades graves.`;
  }
}

export function scoreReport(report: ReportId, all: Finding[]): ReportScore {
  const findings = all.filter((finding) => finding.report === report);
  const counts = emptyCounts();

  let evaluated = 0;
  let scoredWeight = 0;
  let unverifiedWeight = 0;
  let confidenceWeighted = 0;
  let cap: ReportScore["cap"] = null;

  for (const finding of findings) {
    counts.status[finding.status] += 1;

    if (finding.status === "fail" || finding.status === "warning") {
      counts.severity[finding.severity] += 1;
    }

    if (finding.weight === 0) continue;

    if (SCORED.has(finding.status)) {
      evaluated += 1;
      scoredWeight += finding.weight;
      confidenceWeighted += finding.weight * CONFIDENCE_FACTOR[finding.confidence];
    } else if (UNVERIFIED.has(finding.status)) {
      unverifiedWeight += finding.weight;
    }

    const capOnFail =
      getDefinition(finding.id as CheckId).capOnFail ??
      (finding.severity === "high" && finding.confidence === "high"
        ? HIGH_SEVERITY_CAP
        : undefined);

    if (
      finding.status === "fail" &&
      capOnFail !== undefined &&
      (cap === null || capOnFail < cap.value)
    ) {
      cap = { value: capOnFail, checkId: finding.id, reason: finding.description };
    }
  }

  const applicable = scoredWeight + unverifiedWeight;
  const coverage =
    applicable === 0 ? 0 : Math.round((scoredWeight / applicable) * 100);

  const rawRatio = ratio(findings);
  const rawScore = rawRatio === null ? null : Math.round(rawRatio);
  const withheld: ReportScore["withheld"] =
    rawScore === null || evaluated < MIN_SCORED_CHECKS[report]
      ? applicable > 0 && coverage < MIN_COVERAGE_FOR_SCORE
        ? "coverage"
        : "controls"
      : coverage < MIN_COVERAGE_FOR_SCORE
        ? "coverage"
        : null;
  const publishable = rawScore !== null && withheld === null;
  const score = publishable
    ? Math.min(rawScore, cap ? cap.value : 100)
    : null;
  const grade = score === null ? null : gradeFor(score);
  // El tope solo se declara cuando realmente ha rebajado la puntuación.
  const appliedCap =
    score !== null && cap && rawScore !== null && rawScore > cap.value
      ? cap
      : null;

  const averageConfidence =
    scoredWeight === 0 ? 0 : confidenceWeighted / scoredWeight;
  const overall = averageConfidence * (coverage / 100);
  const confidence: Confidence =
    overall >= 0.85 ? "high" : overall >= 0.6 ? "medium" : "low";

  const categories: CategoryScore[] = CATEGORY_ORDER[report].map((category) => {
    const own = findings.filter((finding) => finding.category === category);
    const value = ratio(own);
    const weighted = own.filter(
      (finding) => SCORED.has(finding.status) && finding.weight > 0,
    );

    return {
      category,
      label: CATEGORY_LABELS[category],
      score:
        value === null || weighted.length < MIN_SCORED_PER_CATEGORY
          ? null
          : Math.round(value),
      scored: weighted.length,
      passed: weighted.filter((finding) => finding.status === "pass").length,
      notApplicable: own.filter((finding) => finding.status === "not_applicable")
        .length,
      unverified: own.filter((finding) => UNVERIFIED.has(finding.status)).length,
      total: own.length,
    };
  });

  return {
    report,
    score,
    grade,
    rawScore,
    cap: appliedCap,
    coverage,
    provisional: score !== null && coverage < FULL_COVERAGE_THRESHOLD,
    withheld,
    evaluated,
    confidence,
    categories,
    counts,
    summary: summarize(
      report,
      score,
      grade,
      coverage,
      appliedCap,
      withheld,
      evaluated,
    ),
  };
}

/** Garantiza que cada check del catálogo produce exactamente un hallazgo. */
export function assertCompleteFindings(findings: Finding[]): void {
  const seen = new Set(findings.map((finding) => finding.id));

  if (seen.size !== findings.length) {
    throw new Error("Hay hallazgos duplicados para un mismo check.");
  }

  for (const definition of CATALOG) {
    if (!seen.has(definition.id)) {
      throw new Error(`El check "${definition.id}" no ha producido resultado.`);
    }
  }
}
