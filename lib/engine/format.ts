import type { CategoryScore, ReportScore } from "./types";

/**
 * Texto del resultado de una categoría. Con menos de tres controles
 * evaluados no se da porcentaje: «1 de 1» es honesto, «100 %» no.
 */
export function categoryResult(category: CategoryScore): string {
  if (category.scored === 0) {
    if (category.unverified > 0) return "No comprobado";
    if (category.notApplicable === category.total) return "No aplica";
    return "Solo informativo";
  }

  const counts = `${category.passed} de ${category.scored} ${category.scored === 1 ? "correcto" : "correctos"}`;

  return category.score === null ? counts : `${counts} · ${category.score}/100`;
}

/** «17 evaluados · 3 no aplican · 1 no comprobado». */
export function controlCounts(report: ReportScore): string {
  const { status } = report.counts;
  const unverified = status.not_tested + status.error;
  const parts = [
    `${report.evaluated} ${report.evaluated === 1 ? "control evaluado" : "controles evaluados"}`,
  ];

  if (status.not_applicable > 0) {
    parts.push(
      `${status.not_applicable} no ${status.not_applicable === 1 ? "aplica" : "aplican"}`,
    );
  }
  if (unverified > 0) {
    parts.push(
      `${unverified} no ${unverified === 1 ? "comprobado" : "comprobados"}`,
    );
  }
  if (status.info > 0) {
    parts.push(`${status.info} ${status.info === 1 ? "informativo" : "informativos"}`);
  }

  return parts.join(" · ");
}
