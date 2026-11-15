import type { CategoryScore, ReportScore } from "./types";

/**
 * Texto del resultado de una categoría. Separa dos cifras que no son lo
 * mismo: cuántos controles están correctos (recuento) y la puntuación
 * ponderada (que depende del peso de cada control). Con menos de tres
 * controles evaluados no se da puntuación ponderada.
 */
export function categoryResult(category: CategoryScore): string {
  if (category.scored === 0) {
    if (category.unverified > 0) return "No comprobado";
    if (category.notApplicable === category.total) return "No aplica";
    return "Solo informativo";
  }

  const counts = `${category.passed} de ${category.scored} ${category.scored === 1 ? "correcto" : "correctos"}`;

  return category.score === null
    ? counts
    : `${counts} · puntuación ponderada ${category.score}/100`;
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

export const COVERAGE_LABEL = "Cobertura del catálogo aplicable";

/** Cómo leer las cifras del informe. Se muestra en la interfaz y en el PDF. */
export const SCORE_NOTES: string[] = [
  "Puntuación ponderada: cada control tiene un peso según su importancia. La puntuación es la suma de los pesos conseguidos entre la suma de los pesos de los controles evaluados, de 0 a 100. No es el porcentaje de controles superados: fallar un control de mucho peso baja más la nota que fallar varios de poco peso.",
  "«N de M correctos» es un recuento simple: de los M controles evaluados, cuántos están bien. Por eso una categoría puede tener «1 de 4 correctos» y una puntuación ponderada distinta del 25 %.",
  "Un control «mejorable» conserva parte de su peso; un «fallo», nada. Si la conclusión es un indicio (confianza media o baja), lo que resta se reduce.",
  "Los controles que no aplican a esta web y los informativos no suman ni restan.",
  "Los controles que no se pudieron comprobar tampoco restan: reducen la cobertura.",
  "Cobertura del catálogo aplicable: parte, en peso, de los controles aplicables de ESTE catálogo que se han podido evaluar. Un 100 % significa que se evaluó todo lo que este análisis sabe comprobar; no significa que se haya auditado toda la seguridad del dominio.",
  "Confianza: indica cuánto se apoya el resultado en pruebas directas. Baja cuando hay hallazgos basados en indicios o cuando no se pudo ver la respuesta normal del sitio.",
  "Algunos fallos graves limitan la nota máxima (por ejemplo, un certificado no válido), con independencia del resto.",
];

/** Alcance real del informe de correo y DNS. */
export const MAIL_SCOPE_NOTE =
  "Evaluación limitada. Este apartado solo comprueba los registros SPF y DMARC publicados en el DNS (y CAA, de forma informativa). No comprueba DKIM, ni si los mensajes enviados realmente superan SPF, DKIM y DMARC, ni DNSSEC, MTA-STS, TLS-RPT o la configuración de los servidores de correo. No es una auditoría completa del correo ni del DNS del dominio.";
