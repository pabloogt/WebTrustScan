/**
 * Textos de consumo. Funciones puras: se usan en el panel y en la portada y
 * se prueban sin navegador.
 *
 * El servidor trabaja y responde en UTC (ISO 8601). Aquí se muestran las
 * fechas en la zona horaria del navegador del usuario, indicándola.
 */

/** «3 de 5 análisis utilizados en los últimos 7 días». */
export function usageSummary(used: number, limit: number, windowDays: number): string {
  return `${used} de ${limit} análisis utilizados en los últimos ${windowDays} días`;
}

/**
 * Fecha y hora en la zona horaria del usuario, con su abreviatura:
 * «24 de noviembre de 2026, 19:05 CET». `timeZone` solo se pasa en pruebas.
 */
export function formatLocalDateTime(iso: string, timeZone?: string): string {
  return new Date(iso).toLocaleString("es-ES", {
    day: "numeric",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
    timeZone,
  });
}

/** Explicación de cuándo se libera el próximo uso, o null si no hay ninguno. */
export function releaseText(
  usage: { remaining: number; nextReleaseAt: string | null; availableAt: string | null },
  timeZone?: string,
): string | null {
  if (usage.remaining <= 0 && usage.availableAt) {
    return `Podrás hacer otro análisis a partir del ${formatLocalDateTime(usage.availableAt, timeZone)}.`;
  }
  if (usage.nextReleaseAt) {
    return `El próximo uso se libera el ${formatLocalDateTime(usage.nextReleaseAt, timeZone)}.`;
  }
  return null;
}
