/**
 * MOTOR 1.x (CONGELADO). La aplicación usa el Engine 2.0 de `lib/engine`.
 * Este módulo se conserva sin cambios funcionales como referencia para el
 * laboratorio (tests/lab), que compara las puntuaciones antiguas y nuevas,
 * y para mantener la suite histórica. No añadir funcionalidad aquí.
 */
import type { AuditCheck, CheckStatus } from "@/types/audit";
import { CHECK_WEIGHTS } from "./checks";

/** Parte del peso que suma cada estado: bien, a medias o nada. */
const CREDIT: Record<CheckStatus, number> = {
  pass: 1,
  warn: 0.5,
  fail: 0,
};

const MAX_SCORE = Object.values(CHECK_WEIGHTS).reduce(
  (sum, weight) => sum + weight,
  0,
);

export function calculateScore(checks: AuditCheck[]): number {
  let score = 0;

  for (const check of checks) {
    const weight = (CHECK_WEIGHTS as Record<string, number>)[check.key];

    if (weight === undefined) {
      // Evita que un check nuevo sin peso pase desapercibido.
      throw new Error(`El check "${check.key}" no tiene peso asignado.`);
    }

    score += weight * CREDIT[check.status];
  }

  return Math.round((score / MAX_SCORE) * 100);
}

export function buildSummary(score: number): string {
  if (score >= 85) {
    return "Tu web tiene una base bastante sólida en seguridad básica y transmite una buena sensación de confianza.";
  }

  if (score >= 70) {
    return "Tu web tiene una base aceptable, aunque todavía hay varios puntos que conviene revisar.";
  }

  if (score >= 50) {
    return "Tu web cumple algunos mínimos, pero muestra varias carencias importantes en seguridad básica y configuración.";
  }

  return "Tu web presenta varias debilidades claras en seguridad básica y confianza. Conviene revisarla cuanto antes.";
}
