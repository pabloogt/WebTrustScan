import type {
  CheckStatus,
  Confidence,
  Grade,
  Severity,
} from "@/lib/engine/types";

export const STATUS_LABEL: Record<CheckStatus, string> = {
  pass: "Correcto",
  fail: "Fallo",
  warning: "Mejorable",
  info: "Informativo",
  not_applicable: "No aplica",
  not_tested: "No comprobado",
  error: "Error del análisis",
};

export const STATUS_ICON: Record<CheckStatus, string> = {
  pass: "✓",
  fail: "✕",
  warning: "!",
  info: "i",
  not_applicable: "–",
  not_tested: "?",
  error: "?",
};

export const STATUS_STYLE: Record<CheckStatus, string> = {
  pass: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  fail: "border-red-500/30 bg-red-500/10 text-red-300",
  warning: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  info: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  not_applicable: "border-slate-600 bg-slate-800 text-slate-400",
  not_tested: "border-violet-500/30 bg-violet-500/10 text-violet-300",
  error: "border-violet-500/30 bg-violet-500/10 text-violet-300",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Informativa",
};

export const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-200",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-200",
  medium: "border-amber-500/40 bg-amber-500/15 text-amber-200",
  low: "border-slate-500/50 bg-slate-700/60 text-slate-200",
  info: "border-slate-600 bg-slate-800 text-slate-300",
};

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

export const GRADE_LABEL: Record<Grade, string> = {
  A: "Sólida",
  B: "Buena",
  C: "Aceptable",
  D: "Mejorable",
  F: "Deficiente",
};

/** Color (trazo SVG y texto) de cada nota. */
export const GRADE_COLOR: Record<Grade, { stroke: string; text: string }> = {
  A: { stroke: "stroke-emerald-400", text: "text-emerald-300" },
  B: { stroke: "stroke-lime-400", text: "text-lime-300" },
  C: { stroke: "stroke-amber-400", text: "text-amber-300" },
  D: { stroke: "stroke-orange-400", text: "text-orange-300" },
  F: { stroke: "stroke-red-400", text: "text-red-300" },
};

export function barColor(score: number): string {
  if (score >= 90) return "fill-emerald-400";
  if (score >= 75) return "fill-lime-400";
  if (score >= 60) return "fill-amber-400";
  if (score >= 40) return "fill-orange-400";
  return "fill-red-400";
}
