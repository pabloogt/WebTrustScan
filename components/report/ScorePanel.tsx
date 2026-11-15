import type { ReportScore } from "@/lib/engine/types";
import {
  CONFIDENCE_LABEL,
  GRADE_COLOR,
  GRADE_LABEL,
  barColor,
} from "./labels";

/*
 * Nota: la CSP de producción no permite estilos en línea (atributo style),
 * así que los anillos y barras se dibujan con atributos SVG.
 */

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreRing({ report }: { report: ReportScore }) {
  const { score, grade } = report;
  const color = grade ? GRADE_COLOR[grade] : null;

  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle
          cx="60"
          cy="60"
          r={RADIUS}
          fill="none"
          strokeWidth="9"
          className="stroke-slate-800"
        />
        {score !== null && color && (
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            fill="none"
            strokeWidth="9"
            strokeLinecap="round"
            strokeDasharray={`${(score / 100) * CIRCUMFERENCE} ${CIRCUMFERENCE}`}
            className={color.stroke}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {score !== null && grade ? (
          <>
            <span className="text-4xl font-bold tabular-nums">{score}</span>
            <span className={`text-sm font-semibold ${color?.text}`}>
              Nota {grade}
            </span>
          </>
        ) : (
          <span className="px-4 text-center text-sm font-medium text-slate-300">
            Sin puntuación
          </span>
        )}
      </div>
    </div>
  );
}

export function Bar({ value, tone }: { value: number; tone: string }) {
  return (
    <svg
      viewBox="0 0 100 6"
      preserveAspectRatio="none"
      className="h-1.5 w-full overflow-hidden rounded-full"
      aria-hidden="true"
    >
      <rect width="100" height="6" className="fill-slate-800" />
      <rect width={Math.max(value, 0)} height="6" className={tone} />
    </svg>
  );
}

function Meter({
  label,
  value,
  help,
  children,
}: {
  label: string;
  value: string;
  help: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      <div className="flex items-baseline justify-between gap-3">
        <p className="text-sm text-slate-400">{label}</p>
        <p className="text-lg font-semibold tabular-nums">{value}</p>
      </div>
      {children && <div className="mt-2">{children}</div>}
      <p className="mt-2 text-xs leading-relaxed text-slate-500">{help}</p>
    </div>
  );
}

export function ScorePanel({
  title,
  report,
}: {
  title: string;
  report: ReportScore;
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-[auto_1fr]">
      <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-center sm:gap-6 lg:flex-col lg:gap-3">
        <ScoreRing report={report} />
        <div className="text-center sm:text-left lg:text-center">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
            {title}
          </p>
          {report.grade && (
            <p className={`mt-1 font-semibold ${GRADE_COLOR[report.grade].text}`}>
              {GRADE_LABEL[report.grade]}
              {report.provisional && (
                <span className="ml-2 rounded-full border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-xs font-medium text-violet-300">
                  provisional
                </span>
              )}
            </p>
          )}
        </div>
      </div>

      <div className="min-w-0 space-y-4">
        <p className="text-slate-200">{report.summary}</p>

        <div className="grid gap-3 sm:grid-cols-2">
          <Meter
            label="Cobertura"
            value={`${report.coverage}%`}
            help="Parte de los controles aplicables que se ha podido comprobar. No mide seguridad: mide cuánto se ha visto."
          >
            <Bar value={report.coverage} tone="fill-sky-400" />
          </Meter>
          <Meter
            label="Confianza del resultado"
            value={CONFIDENCE_LABEL[report.confidence]}
            help="Baja cuando hay conclusiones basadas en indicios o cuando el análisis no ha podido ver la respuesta normal del sitio."
          />
        </div>

        <ul className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
          {report.categories.map((category) => (
            <li key={category.category}>
              <div className="flex items-baseline justify-between gap-3 text-sm">
                <span className="text-slate-300">{category.label}</span>
                <span className="tabular-nums text-slate-400">
                  {category.score !== null
                    ? category.score
                    : category.total > 0 && category.scored === 0
                      ? "sin evaluar"
                      : "—"}
                </span>
              </div>
              <div className="mt-1.5">
                <Bar
                  value={category.score ?? 0}
                  tone={
                    category.score === null
                      ? "fill-slate-700"
                      : barColor(category.score)
                  }
                />
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
