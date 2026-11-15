import { CATEGORY_LABELS } from "@/lib/engine/catalog";
import type { Finding } from "@/lib/engine/types";
import {
  CONFIDENCE_LABEL,
  SEVERITY_LABEL,
  SEVERITY_STYLE,
  STATUS_ICON,
  STATUS_LABEL,
  STATUS_STYLE,
} from "./labels";

type FindingCardProps = {
  finding: Finding;
  /** Vista técnica: muestra evidencias, confianza y referencias. */
  technical: boolean;
  /** Abre las evidencias (se usa al imprimir). */
  expanded: boolean;
};

const chip =
  "inline-flex w-fit items-center rounded-full border px-2.5 py-0.5 text-xs font-medium";

export default function FindingCard({
  finding,
  technical,
  expanded,
}: FindingCardProps) {
  const open = finding.status === "fail" || finding.status === "warning";

  return (
    <article className="finding rounded-2xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-start gap-4">
        <div
          aria-hidden="true"
          className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full border text-sm font-bold ${STATUS_STYLE[finding.status]}`}
        >
          {STATUS_ICON[finding.status]}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <h3 className="font-semibold">{finding.title}</h3>
              <p className="text-xs text-slate-500">
                {CATEGORY_LABELS[finding.category]}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {open && (
                <span className={`${chip} ${SEVERITY_STYLE[finding.severity]}`}>
                  Severidad {SEVERITY_LABEL[finding.severity].toLowerCase()}
                </span>
              )}
              {open && finding.confidence !== "high" && (
                <span
                  className={`${chip} border-violet-500/30 bg-violet-500/10 text-violet-200`}
                  title="Esta conclusión se basa en indicios, no en una prueba directa. Penaliza menos en la puntuación."
                >
                  Indicio · confianza{" "}
                  {CONFIDENCE_LABEL[finding.confidence].toLowerCase()}
                </span>
              )}
              <span className={`${chip} ${STATUS_STYLE[finding.status]}`}>
                {STATUS_LABEL[finding.status]}
              </span>
            </div>
          </div>

          <p className="mt-3 text-sm leading-relaxed text-slate-300">
            {finding.description}
          </p>

          {finding.remediation && (
            <div className="mt-4 rounded-xl border border-slate-700/60 bg-slate-800/60 p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                {open ? "Cómo solucionarlo" : "Recomendación"}
              </p>
              <p className="mt-1 text-sm leading-relaxed text-slate-200">
                {finding.remediation}
              </p>
            </div>
          )}

          {/* En el resumen, la evidencia de cada problema va a la vista. */}
          {!technical && open && finding.evidence.length > 0 && (
            <dl className="mt-4 space-y-1.5 border-l-2 border-slate-700 pl-3">
              {finding.evidence.slice(0, 4).map((item, index) => (
                <div key={`${item.label}-${index}`}>
                  <dt className="text-xs text-slate-500">{item.label}</dt>
                  <dd className="break-all font-mono text-xs text-slate-300">
                    {item.value}
                  </dd>
                </div>
              ))}
              {finding.evidence.length > 4 && (
                <p className="text-xs text-slate-500">
                  +{finding.evidence.length - 4} más en la vista técnica
                </p>
              )}
            </dl>
          )}

          {technical && (
            <details
              className="mt-4 text-sm"
              open={expanded || open || undefined}
              key={expanded ? "open" : "closed"}
            >
              <summary className="cursor-pointer text-slate-400 hover:text-slate-200">
                Detalles técnicos
                {finding.evidence.length > 0 &&
                  ` · ${finding.evidence.length} evidencia${finding.evidence.length === 1 ? "" : "s"}`}
              </summary>

              <div className="mt-3 space-y-3">
                {finding.evidence.length > 0 && (
                  <dl className="space-y-2 rounded-xl border border-slate-800 bg-slate-950 p-3">
                    {finding.evidence.map((item, index) => (
                      <div key={`${item.label}-${index}`}>
                        <dt className="text-xs text-slate-500">{item.label}</dt>
                        <dd className="break-all font-mono text-xs text-slate-200">
                          {item.value}
                        </dd>
                      </div>
                    ))}
                  </dl>
                )}

                <p className="text-xs leading-relaxed text-slate-500">
                  <span className="font-mono">{finding.id}</span>
                  {" · "}
                  Comprobación{" "}
                  {finding.method === "passive"
                    ? "pasiva (respuesta normal del sitio)"
                    : "activa no intrusiva (una petición adicional)"}
                  {" · "}Confianza {CONFIDENCE_LABEL[finding.confidence].toLowerCase()}
                  {finding.weight > 0
                    ? ` · Peso ${finding.weight}`
                    : " · No puntúa"}
                  {finding.credit !== null &&
                    finding.status === "warning" &&
                    ` · Crédito ${Math.round(finding.credit * 100)}%`}
                </p>
                <p className="text-xs leading-relaxed text-slate-500">
                  Referencias: {finding.references.join(" · ")}
                </p>
              </div>
            </details>
          )}
        </div>
      </div>
    </article>
  );
}
