"use client";

import { useEffect, useState } from "react";
import { REPORT_LABELS } from "@/lib/engine/catalog";
import { MAIL_SCOPE_NOTE } from "@/lib/engine/format";
import type { AuditReport, Finding, ReportId } from "@/lib/engine/types";
import FindingCard from "./FindingCard";
import { SEVERITY_LABEL, SEVERITY_ORDER, SEVERITY_STYLE } from "./labels";
import { ScorePanel } from "./ScorePanel";

type View = "executive" | "technical";

const card = "rounded-2xl border border-slate-800 bg-slate-900 p-6";

function bySeverity(a: Finding, b: Finding): number {
  return (
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    b.weight - a.weight
  );
}

function Group({
  title,
  hint,
  findings,
  technical,
  expanded,
  collapsible = false,
}: {
  title: string;
  hint?: string;
  findings: Finding[];
  technical: boolean;
  expanded: boolean;
  collapsible?: boolean;
}) {
  if (findings.length === 0) return null;

  const list = (
    <div className="mt-4 space-y-3">
      {findings.map((finding) => (
        <FindingCard
          key={finding.id}
          finding={finding}
          technical={technical}
          expanded={expanded}
        />
      ))}
    </div>
  );
  const heading = (
    <>
      <span className="text-lg font-semibold">{title}</span>
      <span className="ml-2 rounded-full bg-slate-800 px-2.5 py-0.5 text-sm tabular-nums text-slate-300">
        {findings.length}
      </span>
    </>
  );

  return (
    <section>
      {collapsible ? (
        <details open={expanded || undefined} key={expanded ? "open" : "closed"}>
          <summary className="cursor-pointer list-none">
            {heading}
            <span className="ml-2 text-sm text-slate-500">mostrar</span>
            {hint && <p className="mt-1 text-sm text-slate-400">{hint}</p>}
          </summary>
          {list}
        </details>
      ) : (
        <>
          <h3>{heading}</h3>
          {hint && <p className="mt-1 text-sm text-slate-400">{hint}</p>}
          {list}
        </>
      )}
    </section>
  );
}

function ReportSection({
  id,
  report,
  view,
  expanded,
}: {
  id: ReportId;
  report: AuditReport;
  view: View;
  expanded: boolean;
}) {
  const score = id === "web" ? report.web : report.dnsEmail;
  const own = report.findings.filter((finding) => finding.report === id);
  const technical = view === "technical";

  const open = own
    .filter((f) => f.status === "fail" || f.status === "warning")
    .sort(bySeverity);
  const unverified = own.filter(
    (f) => f.status === "not_tested" || f.status === "error",
  );
  const passed = own.filter((f) => f.status === "pass");
  const neutral = own.filter(
    (f) => f.status === "info" || f.status === "not_applicable",
  );

  return (
    <section className="space-y-6" aria-label={REPORT_LABELS[id]}>
      <div className={card}>
        <ScorePanel title={REPORT_LABELS[id]} report={score} />

        {open.length > 0 && (
          <div className="mt-6 flex flex-wrap items-center gap-2 border-t border-slate-800 pt-4 text-sm">
            <span className="text-slate-400">Hallazgos abiertos:</span>
            {SEVERITY_ORDER.filter((s) => score.counts.severity[s] > 0).map((s) => (
              <span
                key={s}
                className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${SEVERITY_STYLE[s]}`}
              >
                {score.counts.severity[s]} · {SEVERITY_LABEL[s].toLowerCase()}
              </span>
            ))}
          </div>
        )}
      </div>

      <Group
        title={technical ? "Problemas detectados" : "Qué conviene arreglar primero"}
        hint={
          technical
            ? "Ordenados por severidad."
            : open.length > 5
              ? `Se muestran los 5 más importantes de ${open.length}. Cambia a la vista técnica para verlos todos.`
              : undefined
        }
        findings={technical ? open : open.slice(0, 5)}
        technical={technical}
        expanded={expanded}
      />

      {open.length === 0 && score.score !== null && (
        <p className={`${card} text-sm text-emerald-200`}>
          No se ha detectado ningún problema en los controles comprobados de
          este informe.
        </p>
      )}

      <Group
        title="No se pudo comprobar"
        hint="Estos controles no restan puntos: reducen la cobertura. No significan que la web tenga un problema."
        findings={unverified}
        technical={technical}
        expanded={expanded}
      />

      {technical && (
        <>
          <Group
            title="Correcto"
            findings={passed}
            technical
            expanded={expanded}
            collapsible
          />
          <Group
            title="No aplica o informativo"
            hint="No afectan a la puntuación."
            findings={neutral}
            technical
            expanded={expanded}
            collapsible
          />
        </>
      )}

      {!technical && (
        <p className="text-sm text-slate-400">
          {passed.length === 1
            ? "1 control correcto"
            : `${passed.length} controles correctos`}
          {neutral.length > 0 &&
            ` · ${neutral.length} que no aplican a esta web o son informativos`}
          . El detalle está en la vista técnica.
        </p>
      )}
    </section>
  );
}

const CONDITION_LABEL: Record<AuditReport["target"]["condition"], string> = {
  ok: "Respuesta normal",
  "client-error": "Página de error",
  "auth-required": "Requiere autenticación",
  "rate-limited": "Límite de peticiones",
  "server-error": "Error temporal del servidor",
  blocked: "Bloqueado por WAF/CDN",
};

export default function ReportView({ report }: { report: AuditReport }) {
  const [view, setView] = useState<View>("executive");
  const [printing, setPrinting] = useState(false);
  const scanned = new Date(report.scannedAt);

  // Para el PDF se despliega todo el detalle técnico antes de imprimir.
  useEffect(() => {
    if (!printing) return;

    const done = () => setPrinting(false);
    window.addEventListener("afterprint", done, { once: true });
    const frame = requestAnimationFrame(() => window.print());

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("afterprint", done);
    };
  }, [printing]);

  const [pdfState, setPdfState] = useState<"idle" | "working" | "error">("idle");

  const save = (blob: Blob, name: string) => {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = name;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  // El PDF se genera en el navegador: el informe no se envía a ningún servidor.
  const downloadPdf = async () => {
    setPdfState("working");

    try {
      const { buildReportPdf, pdfFileName } = await import("@/lib/report/pdf");
      const bytes = await buildReportPdf(report);

      save(
        new Blob([bytes.buffer as ArrayBuffer], { type: "application/pdf" }),
        pdfFileName(report),
      );
      setPdfState("idle");
    } catch (error) {
      console.error(error);
      setPdfState("error");
    }
  };

  const exportJson = () => {
    save(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
      `webtrustscan-${report.target.host}-${report.scannedAt.slice(0, 10)}.json`,
    );
  };

  const tab = (value: View, label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={view === value}
      onClick={() => setView(value)}
      className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
        view === value
          ? "bg-white text-slate-900"
          : "text-slate-300 hover:text-white"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="report space-y-8">
      <header className={card}>
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
              Informe de configuración de seguridad
            </p>
            <h2 className="mt-2 break-all text-2xl font-bold">
              {report.target.host}
            </h2>
            <p className="mt-1 break-all text-sm text-slate-400">
              {report.target.url}
            </p>
          </div>

          <div className="no-print flex flex-wrap gap-2">
            <div
              role="tablist"
              aria-label="Tipo de vista"
              className="flex rounded-xl border border-slate-700 bg-slate-950 p-1"
            >
              {tab("executive", "Resumen")}
              {tab("technical", "Técnica")}
            </div>
            <button
              type="button"
              onClick={downloadPdf}
              disabled={pdfState === "working"}
              className="rounded-xl border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-500 disabled:opacity-60"
            >
              {pdfState === "working" ? "Generando PDF…" : "Descargar PDF"}
            </button>
            <button
              type="button"
              onClick={() => {
                setView("technical");
                setPrinting(true);
              }}
              className="rounded-xl border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-500 disabled:opacity-60"
            >
              Imprimir
            </button>
            <button
              type="button"
              onClick={exportJson}
              className="rounded-xl border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-500"
            >
              Exportar JSON
            </button>
          </div>
        </div>

        {pdfState === "error" && (
          <p role="alert" className="no-print mt-3 text-sm text-red-300">
            No se ha podido generar el PDF. Prueba con «Imprimir» y elige
            «Guardar como PDF».
          </p>
        )}

        <dl className="mt-5 grid gap-x-8 gap-y-3 border-t border-slate-800 pt-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <div>
            <dt className="text-slate-500">Respuesta</dt>
            <dd className="text-slate-200">
              HTTP {report.target.httpStatus} ·{" "}
              {CONDITION_LABEL[report.target.condition]}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Fecha del análisis</dt>
            <dd className="text-slate-200">
              {scanned.toLocaleString("es-ES", {
                dateStyle: "medium",
                timeStyle: "short",
              })}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Intermediario</dt>
            <dd className="text-slate-200">
              {report.target.edge ?? "No detectado"}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Motor</dt>
            <dd className="text-slate-200">
              WebTrustScan Engine {report.engineVersion}
            </dd>
          </div>
        </dl>

        {view === "technical" && report.target.redirects.length > 1 && (
          <p className="mt-4 break-all font-mono text-xs text-slate-400">
            {report.target.redirects
              .map((hop) => `${hop.status} ${hop.url}`)
              .join("  →  ")}
          </p>
        )}

        {report.notices.length > 0 && (
          <ul role="status" className="mt-5 space-y-2">
            {report.notices.map((notice) => (
              <li
                key={notice}
                className="rounded-xl border border-violet-500/30 bg-violet-500/10 px-4 py-3 text-sm leading-relaxed text-violet-100"
              >
                {notice}
              </li>
            ))}
          </ul>
        )}
      </header>

      <ReportSection id="web" report={report} view={view} expanded={printing} />

      <div className="border-t border-slate-800 pt-8">
        <p className="mb-4 text-sm text-slate-400">
          <strong className="text-slate-200">Informe independiente.</strong>{" "}
          La autenticación del correo y el DNS no forman parte de la seguridad
          de la web: miden si alguien puede suplantar tu dominio al enviar
          correo. Tienen su propia nota y no alteran la de arriba.
        </p>
        <p
          role="note"
          className="mb-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm leading-relaxed text-amber-100"
        >
          {MAIL_SCOPE_NOTE}
        </p>
        <ReportSection
          id="dns-email"
          report={report}
          view={view}
          expanded={printing}
        />
      </div>

      <footer className={`${card} text-xs leading-relaxed text-slate-400`}>
        <p className="font-semibold text-slate-300">Alcance y límites</p>
        <p className="mt-2">
          Este informe evalúa la configuración de seguridad observable desde
          fuera, sin autenticarse y con un máximo de cinco peticiones
          inocuas (más un saludo TLS por versión de protocolo). No es una prueba de intrusión ni una certificación: no
          analiza el código, la lógica de la aplicación, las zonas con inicio
          de sesión ni el contenido que la web genera con JavaScript. Una
          puntuación alta indica una buena configuración en los controles
          comprobados, no la ausencia de vulnerabilidades.
        </p>
      </footer>
    </div>
  );
}
