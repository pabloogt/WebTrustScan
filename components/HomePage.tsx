"use client";

import Link from "next/link";
import { FormEvent, useEffect, useRef, useState } from "react";
import ReportView from "@/components/report/ReportView";
import UrlForm from "@/components/UrlForm";
import { usageSummary } from "@/components/account/quotaText";
import {
  CATALOG,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
} from "@/lib/engine/catalog";
import type { AuditReport } from "@/lib/engine/types";
import { normalizeUrl } from "@/lib/normalizeUrl";

/** Devuelve el mensaje de error de validación, o null si la URL es válida. */
function validateUrl(value: string): string | null {
  try {
    normalizeUrl(value);
    return null;
  } catch (error) {
    return error instanceof Error
      ? error.message
      : "La URL no parece válida. Prueba algo como ejemplo.com";
  }
}

const features = [
  {
    title: "Puntuación que se puede explicar",
    description:
      "Cada punto perdido corresponde a un hallazgo concreto, con su severidad y su evidencia. Lo que no aplica a tu web no cuenta.",
  },
  {
    title: "Distingue fallo de «no comprobado»",
    description:
      "Si un WAF bloquea el análisis o el servidor da un error temporal, no te ponemos mala nota: te decimos qué no se pudo ver.",
  },
  {
    title: "Correcciones accionables",
    description:
      "Cada hallazgo incluye la cabecera o el ajuste exacto que lo resuelve, y una vista técnica con las evidencias.",
  },
];

/** «Qué analiza»: se genera a partir del catálogo real del motor. */
const coverage = [...CATEGORY_ORDER.web, ...CATEGORY_ORDER["dns-email"]].map(
  (category) => ({
    category,
    label: CATEGORY_LABELS[category],
    checks: CATALOG.filter((check) => check.category === category),
  }),
);

/** Portada. `accountsEnabled` lo decide el servidor (app/page.tsx). */
export default function HomePage({
  accountsEnabled,
}: {
  accountsEnabled: boolean;
}) {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AuditReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [quota, setQuota] = useState<{
    used: number;
    remaining: number;
    limit: number;
    windowDays: number;
  } | null>(null);
  const reportRef = useRef<HTMLElement>(null);

  // Al terminar un análisis se lleva al usuario al informe.
  useEffect(() => {
    if (result) {
      reportRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [result]);

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    const trimmedUrl = url.trim();

    setErrorMessage("");

    if (!trimmedUrl) {
      setResult(null);
      setErrorMessage("Introduce una URL para poder analizarla.");
      return;
    }

    const validationError = validateUrl(trimmedUrl);

    if (validationError) {
      setResult(null);
      setErrorMessage(validationError);
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        // Identificador único de esta petición: si la red falla y se
        // reintenta, el servidor no consume ni ejecuta el análisis dos veces.
        body: JSON.stringify({ url: trimmedUrl, requestId: crypto.randomUUID() }),
      });

      const data = await response.json().catch(() => null);

      if (!response.ok || !data) {
        throw new Error(data?.error || "No se pudo analizar la URL.");
      }

      setResult(data);
      setQuota(data.quota ?? null);
    } catch (error) {
      console.error(error);
      setResult(null);
      setErrorMessage(
        error instanceof Error
          ? error.message
          : "Ha ocurrido un error al analizar la URL.",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-white">
      {accountsEnabled && (
        <nav
          aria-label="Cuenta"
          className="no-print mx-auto flex w-full max-w-6xl justify-end px-6 pt-6"
        >
          <Link
            href="/panel"
            className="rounded-xl border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-500"
          >
            Mi cuenta
          </Link>
        </nav>
      )}

      <section className="no-print px-6 pt-10 pb-10">
        <div className="mx-auto w-full max-w-6xl">
          <div className="mx-auto max-w-3xl text-center">
            <div className="inline-flex rounded-full border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-300">
              WebTrustScan · auditoría de configuración de seguridad web
            </div>

            <h1 className="mt-6 text-4xl font-bold tracking-tight md:text-6xl">
              Comprueba la configuración de seguridad de tu web, con evidencias
            </h1>

            <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-300">
              Cifrado, cabeceras, cookies, CORS, contenido y correo. Una
              puntuación coherente, qué significa cada hallazgo y cómo
              arreglarlo.
            </p>
          </div>

          <div className="mx-auto mt-10 max-w-4xl">
            <UrlForm
              url={url}
              loading={loading}
              errorMessage={errorMessage}
              onUrlChange={(value) => {
                setUrl(value);
                setErrorMessage("");
              }}
              onSubmit={handleSubmit}
            />
          </div>

          {quota && (
            <p role="status" className="mx-auto mt-4 max-w-4xl text-center text-sm text-slate-400">
              Análisis guardado en tu historial.{" "}
              {usageSummary(quota.used, quota.limit, quota.windowDays)}; te{" "}
              {quota.remaining === 1 ? "queda" : "quedan"} {quota.remaining}.
            </p>
          )}

          {!result && (
            <div className="mx-auto mt-10 grid max-w-5xl gap-4 md:grid-cols-3">
              {features.map((feature) => (
                <div
                  key={feature.title}
                  className="rounded-2xl border border-slate-800 bg-slate-900 p-6"
                >
                  <h2 className="text-lg font-semibold">{feature.title}</h2>
                  <p className="mt-3 text-sm leading-6 text-slate-300">
                    {feature.description}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {result && (
        <section ref={reportRef} className="scroll-mt-6 px-6 py-8">
          <div className="mx-auto w-full max-w-5xl">
            <ReportView report={result} />
          </div>
        </section>
      )}

      <section className="no-print px-6 py-14">
        <div className="mx-auto grid w-full max-w-5xl gap-6 rounded-3xl border border-slate-800 bg-slate-900 p-8 lg:grid-cols-[1.2fr_0.8fr]">
          <div>
            <p className="text-sm uppercase tracking-[0.2em] text-slate-400">
              Qué analiza
            </p>
            <h2 className="mt-3 text-2xl font-bold">
              {CATALOG.length} controles, cada uno con su evidencia
            </h2>
            <p className="mt-4 max-w-2xl text-slate-300">
              WebTrustScan observa tu web como lo haría un visitante: una
              petición normal y, como mucho, cuatro peticiones adicionales
              inocuas y un saludo TLS por versión de protocolo. No intenta explotar nada ni accede a zonas privadas.
            </p>
            <p className="mt-4 max-w-2xl text-sm leading-relaxed text-slate-400">
              No sustituye a una prueba de intrusión ni certifica que una web
              sea segura: mide si su configuración visible sigue las buenas
              prácticas de OWASP, MDN y los RFC aplicables. Analiza solo webs
              tuyas o para las que tengas permiso.
            </p>
          </div>

          <div className="grid gap-3">
            {coverage.map((group) => (
              <details
                key={group.category}
                className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200"
              >
                <summary className="cursor-pointer font-medium list-none">
                  <div className="flex items-center justify-between gap-3">
                    <span>{group.label}</span>
                    <span className="text-slate-500">
                      {group.checks.length} controles
                    </span>
                  </div>
                </summary>

                <ul className="mt-3 space-y-2 text-slate-400">
                  {group.checks.map((check) => (
                    <li key={check.id} className="leading-6">
                      <span className="text-slate-200">{check.title}.</span>{" "}
                      {check.summary}
                    </li>
                  ))}
                </ul>
              </details>
            ))}
          </div>
        </div>
      </section>

      <footer className="no-print border-t border-slate-800 px-6 py-8">
        <div className="mx-auto flex w-full max-w-5xl flex-col gap-3 text-sm text-slate-400 sm:flex-row sm:items-center sm:justify-between">
          <p>WebTrustScan · Engine 2.0</p>
          <p>Auditoría externa de configuración. No es un pentest.</p>
        </div>
      </footer>
    </main>
  );
}
