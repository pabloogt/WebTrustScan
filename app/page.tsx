"use client";

import { FormEvent, useState } from "react";
import ChecksList from "@/components/ChecksList";
import ScoreOverview from "@/components/ScoreOverview";
import UrlForm from "@/components/UrlForm";
import { AuditResult } from "@/types/audit";

function isProbablyValidUrl(value: string) {
  const trimmed = value.trim();

  if (!trimmed) return false;

  try {
    const candidate =
      trimmed.startsWith("http://") || trimmed.startsWith("https://")
        ? trimmed
        : `https://${trimmed}`;

    const parsed = new URL(candidate);
    return Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

const features = [
  {
    title: "Análisis en segundos",
    description:
      "Introduce una URL y obtén una revisión rápida de señales básicas de seguridad y confianza.",
  },
  {
    title: "Resultados claros",
    description:
      "Entiende qué está bien, qué falla y qué deberías priorizar sin perderte en lenguaje técnico.",
  },
  {
    title: "Correcciones accionables",
    description:
      "Cada hallazgo incluye una recomendación concreta para que sepas cómo empezar a arreglarlo.",
  },
];

const checksPreview = [
  {
    title: "HTTPS activo",
    description:
      "Comprueba si la web usa una conexión segura para proteger los datos del usuario.",
  },
  {
    title: "Redirección de HTTP a HTTPS",
    description:
      "Revisa si la versión insegura de la web redirige automáticamente a la versión segura.",
  },
  {
    title: "Strict-Transport-Security",
    description:
      "Indica si el navegador debe recordar que esta web solo debe abrirse con conexión segura.",
  },
  {
    title: "Content-Security-Policy",
    description:
      "Ayuda a limitar scripts y recursos peligrosos que podrían cargarse en la web.",
  },
  {
    title: "X-Frame-Options",
    description:
      "Protege la web para que no pueda mostrarse dentro de páginas maliciosas.",
  },
  {
    title: "X-Content-Type-Options",
    description:
      "Evita que el navegador interprete archivos de una forma insegura.",
  },
  {
    title: "Referrer-Policy",
    description:
      "Controla qué información comparte el navegador cuando el usuario sale a otra web.",
  },
  {
    title: "Permissions-Policy",
    description:
      "Limita permisos del navegador como cámara, micrófono o ubicación.",
  },
];

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    const trimmedUrl = url.trim();

    setErrorMessage("");

    if (!trimmedUrl) {
      setResult(null);
      setErrorMessage("Introduce una URL para poder analizarla.");
      return;
    }

    if (!isProbablyValidUrl(trimmedUrl)) {
      setResult(null);
      setErrorMessage("La URL no parece válida. Prueba algo como ejemplo.com");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: trimmedUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "No se pudo analizar la URL.");
      }

      setResult(data);
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
      <section className="px-6 pt-16 pb-10">
        <div className="mx-auto w-full max-w-6xl">
          <div className="mx-auto max-w-3xl text-center">
            <div className="inline-flex rounded-full border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-slate-300">
              WebTrustScan · revisión básica de seguridad web
            </div>

            <h1 className="mt-6 text-4xl font-bold tracking-tight md:text-6xl">
              Detecta en minutos si tu web falla en seguridad básica y confianza
            </h1>

            <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-300">
              WebTrustScan analiza tu web y te muestra de forma clara los fallos
              básicos que pueden afectar a la seguridad, la configuración y la
              confianza que transmite.
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
        <section className="px-6 py-8">
          <div className="mx-auto w-full max-w-5xl space-y-6">
            <ScoreOverview result={result} />
            <ChecksList checks={result.checks} />
          </div>
        </section>
      )}

      <section className="px-6 py-14">
        <div className="mx-auto grid w-full max-w-5xl gap-6 rounded-3xl border border-slate-800 bg-slate-900 p-8 lg:grid-cols-[1.2fr_0.8fr]">
          <div>
            <p className="text-sm uppercase tracking-[0.2em] text-slate-400">
              Qué analiza
            </p>
            <h2 className="mt-3 text-2xl font-bold">
              Una revisión inicial pensada para detectar fallos básicos rápido
            </h2>
            <p className="mt-4 max-w-2xl text-slate-300">
              WebTrustScan no sustituye una auditoría profesional completa, pero
              sí te ayuda a detectar rápidamente errores comunes de
              configuración que pueden debilitar la seguridad básica de una web
              o hacer que transmita menos confianza.
            </p>
          </div>

          <div className="grid gap-3">
            {checksPreview.map((item, index) => (
              <details
                key={index}
                className="rounded-xl border border-slate-800 bg-slate-950 px-4 py-3 text-sm text-slate-200"
              >
                <summary className="cursor-pointer font-medium list-none">
                  <div className="flex items-center justify-between gap-3">
                    <span>{item.title}</span>
                    <span className="text-slate-500">+</span>
                  </div>
                </summary>

                <p className="mt-3 text-slate-400 leading-6">
                  {item.description}
                </p>
              </details>
            ))}
          </div>
        </div>
      </section>

      <footer className="border-t border-slate-800 px-6 py-8">
        <div className="mx-auto flex w-full max-w-5xl flex-col gap-3 text-sm text-slate-400 sm:flex-row sm:items-center sm:justify-between">
          <p>WebTrustScan · MVP inicial</p>
          <p>
            Auditoría básica para detectar fallos de seguridad y confianza web
          </p>
        </div>
      </footer>
    </main>
  );
}
