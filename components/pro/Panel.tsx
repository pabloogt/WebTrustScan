"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import ReportView from "@/components/report/ReportView";
import { STATUS_LABEL } from "@/components/report/labels";
import type { AuditReport } from "@/lib/engine/types";
import type { AuditSummary } from "@/lib/pro/audits";
import type { AuditComparison, FindingChange } from "@/lib/pro/compare";
import type { Domain } from "@/lib/pro/domains";
import { ApiError, api, type SessionInfo } from "./api";

const card = "rounded-2xl border border-slate-800 bg-slate-900 p-6";
const button =
  "rounded-xl border border-slate-700 px-3 py-1.5 text-sm font-medium text-slate-200 transition hover:border-slate-500 disabled:opacity-50";
const PLAN_LABEL = { free: "Free", pro: "Pro", agency: "Agency" } as const;

const formatDate = (value: string) =>
  new Date(value).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" });

function Score({ score, grade }: { score: number | null; grade: string | null }) {
  return score === null ? (
    <span className="text-slate-500">Sin puntuación</span>
  ) : (
    <span className="font-semibold tabular-nums">
      {score} <span className="text-slate-400">· {grade}</span>
    </span>
  );
}

function Changes({ title, tone, items }: { title: string; tone: string; items: FindingChange[] }) {
  if (items.length === 0) return null;

  return (
    <div>
      <h4 className={`text-sm font-semibold ${tone}`}>
        {title} ({items.length})
      </h4>
      <ul className="mt-2 space-y-2">
        {items.map((item) => (
          <li key={item.id} className="rounded-xl border border-slate-800 bg-slate-950 p-3 text-sm">
            <p className="font-medium text-slate-100">{item.title}</p>
            <p className="text-xs text-slate-400">
              {item.from ? STATUS_LABEL[item.from] : "—"} → {item.to ? STATUS_LABEL[item.to] : "—"}
            </p>
            <p className="mt-1 text-slate-300">{item.description}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Delta({ label, value }: { label: string; value: number | null }) {
  return (
    <p className="text-sm text-slate-300">
      {label}:{" "}
      <span
        className={`font-semibold ${
          value === null || value === 0
            ? "text-slate-200"
            : value > 0
              ? "text-emerald-300"
              : "text-red-300"
        }`}
      >
        {value === null ? "no comparable" : `${value > 0 ? "+" : ""}${value} puntos`}
      </span>
    </p>
  );
}

export default function Panel() {
  const router = useRouter();
  const [info, setInfo] = useState<SessionInfo | null>(null);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [history, setHistory] = useState<AuditSummary[]>([]);
  const [picked, setPicked] = useState<string[]>([]);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [comparison, setComparison] = useState<AuditComparison | null>(null);
  const [hostname, setHostname] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ kind: "error" | "ok"; text: string } | null>(null);

  /** Ejecuta una acción mostrando su estado y su error, si lo hay. */
  const act = useCallback(
    async (name: string, work: () => Promise<void>) => {
      setBusy(name);
      setMessage(null);

      try {
        await work();
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 401) {
          router.push("/acceso");
          return;
        }
        setMessage({
          kind: "error",
          text: cause instanceof Error ? cause.message : "Ha ocurrido un error.",
        });
      } finally {
        setBusy(null);
      }
    },
    [router],
  );

  const loadDomains = useCallback(async () => {
    setDomains((await api<{ domains: Domain[] }>("/api/domains")).domains);
  }, []);

  const openDomain = useCallback(async (id: string) => {
    setSelected(id);
    setPicked([]);
    setReport(null);
    setComparison(null);
    setHistory(
      (await api<{ audits: AuditSummary[] }>(`/api/domains/${id}/audits`)).audits,
    );
  }, []);

  // Carga inicial: sin sesión, se envía a la pantalla de acceso.
  useEffect(() => {
    let alive = true;

    (async () => {
      try {
        const me = await api<SessionInfo>("/api/auth/me");
        const list = await api<{ domains: Domain[] }>("/api/domains");

        if (alive) {
          setInfo(me);
          setDomains(list.domains);
        }
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 401) {
          router.push("/acceso");
        } else if (alive) {
          setMessage({
            kind: "error",
            text: cause instanceof Error ? cause.message : "No se pudo cargar el panel.",
          });
        }
      }
    })();

    return () => {
      alive = false;
    };
  }, [router]);

  const addDomain = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void act("add", async () => {
      const { domain } = await api<{ domain: Domain }>("/api/domains", {
        method: "POST",
        body: { hostname },
      });
      setHostname("");
      await loadDomains();
      await openDomain(domain.id);
    });
  };

  const audit = (id: string) =>
    act(`audit:${id}`, async () => {
      const result = await api<{ report: AuditReport }>(`/api/domains/${id}/audits`, {
        method: "POST",
      });
      await loadDomains();
      await openDomain(id);
      setReport(result.report);
    });

  const verify = (id: string) =>
    act(`verify:${id}`, async () => {
      const result = await api<{ verified: boolean; method: string | null }>(
        `/api/domains/${id}/verify`,
        { method: "POST" },
      );
      await loadDomains();
      setMessage(
        result.verified
          ? {
              kind: "ok",
              text: `Dominio verificado mediante ${result.method === "dns" ? "el registro TXT" : "el fichero"}.`,
            }
          : {
              kind: "error",
              text: "No se ha encontrado la prueba de verificación. Los cambios de DNS pueden tardar unos minutos.",
            },
      );
    });

  const remove = (domain: Domain) => {
    if (!window.confirm(`¿Eliminar ${domain.hostname} y todo su historial? No se puede deshacer.`)) {
      return;
    }
    void act(`delete:${domain.id}`, async () => {
      await api(`/api/domains/${domain.id}`, { method: "DELETE" });
      if (selected === domain.id) setSelected(null);
      await loadDomains();
    });
  };

  const showAudit = (id: string) =>
    act(`open:${id}`, async () => {
      setComparison(null);
      setReport((await api<{ report: AuditReport }>(`/api/audits/${id}`)).report);
    });

  const compare = () =>
    act("compare", async () => {
      setReport(null);
      setComparison(
        (
          await api<{ comparison: AuditComparison }>(
            `/api/audits/compare?from=${picked[0]}&to=${picked[1]}`,
          )
        ).comparison,
      );
    });

  const logout = () =>
    act("logout", async () => {
      await api("/api/auth/logout", { method: "POST" });
      router.push("/acceso");
    });

  const togglePick = (id: string) =>
    setPicked((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id].slice(-2),
    );

  if (!info) {
    return <p className="text-slate-400">{message?.text ?? "Cargando…"}</p>;
  }

  const current = domains.find((domain) => domain.id === selected) ?? null;
  const { organization, user } = info.session;

  return (
    <div className="space-y-6">
      <header className={`${card} flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between`}>
        <div>
          <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
            Plan {PLAN_LABEL[organization.plan]}
          </p>
          <h1 className="mt-1 text-2xl font-bold">{organization.name}</h1>
          <p className="text-sm text-slate-400">
            {user.email} · {domains.length} de {info.limits.domains}{" "}
            {info.limits.domains === 1 ? "dominio" : "dominios"}
          </p>
        </div>
        <button type="button" onClick={logout} className={button}>
          Cerrar sesión
        </button>
      </header>

      {message && (
        <p
          role={message.kind === "error" ? "alert" : "status"}
          className={`rounded-xl border px-4 py-3 text-sm ${
            message.kind === "error"
              ? "border-red-500/30 bg-red-500/10 text-red-200"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
          }`}
        >
          {message.text}
        </p>
      )}

      <section className={card} aria-label="Dominios">
        <h2 className="text-lg font-semibold">Dominios</h2>

        <form onSubmit={addDomain} className="mt-4 flex flex-col gap-3 sm:flex-row">
          <label htmlFor="new-domain" className="sr-only">
            Dominio que quieres añadir
          </label>
          <input
            id="new-domain"
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
            placeholder="midominio.com"
            autoCapitalize="none"
            spellCheck={false}
            className="flex-1 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-white placeholder:text-slate-500 outline-none focus:border-slate-500"
          />
          <button
            type="submit"
            disabled={busy === "add" || !hostname.trim()}
            className="rounded-xl bg-white px-5 py-2.5 font-semibold text-slate-900 transition hover:bg-slate-200 disabled:opacity-60"
          >
            Añadir dominio
          </button>
        </form>

        {domains.length === 0 ? (
          <p className="mt-6 text-sm text-slate-400">
            Todavía no has guardado ningún dominio. Añade uno para conservar
            sus auditorías y compararlas en el tiempo.
          </p>
        ) : (
          <ul className="mt-6 divide-y divide-slate-800">
            {domains.map((domain) => (
              <li key={domain.id} className="flex flex-col gap-3 py-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                  <p className="break-all font-medium">
                    {domain.hostname}{" "}
                    <span
                      className={`ml-1 rounded-full border px-2 py-0.5 text-xs ${
                        domain.verified
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                          : "border-slate-600 bg-slate-800 text-slate-400"
                      }`}
                    >
                      {domain.verified ? "Verificado" : "Sin verificar"}
                    </span>
                  </p>
                  <p className="mt-1 text-sm text-slate-400">
                    {domain.latestAudit ? (
                      <>
                        <Score score={domain.latestAudit.webScore} grade={domain.latestAudit.webGrade} />{" "}
                        · {formatDate(domain.latestAudit.createdAt)}
                      </>
                    ) : (
                      "Sin auditorías todavía"
                    )}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button type="button" className={button} disabled={busy !== null} onClick={() => audit(domain.id)}>
                    {busy === `audit:${domain.id}` ? "Analizando…" : "Auditar ahora"}
                  </button>
                  <button
                    type="button"
                    className={button}
                    aria-pressed={selected === domain.id}
                    onClick={() => act("history", () => openDomain(domain.id))}
                  >
                    Historial
                  </button>
                  <button type="button" className={button} disabled={busy !== null} onClick={() => remove(domain)}>
                    Eliminar
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {current && (
        <section className={card} aria-label={`Detalle de ${current.hostname}`}>
          <h2 className="break-all text-lg font-semibold">{current.hostname}</h2>

          {!current.verified && (
            <div className="mt-4 rounded-xl border border-slate-700 bg-slate-950 p-4 text-sm">
              <p className="font-medium text-slate-100">Verifica que el dominio es tuyo</p>
              <p className="mt-1 text-slate-400">
                Hará falta para la monitorización y los análisis en profundidad.
                Usa una de estas dos opciones y pulsa «Comprobar».
              </p>
              <dl className="mt-3 space-y-3">
                <div>
                  <dt className="text-xs text-slate-500">Opción 1 · registro DNS de tipo TXT</dt>
                  <dd className="break-all font-mono text-xs text-slate-200">
                    {current.verification.dnsName} → {current.verification.dnsValue}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-slate-500">
                    Opción 2 · fichero en {current.verification.fileUrl} con esta línea
                  </dt>
                  <dd className="break-all font-mono text-xs text-slate-200">
                    {current.verification.dnsValue}
                  </dd>
                </div>
              </dl>
              <button
                type="button"
                className={`${button} mt-4`}
                disabled={busy !== null}
                onClick={() => verify(current.id)}
              >
                {busy === `verify:${current.id}` ? "Comprobando…" : "Comprobar"}
              </button>
            </div>
          )}

          <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
            <h3 className="font-semibold">Historial ({history.length})</h3>
            <button
              type="button"
              className={button}
              disabled={picked.length !== 2 || busy !== null}
              onClick={compare}
            >
              Comparar las dos seleccionadas
            </button>
          </div>

          {history.length === 0 ? (
            <p className="mt-3 text-sm text-slate-400">
              Aún no hay auditorías guardadas de este dominio.
            </p>
          ) : (
            <ul className="mt-3 divide-y divide-slate-800">
              {history.map((item) => (
                <li key={item.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3 text-sm">
                  <input
                    type="checkbox"
                    checked={picked.includes(item.id)}
                    onChange={() => togglePick(item.id)}
                    aria-label={`Seleccionar la auditoría del ${formatDate(item.createdAt)} para comparar`}
                    className="h-4 w-4 accent-white"
                  />
                  <span className="min-w-40 text-slate-300">{formatDate(item.createdAt)}</span>
                  <Score score={item.webScore} grade={item.webGrade} />
                  <span className="text-slate-400">
                    cobertura {item.webCoverage}% · {item.openFindings}{" "}
                    {item.openFindings === 1 ? "hallazgo abierto" : "hallazgos abiertos"}
                  </span>
                  <button type="button" className={`${button} ml-auto`} onClick={() => showAudit(item.id)}>
                    Ver informe
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {comparison && (
        <section className={`${card} space-y-5`} aria-label="Comparación de auditorías">
          <div>
            <h2 className="text-lg font-semibold">Comparación</h2>
            <p className="text-sm text-slate-400">
              {formatDate(comparison.from.scannedAt)} → {formatDate(comparison.to.scannedAt)}
            </p>
          </div>
          <div>
            <Delta label="Seguridad web" value={comparison.webScoreDelta} />
            <Delta label="Correo y DNS" value={comparison.mailScoreDelta} />
          </div>
          {comparison.engineChanged && (
            <p className="rounded-xl border border-violet-500/30 bg-violet-500/10 px-4 py-3 text-sm text-violet-100">
              Las dos auditorías se hicieron con versiones distintas del motor
              ({comparison.from.engineVersion} y {comparison.to.engineVersion}):
              parte de los cambios puede deberse a eso y no a tu web.
            </p>
          )}
          <Changes title="Ha empeorado" tone="text-red-300" items={comparison.regressions} />
          <Changes title="Resuelto" tone="text-emerald-300" items={comparison.resolved} />
          <Changes title="Ha mejorado, pero sigue abierto" tone="text-amber-300" items={comparison.improved} />
          <Changes
            title="No se pudo comprobar esta vez (no es un empeoramiento)"
            tone="text-violet-300"
            items={comparison.unverified}
          />
          <Changes title="Otros cambios sin efecto en la nota" tone="text-slate-300" items={comparison.other} />
          <p className="text-sm text-slate-400">
            {comparison.unchanged} controles sin cambios.
            {comparison.regressions.length + comparison.resolved.length + comparison.improved.length === 0 &&
              " No hay diferencias que afecten a la puntuación."}
          </p>
        </section>
      )}

      {report && <ReportView report={report} />}
    </div>
  );
}
