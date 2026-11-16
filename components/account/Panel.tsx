"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import ReportView from "@/components/report/ReportView";
import type { AuditSummary } from "@/lib/accounts/ports";
import type { AccountOverview } from "@/lib/accounts/service";
import type { AuditReport } from "@/lib/engine/types";
import { PASSWORD_MIN_LENGTH, PLANS } from "@/lib/plans";
import {
  ApiError,
  api,
  card,
  field,
  messageOf,
  primaryButton,
  secondaryButton,
} from "./api";

type Tab = "resumen" | "configuracion" | "plan";
type Notice = { kind: "error" | "ok"; text: string } | null;

const formatDate = (value: string) =>
  new Date(value).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" });
const formatDay = (value: string) =>
  new Date(value).toLocaleDateString("es-ES", { dateStyle: "long", timeZone: "UTC" });

function UsageBar({ used, total }: { used: number; total: number }) {
  const share = total === 0 ? 0 : Math.min(100, (used / total) * 100);

  // La CSP no permite estilos en línea: la barra se dibuja con SVG.
  return (
    <svg viewBox="0 0 100 6" preserveAspectRatio="none" className="h-2 w-full overflow-hidden rounded-full" aria-hidden="true">
      <rect width="100" height="6" className="fill-slate-800" />
      <rect width={share} height="6" className={share >= 100 ? "fill-red-400" : "fill-sky-400"} />
    </svg>
  );
}

function Message({ notice }: { notice: Notice }) {
  if (!notice) return null;

  return (
    <p
      role={notice.kind === "error" ? "alert" : "status"}
      className={`rounded-xl border px-4 py-3 text-sm ${
        notice.kind === "error"
          ? "border-red-500/30 bg-red-500/10 text-red-200"
          : "border-emerald-500/30 bg-emerald-500/10 text-emerald-100"
      }`}
    >
      {notice.text}
    </p>
  );
}

export default function Panel() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("resumen");
  const [account, setAccount] = useState<AccountOverview | null>(null);
  const [audits, setAudits] = useState<AuditSummary[]>([]);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [displayName, setDisplayName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [emailPassword, setEmailPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");

  /** Ejecuta una acción mostrando su estado y su error. Sin sesión, a /acceso. */
  const act = useCallback(
    async (name: string, work: () => Promise<void>) => {
      setBusy(name);
      setNotice(null);

      try {
        await work();
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 401) {
          router.push("/acceso");
          return;
        }
        setNotice({ kind: "error", text: messageOf(cause) });
      } finally {
        setBusy(null);
      }
    },
    [router],
  );

  const load = useCallback(async () => {
    const [overview, list] = await Promise.all([
      api<AccountOverview>("/api/account"),
      api<{ audits: AuditSummary[] }>("/api/audits"),
    ]);
    setAccount(overview);
    setDisplayName(overview.profile.displayName ?? "");
    setAudits(list.audits);
  }, []);

  // Carga inicial. Sin sesión, a la pantalla de acceso.
  useEffect(() => {
    let alive = true;

    (async () => {
      try {
        const [overview, list] = await Promise.all([
          api<AccountOverview>("/api/account"),
          api<{ audits: AuditSummary[] }>("/api/audits"),
        ]);

        if (alive) {
          setAccount(overview);
          setDisplayName(overview.profile.displayName ?? "");
          setAudits(list.audits);
        }
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 401) {
          router.push("/acceso");
        } else if (alive) {
          setNotice({ kind: "error", text: messageOf(cause, "No se pudo cargar el panel.") });
        }
      }
    })();

    return () => {
      alive = false;
    };
  }, [router]);

  const openAudit = (id: string) =>
    act(`open:${id}`, async () => {
      setReport((await api<{ report: AuditReport }>(`/api/audits/${id}`)).report);
    });

  const removeAudit = (audit: AuditSummary) => {
    if (
      !window.confirm(
        `¿Eliminar del historial el análisis de ${audit.hostname}? No recuperarás el análisis consumido.`,
      )
    ) {
      return;
    }
    void act(`delete:${audit.id}`, async () => {
      await api(`/api/audits/${audit.id}`, { method: "DELETE" });
      setReport(null);
      await load();
    });
  };

  const logout = (scope: "one" | "all") =>
    act("logout", async () => {
      await api("/api/auth/logout", { method: "POST", body: { scope } });
      router.push("/acceso?estado=sesion-cerrada");
      router.refresh();
    });

  const saveName = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void act("name", async () => {
      await api("/api/account", { method: "PATCH", body: { displayName } });
      await load();
      setNotice({ kind: "ok", text: "Nombre actualizado." });
    });
  };

  const saveEmail = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void act("email", async () => {
      const { message } = await api<{ message: string }>("/api/account/email", {
        method: "POST",
        body: { email: newEmail, currentPassword: emailPassword },
      });
      setNewEmail("");
      setEmailPassword("");
      setNotice({ kind: "ok", text: message });
    });
  };

  const savePassword = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void act("password", async () => {
      await api("/api/account/password", {
        method: "POST",
        body: { password: newPassword, currentPassword },
      });
      setCurrentPassword("");
      setNewPassword("");
      setNotice({
        kind: "ok",
        text: "Contraseña cambiada. Se han cerrado las demás sesiones de tu cuenta.",
      });
    });
  };

  const removeAccount = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void act("remove", async () => {
      await api("/api/account/delete", {
        method: "POST",
        body: { password: deletePassword, confirm: deleteConfirm },
      });
      router.push("/acceso?estado=cuenta-eliminada");
      router.refresh();
    });
  };

  if (!account) {
    return notice ? <Message notice={notice} /> : <p className="text-slate-400">Cargando…</p>;
  }

  const { usage, plan, user } = account;
  const tabButton = (value: Tab, label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={tab === value}
      onClick={() => {
        setTab(value);
        setNotice(null);
      }}
      className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
        tab === value ? "bg-white text-slate-900" : "text-slate-300 hover:text-white"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="space-y-6">
      <header className={`${card} flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between`}>
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-400">
            Plan {plan.label}
          </p>
          <h1 className="mt-1 break-all text-2xl font-bold">
            {account.profile.displayName || user.email}
          </h1>
          <p className="break-all text-sm text-slate-400">{user.email}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link href="/" className={secondaryButton}>
            Nuevo análisis
          </Link>
          <button type="button" onClick={() => logout("one")} className={secondaryButton}>
            Cerrar sesión
          </button>
        </div>
      </header>

      <div
        role="tablist"
        aria-label="Secciones de la cuenta"
        className="no-print flex w-fit rounded-xl border border-slate-700 bg-slate-950 p-1"
      >
        {tabButton("resumen", "Resumen")}
        {tabButton("configuracion", "Configuración")}
        {tabButton("plan", "Plan")}
      </div>

      <Message notice={notice} />

      {tab === "resumen" && (
        <>
          <section className={card} aria-label="Consumo del periodo">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 className="text-lg font-semibold">Análisis de este periodo</h2>
              <p className="text-2xl font-bold tabular-nums">
                {usage.used}{" "}
                <span className="text-base font-normal text-slate-400">
                  de {plan.monthlyAudits}
                </span>
              </p>
            </div>
            <div className="mt-3">
              <UsageBar used={usage.used} total={plan.monthlyAudits} />
            </div>
            <p className="mt-3 text-sm text-slate-400">
              {usage.remaining > 0
                ? `Te quedan ${usage.remaining}.`
                : "Has usado todos los análisis de este periodo."}{" "}
              El contador se reinicia el {formatDay(usage.periodEnd)} (UTC). Borrar
              análisis del historial no devuelve los ya consumidos.
            </p>
          </section>

          <section className={card} aria-label="Historial de análisis">
            <h2 className="text-lg font-semibold">
              Historial{" "}
              <span className="text-sm font-normal text-slate-400">
                · se conservan los {plan.historySize} más recientes
              </span>
            </h2>

            {audits.length === 0 ? (
              <p className="mt-4 text-sm text-slate-400">
                Todavía no has hecho ningún análisis con tu cuenta.{" "}
                <Link href="/" className="underline hover:text-white">
                  Analiza una web
                </Link>{" "}
                y aparecerá aquí.
              </p>
            ) : (
              <ul className="mt-4 divide-y divide-slate-800">
                {audits.map((audit) => (
                  <li key={audit.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3 text-sm">
                    <span className="min-w-0 flex-1 break-all font-medium">{audit.hostname}</span>
                    <span className="tabular-nums">
                      {audit.webScore === null ? (
                        <span className="text-slate-500">Sin puntuación</span>
                      ) : (
                        <>
                          {audit.webScore}{" "}
                          <span className="text-slate-400">· {audit.webGrade}</span>
                        </>
                      )}
                    </span>
                    <span className="text-slate-400">{formatDate(audit.createdAt)}</span>
                    <span className="flex gap-2">
                      <button type="button" className={secondaryButton} disabled={busy !== null} onClick={() => openAudit(audit.id)}>
                        Ver informe
                      </button>
                      <button type="button" className={secondaryButton} disabled={busy !== null} onClick={() => removeAudit(audit)}>
                        Eliminar
                      </button>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {report && <ReportView report={report} />}
        </>
      )}

      {tab === "configuracion" && (
        <>
          <form onSubmit={saveName} className={`${card} space-y-3`}>
            <h2 className="text-lg font-semibold">Nombre visible</h2>
            <label htmlFor="display-name" className="sr-only">
              Nombre visible
            </label>
            <input
              id="display-name"
              value={displayName}
              maxLength={80}
              onChange={(event) => setDisplayName(event.target.value)}
              placeholder="Cómo quieres que te llamemos"
              className={field}
            />
            <button type="submit" disabled={busy !== null} className={primaryButton}>
              Guardar
            </button>
          </form>

          <form onSubmit={saveEmail} className={`${card} space-y-3`}>
            <h2 className="text-lg font-semibold">Correo electrónico</h2>
            <p className="text-sm text-slate-400">
              Actual: <span className="break-all text-slate-200">{user.email}</span>
              {user.pendingEmail && (
                <> · pendiente de confirmar: <span className="break-all text-amber-200">{user.pendingEmail}</span></>
              )}
            </p>
            <label htmlFor="new-email" className="block text-sm text-slate-300">
              Correo nuevo
            </label>
            <input id="new-email" type="email" required autoComplete="email" value={newEmail} onChange={(event) => setNewEmail(event.target.value)} className={field} />
            <label htmlFor="email-password" className="block text-sm text-slate-300">
              Tu contraseña actual
            </label>
            <input id="email-password" type="password" required autoComplete="current-password" value={emailPassword} onChange={(event) => setEmailPassword(event.target.value)} className={field} />
            <button type="submit" disabled={busy !== null} className={primaryButton}>
              Cambiar correo
            </button>
            <p className="text-xs text-slate-500">
              El cambio no se aplica hasta que confirmes el enlace que te enviaremos.
            </p>
          </form>

          <form onSubmit={savePassword} className={`${card} space-y-3`}>
            <h2 className="text-lg font-semibold">Contraseña</h2>
            <label htmlFor="current-password" className="block text-sm text-slate-300">
              Contraseña actual
            </label>
            <input id="current-password" type="password" required autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} className={field} />
            <label htmlFor="next-password" className="block text-sm text-slate-300">
              Contraseña nueva (mínimo {PASSWORD_MIN_LENGTH} caracteres)
            </label>
            <input id="next-password" type="password" required minLength={PASSWORD_MIN_LENGTH} autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} className={field} />
            <button type="submit" disabled={busy !== null} className={primaryButton}>
              Cambiar contraseña
            </button>
          </form>

          <section className={`${card} space-y-3`}>
            <h2 className="text-lg font-semibold">Sesiones y datos</h2>
            <p className="text-sm text-slate-400">
              Si has entrado desde un equipo que no es tuyo, cierra todas las
              sesiones. También puedes descargar todo lo que guardamos de tu cuenta.
            </p>
            <div className="flex flex-wrap gap-2">
              <button type="button" className={secondaryButton} disabled={busy !== null} onClick={() => logout("all")}>
                Cerrar todas las sesiones
              </button>
              <a href="/api/account/export" download className={secondaryButton}>
                Descargar mis datos (JSON)
              </a>
            </div>
          </section>

          <form onSubmit={removeAccount} className={`${card} space-y-3 border-red-500/30`}>
            <h2 className="text-lg font-semibold text-red-200">Eliminar la cuenta</h2>
            <p className="text-sm text-slate-400">
              Se borran tu perfil, tu historial de análisis y tu acceso. No se
              puede deshacer.
            </p>
            <label htmlFor="delete-password" className="block text-sm text-slate-300">
              Tu contraseña
            </label>
            <input id="delete-password" type="password" required autoComplete="current-password" value={deletePassword} onChange={(event) => setDeletePassword(event.target.value)} className={field} />
            <label htmlFor="delete-confirm" className="block text-sm text-slate-300">
              Escribe ELIMINAR para confirmar
            </label>
            <input id="delete-confirm" required value={deleteConfirm} onChange={(event) => setDeleteConfirm(event.target.value)} autoComplete="off" className={field} />
            <button
              type="submit"
              disabled={busy !== null || deleteConfirm !== "ELIMINAR"}
              className="rounded-xl border border-red-500/40 px-5 py-2.5 font-semibold text-red-200 transition hover:bg-red-500/10 disabled:opacity-50"
            >
              Eliminar mi cuenta
            </button>
          </form>
        </>
      )}

      {tab === "plan" && (
        <section className={`${card} space-y-5`} aria-label="Plan">
          <div>
            <h2 className="text-lg font-semibold">Tu plan: {plan.label}</h2>
            <p className="mt-1 text-sm text-slate-400">
              {usage.used} de {plan.monthlyAudits} análisis usados en este periodo,
              que termina el {formatDay(usage.periodEnd)} (UTC).
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-96 text-left text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th scope="col" className="py-2 pr-4 font-medium">Incluye</th>
                  {Object.values(PLANS).map((entry) => (
                    <th key={entry.plan} scope="col" className="py-2 pr-4 font-medium">
                      {entry.label}
                      {entry.plan === plan.id && (
                        <span className="ml-2 rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-xs text-sky-200">
                          actual
                        </span>
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                <tr>
                  <th scope="row" className="py-2 pr-4 font-normal text-slate-300">Análisis por periodo</th>
                  {Object.values(PLANS).map((entry) => (
                    <td key={entry.plan} className="py-2 pr-4 tabular-nums">{entry.monthlyAudits}</td>
                  ))}
                </tr>
                <tr>
                  <th scope="row" className="py-2 pr-4 font-normal text-slate-300">Análisis guardados en el historial</th>
                  {Object.values(PLANS).map((entry) => (
                    <td key={entry.plan} className="py-2 pr-4 tabular-nums">{entry.historySize}</td>
                  ))}
                </tr>
                <tr>
                  <th scope="row" className="py-2 pr-4 font-normal text-slate-300">Informes completos y PDF</th>
                  {Object.values(PLANS).map((entry) => (
                    <td key={entry.plan} className="py-2 pr-4">Sí</td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>

          {plan.id === "free" && (
            <div className="rounded-xl border border-slate-700 bg-slate-950 p-4">
              <p className="font-medium text-slate-100">Pro todavía no está disponible</p>
              <p className="mt-1 text-sm text-slate-400">
                Estamos preparando el plan Pro. Aún no se puede contratar ni
                tiene precio definido; cuando lo esté, aparecerá aquí.
              </p>
              <button
                type="button"
                disabled
                aria-disabled="true"
                className="mt-3 cursor-not-allowed rounded-xl border border-slate-700 px-5 py-2.5 text-sm font-semibold text-slate-500"
              >
                Pro · próximamente
              </button>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
