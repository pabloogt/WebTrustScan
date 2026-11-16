"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { PASSWORD_MIN_LENGTH } from "@/lib/plans";
import { api, field, messageOf, primaryButton } from "./api";

type Mode = "login" | "register" | "recover";

const NOTICES: Record<string, string> = {
  "enlace-no-valido":
    "El enlace no es válido o ha caducado. Solicita uno nuevo desde aquí.",
  "sesion-cerrada": "Has cerrado sesión.",
  "cuenta-eliminada": "Tu cuenta y sus datos se han eliminado.",
};

const LABEL: Record<Mode, string> = {
  login: "Entrar",
  register: "Crear cuenta",
  recover: "Enviar enlace",
};

export default function AccessForm({ notice }: { notice?: string }) {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState(notice ? (NOTICES[notice] ?? "") : "");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setInfo("");
    setBusy(true);

    try {
      if (mode === "login") {
        await api("/api/auth/login", { method: "POST", body: { email, password } });
        router.push("/panel");
        router.refresh();
        return;
      }

      const { message } = await api<{ message: string }>(
        mode === "register" ? "/api/auth/register" : "/api/auth/recover",
        { method: "POST", body: mode === "register" ? { email, password } : { email } },
      );
      setInfo(message);
      setPassword("");
    } catch (cause) {
      setError(messageOf(cause, "No se pudo completar la operación."));
    }

    setBusy(false);
  };

  const tab = (value: Mode, label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={mode === value}
      onClick={() => {
        setMode(value);
        setError("");
        setInfo("");
      }}
      className={`flex-1 rounded-lg px-3 py-2 text-sm font-medium transition ${
        mode === value ? "bg-white text-slate-900" : "text-slate-300 hover:text-white"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
      <div
        role="tablist"
        aria-label="Acceso"
        className="flex rounded-xl border border-slate-700 bg-slate-950 p-1"
      >
        {tab("login", "Iniciar sesión")}
        {tab("register", "Crear cuenta")}
      </div>

      {mode === "recover" && (
        <p className="mt-5 text-sm text-slate-300">
          Indica tu correo y te enviaremos un enlace para elegir una contraseña
          nueva.
        </p>
      )}

      <form onSubmit={submit} className="mt-6 space-y-4">
        <div>
          <label htmlFor="email" className="mb-1.5 block text-sm text-slate-300">
            Correo electrónico
          </label>
          <input
            id="email"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className={field}
          />
        </div>

        {mode !== "recover" && (
          <div>
            <label htmlFor="password" className="mb-1.5 block text-sm text-slate-300">
              Contraseña
            </label>
            <input
              id="password"
              type="password"
              required
              minLength={mode === "register" ? PASSWORD_MIN_LENGTH : undefined}
              autoComplete={mode === "register" ? "new-password" : "current-password"}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-describedby={mode === "register" ? "password-help" : undefined}
              className={field}
            />
            {mode === "register" && (
              <p id="password-help" className="mt-1.5 text-xs text-slate-500">
                Mínimo {PASSWORD_MIN_LENGTH} caracteres. Mejor una frase larga
                que símbolos raros.
              </p>
            )}
          </div>
        )}

        {error && (
          <p
            role="alert"
            className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            {error}
          </p>
        )}
        {info && (
          <p
            role="status"
            className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-100"
          >
            {info}
          </p>
        )}

        <button type="submit" disabled={busy} className={`${primaryButton} w-full`}>
          {busy ? "Un momento…" : LABEL[mode]}
        </button>
      </form>

      <p className="mt-4 text-center text-sm">
        {mode === "recover" ? (
          <button
            type="button"
            className="text-slate-400 underline hover:text-white"
            onClick={() => setMode("login")}
          >
            Volver a iniciar sesión
          </button>
        ) : (
          <button
            type="button"
            className="text-slate-400 underline hover:text-white"
            onClick={() => {
              setMode("recover");
              setError("");
              setInfo("");
            }}
          >
            He olvidado mi contraseña
          </button>
        )}
      </p>

      {mode === "register" && (
        <p className="mt-4 text-xs leading-relaxed text-slate-500">
          Tendrás que confirmar tu correo antes de poder entrar. La cuenta
          empieza en el plan Free.
        </p>
      )}
    </div>
  );
}
