"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { api } from "./api";

type Mode = "login" | "register";

const field =
  "w-full rounded-xl border border-slate-700 bg-slate-800 px-4 py-3 text-white placeholder:text-slate-500 outline-none focus:border-slate-500";

export default function AccessForm() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setBusy(true);

    try {
      await api(`/api/auth/${mode}`, { method: "POST", body: { email, password } });
      router.push("/panel");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo acceder.");
      setBusy(false);
    }
  };

  const tab = (value: Mode, label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={mode === value}
      onClick={() => {
        setMode(value);
        setError("");
      }}
      className={`flex-1 rounded-lg px-4 py-2 text-sm font-medium transition ${
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

        <div>
          <label htmlFor="password" className="mb-1.5 block text-sm text-slate-300">
            Contraseña
          </label>
          <input
            id="password"
            type="password"
            required
            minLength={mode === "register" ? 10 : undefined}
            autoComplete={mode === "register" ? "new-password" : "current-password"}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            aria-describedby={mode === "register" ? "password-help" : undefined}
            className={field}
          />
          {mode === "register" && (
            <p id="password-help" className="mt-1.5 text-xs text-slate-500">
              Mínimo 10 caracteres. Mejor una frase larga que símbolos raros.
            </p>
          )}
        </div>

        {error && (
          <p
            role="alert"
            className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
          >
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-xl bg-white px-6 py-3 font-semibold text-slate-900 transition hover:bg-slate-200 disabled:opacity-60"
        >
          {busy ? "Un momento…" : mode === "login" ? "Entrar" : "Crear cuenta"}
        </button>
      </form>

      {mode === "register" && (
        <p className="mt-4 text-xs leading-relaxed text-slate-500">
          Al crear la cuenta se crea también tu organización, con el plan
          gratuito: un dominio guardado y sus cinco últimas auditorías.
        </p>
      )}
    </div>
  );
}
