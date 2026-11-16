"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { PASSWORD_MIN_LENGTH } from "@/lib/plans";
import { api, card, field, messageOf, primaryButton } from "./api";

/** Contraseña nueva tras abrir un enlace de recuperación. */
export default function NewPasswordForm() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");

    if (password !== repeat) {
      setError("Las dos contraseñas no coinciden.");
      return;
    }

    setBusy(true);

    try {
      await api("/api/account/password", { method: "POST", body: { password } });
      router.push("/panel");
      router.refresh();
    } catch (cause) {
      setError(messageOf(cause));
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className={`${card} space-y-4`}>
      <div>
        <label htmlFor="new-password" className="mb-1.5 block text-sm text-slate-300">
          Contraseña nueva
        </label>
        <input
          id="new-password"
          type="password"
          required
          minLength={PASSWORD_MIN_LENGTH}
          autoComplete="new-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className={field}
        />
      </div>
      <div>
        <label htmlFor="repeat-password" className="mb-1.5 block text-sm text-slate-300">
          Repite la contraseña
        </label>
        <input
          id="repeat-password"
          type="password"
          required
          autoComplete="new-password"
          value={repeat}
          onChange={(event) => setRepeat(event.target.value)}
          className={field}
        />
      </div>

      {error && (
        <p
          role="alert"
          className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {error}
        </p>
      )}

      <button type="submit" disabled={busy} className={`${primaryButton} w-full`}>
        {busy ? "Guardando…" : "Guardar contraseña"}
      </button>
      <p className="text-xs text-slate-500">
        Al cambiarla se cerrarán las demás sesiones abiertas de tu cuenta.
      </p>
    </form>
  );
}
