"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useSyncExternalStore, useState } from "react";
import { ApiError, api, card, messageOf, primaryButton, secondaryButton } from "./api";

type Props = {
  tokenHash?: string;
  type?: string;
  code?: string;
  next?: string;
  /** Error que Supabase añade a la URL cuando rechaza el enlace. */
  errorCode?: string;
};

const TITLE: Record<string, string> = {
  recovery: "Restablecer la contraseña",
  email: "Confirmar tu cuenta",
  signup: "Confirmar tu cuenta",
  email_change: "Confirmar tu nuevo correo",
};

const BUTTON: Record<string, string> = {
  recovery: "Elegir una contraseña nueva",
  email: "Confirmar y entrar",
  signup: "Confirmar y entrar",
  email_change: "Confirmar el cambio",
};

const RECOVERY_PATH = "/cuenta/nueva-contrasena";

/** Supabase también puede dejar el error en el fragmento (#error_code=…). */
function hashError(): string {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return params.get("error_code") ?? params.get("error") ?? "";
}

const noSubscription = () => () => {};

export default function ConfirmLink({ tokenHash, type, code, next, errorCode }: Props) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ expired: boolean; text: string } | null>(null);
  const fragmentError = useSyncExternalStore(noSubscription, hashError, () => "");

  const kind = type && TITLE[type] ? type : next === RECOVERY_PATH ? "recovery" : "email";
  const isRecovery = kind === "recovery";
  const providerError = errorCode || fragmentError;
  const usable = Boolean((tokenHash && type) || code) && !providerError;

  const confirm = async () => {
    setBusy(true);
    setFailure(null);

    try {
      const result = await api<{ next: string }>("/api/auth/confirm", {
        method: "POST",
        body: tokenHash && type ? { tokenHash, type, next } : { code, next },
      });
      router.replace(result.next);
      router.refresh();
    } catch (cause) {
      setFailure({
        expired: cause instanceof ApiError && cause.data.code === "link_expired",
        text: messageOf(cause),
      });
      setBusy(false);
    }
  };

  const requestAnother = (
    <Link
      href={isRecovery ? "/acceso?modo=recuperar" : "/acceso"}
      className={`${primaryButton} inline-block text-center`}
    >
      {isRecovery ? "Solicitar otro enlace" : "Ir a la pantalla de acceso"}
    </Link>
  );

  if (!usable || failure?.expired) {
    const expired = failure?.expired || /expired|otp|access_denied/i.test(providerError);

    return (
      <div className={`${card} space-y-4`}>
        <h1 className="text-2xl font-bold">
          {expired ? "Este enlace ya no es válido" : "Enlace incompleto"}
        </h1>
        <p role="alert" className="text-slate-300">
          {expired
            ? "El enlace ha caducado o ya se ha usado. Los enlaces sirven una sola vez y durante una hora."
            : "Falta información en el enlace. Ábrelo de nuevo desde el correo, completo y sin modificar."}
        </p>
        {isRecovery && expired && (
          <p className="text-sm text-slate-400">
            Pide un enlace nuevo: tardará unos segundos en llegar. Si pides
            varios, solo funciona el último.
          </p>
        )}
        {requestAnother}
      </div>
    );
  }

  return (
    <div className={`${card} space-y-4`}>
      <h1 className="text-2xl font-bold">{TITLE[kind]}</h1>
      <p className="text-slate-300">
        {isRecovery
          ? "Pulsa el botón para continuar y elegir una contraseña nueva."
          : "Pulsa el botón para terminar la confirmación."}
      </p>

      {failure && (
        <p
          role="alert"
          className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
        >
          {failure.text}
        </p>
      )}

      <button type="button" onClick={confirm} disabled={busy} className={`${primaryButton} w-full`}>
        {busy ? "Comprobando…" : BUTTON[kind]}
      </button>
      <p className="text-xs text-slate-500">
        Este paso evita que el enlace se gaste si tu programa de correo lo
        abre automáticamente para analizarlo.
      </p>
      {failure && (
        <Link href="/acceso" className={`${secondaryButton} inline-block`}>
          Volver a la pantalla de acceso
        </Link>
      )}
    </div>
  );
}
