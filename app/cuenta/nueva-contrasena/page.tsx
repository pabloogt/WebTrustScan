import type { Metadata } from "next";
import { redirect } from "next/navigation";
import NewPasswordForm from "@/components/account/NewPasswordForm";
import { pageSession } from "@/lib/accounts/pageSession";

export const metadata: Metadata = { title: "Nueva contraseña · WebTrustScan" };

export default async function NewPasswordPage() {
  // Solo se llega aquí con la sesión que abre el enlace de recuperación.
  if (!(await pageSession())) redirect("/acceso?modo=recuperar&estado=enlace-no-valido");

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-16 text-white">
      <div className="mx-auto w-full max-w-md">
        <h1 className="text-3xl font-bold">Elige una contraseña nueva</h1>
        <p className="mt-2 text-slate-300">
          Tienes 15 minutos desde que abriste el enlace. Usa al menos 10
          caracteres; mejor una frase larga.
        </p>
        <div className="mt-8">
          <NewPasswordForm />
        </div>
      </div>
    </main>
  );
}
