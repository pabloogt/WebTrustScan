import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import AccessForm from "@/components/pro/AccessForm";

import { accountsEnabled } from "@/lib/pro/config";

export const metadata: Metadata = { title: "Acceso · WebTrustScan" };

export default function AccessPage() {
  // Las cuentas están desactivadas por defecto (ver lib/pro/config.ts).
  if (!accountsEnabled()) notFound();

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-16 text-white">
      <div className="mx-auto w-full max-w-md">
        <Link href="/" className="text-sm text-slate-400 hover:text-white">
          ← WebTrustScan
        </Link>
        <h1 className="mt-6 text-3xl font-bold">Tu cuenta</h1>
        <p className="mt-2 text-slate-300">
          Guarda tus dominios, conserva el historial de auditorías y compara
          cómo evoluciona su configuración.
        </p>
        <div className="mt-8">
          <AccessForm />
        </div>
      </div>
    </main>
  );
}
