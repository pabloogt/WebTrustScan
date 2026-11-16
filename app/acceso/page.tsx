import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import AccessForm from "@/components/account/AccessForm";
import { pageSession } from "@/lib/accounts/pageSession";

export const metadata: Metadata = { title: "Acceso · WebTrustScan" };

export default async function AccessPage({
  searchParams,
}: {
  searchParams: Promise<{ estado?: string }>;
}) {
  if (await pageSession()) redirect("/panel");

  const { estado } = await searchParams;

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-16 text-white">
      <div className="mx-auto w-full max-w-md">
        <Link href="/" className="text-sm text-slate-400 hover:text-white">
          ← WebTrustScan
        </Link>
        <h1 className="mt-6 text-3xl font-bold">Tu cuenta</h1>
        <p className="mt-2 text-slate-300">
          Guarda el historial de tus análisis y consulta sus informes cuando
          quieras.
        </p>
        <div className="mt-8">
          <AccessForm notice={estado} />
        </div>
      </div>
    </main>
  );
}
