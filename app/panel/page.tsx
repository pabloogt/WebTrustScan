import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import Panel from "@/components/pro/Panel";

import { accountsEnabled } from "@/lib/pro/config";

export const metadata: Metadata = { title: "Panel · WebTrustScan" };

export default function PanelPage() {
  // Las cuentas están desactivadas por defecto (ver lib/pro/config.ts).
  if (!accountsEnabled()) notFound();

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-10 text-white">
      <div className="mx-auto w-full max-w-5xl">
        <Link href="/" className="no-print text-sm text-slate-400 hover:text-white">
          ← Análisis rápido
        </Link>
        <div className="mt-6">
          <Panel />
        </div>
      </div>
    </main>
  );
}
