import type { Metadata } from "next";
import { redirect } from "next/navigation";
import Panel from "@/components/account/Panel";
import { pageSession } from "@/lib/accounts/pageSession";

export const metadata: Metadata = { title: "Panel · WebTrustScan" };

export default async function PanelPage() {
  // Ruta privada: sin sesión válida no se renderiza nada del panel.
  if (!(await pageSession())) redirect("/acceso");

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-10 text-white">
      <div className="mx-auto w-full max-w-5xl">
        <Panel />
      </div>
    </main>
  );
}
