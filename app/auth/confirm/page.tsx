import type { Metadata } from "next";
import { notFound } from "next/navigation";
import ConfirmLink from "@/components/account/ConfirmLink";
import { accountsEnabled } from "@/lib/accounts/config";

export const metadata: Metadata = {
  title: "Confirmar · WebTrustScan",
  // El enlace lleva un token: que no se indexe ni se envíe como referente.
  robots: { index: false, follow: false },
  referrer: "no-referrer",
};

type Params = Record<string, string | string[] | undefined>;

const one = (value: string | string[] | undefined) =>
  typeof value === "string" ? value.slice(0, 300) : undefined;

/**
 * Destino de los enlaces de los correos. Esta página NO canjea el enlace:
 * solo lo muestra con un botón. Así un filtro de correo o una vista previa
 * que la abra no gasta el token de un solo uso.
 */
export default async function ConfirmPage({
  searchParams,
}: {
  searchParams: Promise<Params>;
}) {
  if (!accountsEnabled()) notFound();

  const params = await searchParams;

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-16 text-white">
      <div className="mx-auto w-full max-w-md">
        <ConfirmLink
          tokenHash={one(params.token_hash)}
          type={one(params.type)}
          code={one(params.code)}
          next={one(params.next)}
          errorCode={one(params.error_code) ?? one(params.error)}
        />
      </div>
    </main>
  );
}
