import Link from "next/link";

// Página 404 propia: la que trae Next.js por defecto usa estilos en línea,
// que la Content-Security-Policy bloquea.
export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center bg-slate-950 px-6 text-center text-white">
      <p className="text-sm uppercase tracking-[0.2em] text-slate-400">
        Error 404
      </p>
      <h1 className="mt-3 text-3xl font-bold">Esta página no existe</h1>
      <p className="mt-4 max-w-md text-slate-300">
        Puede que el enlace esté mal escrito o que la página se haya movido.
      </p>
      <Link
        href="/"
        className="mt-8 rounded-xl bg-white px-6 py-3 font-semibold text-slate-900 transition hover:bg-slate-200"
      >
        Volver a WebTrustScan
      </Link>
    </main>
  );
}
