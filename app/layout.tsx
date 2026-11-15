import type { Metadata } from "next";
import { connection } from "next/server";
import "./globals.css";

export const metadata: Metadata = {
  title: "WebTrustScan",
  description: "Auditoría básica de seguridad y confianza para webs",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // La CSP usa un nonce distinto en cada petición, así que las páginas tienen
  // que renderizarse por petición: una página estática no podría llevarlo.
  await connection();

  return (
    <html lang="es" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
