import { NextResponse, type NextRequest } from "next/server";
import { buildContentSecurityPolicy, generateNonce } from "./lib/csp";

/**
 * Genera un nonce por petición y la cabecera Content-Security-Policy.
 * Next.js lee el nonce de la cabecera de la petición y lo añade a sus scripts.
 */
export function proxy(request: NextRequest) {
  const nonce = generateNonce();
  const csp = buildContentSecurityPolicy({
    nonce,
    isDev: process.env.NODE_ENV === "development",
  });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);

  return response;
}

export const config = {
  matcher: [
    {
      // Todo salvo la API, los estáticos de Next.js y el favicon.
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
