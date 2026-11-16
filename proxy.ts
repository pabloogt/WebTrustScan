import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { accountsEnabled, supabaseConfig } from "./lib/accounts/config";
import { buildContentSecurityPolicy, generateNonce } from "./lib/csp";

type PendingCookie = { name: string; value: string; options?: Record<string, unknown> };

/**
 * Renueva la sesión de Supabase antes de renderizar una página. Los
 * componentes de servidor no pueden escribir cookies, así que el token
 * renovado se guarda aquí. Solo se hace si las cuentas están activadas y la
 * petición trae una cookie de sesión: un visitante anónimo no provoca
 * ninguna llamada a Supabase.
 */
async function refreshSession(request: NextRequest): Promise<PendingCookie[]> {
  if (!accountsEnabled()) return [];

  const config = supabaseConfig();
  const hasSession = request.cookies.getAll().some((cookie) => cookie.name.startsWith("sb-"));

  if (!config || !hasSession) return [];

  const pending: PendingCookie[] = [];

  try {
    const supabase = createServerClient(config.url, config.publishableKey, {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (list) => {
          for (const cookie of list) {
            // Para que la página que se renderiza a continuación vea el token nuevo.
            request.cookies.set(cookie.name, cookie.value);
            pending.push(cookie);
          }
        },
      },
    });

    await supabase.auth.getUser();
  } catch {
    // Si Supabase no responde, la página decidirá: sin sesión válida, a /acceso.
  }

  return pending;
}

/**
 * Genera un nonce por petición y la cabecera Content-Security-Policy.
 * Next.js lee el nonce de la cabecera de la petición y lo añade a sus scripts.
 */
export async function proxy(request: NextRequest) {
  const sessionCookies = await refreshSession(request);
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

  for (const { name, value, options } of sessionCookies) {
    response.cookies.set(name, value, {
      ...options,
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });
  }

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
