import { NextResponse, type NextRequest } from "next/server";
import { getClientIdentity } from "../clientIp";
import { createMemoryStore, createRateLimiter } from "../rateLimit";
import { SESSION_MAX_AGE_SECONDS, getSession, type SessionContext } from "./auth";
import { accountsEnabled } from "./config";
import { getDb, isProConfigured, type Db } from "./db";
import { ProError } from "./errors";

/**
 * Utilidades HTTP de las rutas Pro: cookie de sesión, protección CSRF,
 * límites de peticiones y traducción de errores.
 */

const MAX_BODY_BYTES = 8 * 1024;

/**
 * Con prefijo `__Host-` el navegador exige Secure, Path=/ y sin Domain: la
 * cookie no puede fijarla ni leerla un subdominio. En desarrollo (HTTP) ese
 * prefijo no es posible.
 */
export function sessionCookieName(env = process.env): string {
  return env.NODE_ENV === "production" ? "__Host-wts_session" : "wts_session";
}

export function setSessionCookie(response: NextResponse, token: string): void {
  response.cookies.set(sessionCookieName(), token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });
}

export function clearSessionCookie(response: NextResponse): void {
  response.cookies.set(sessionCookieName(), "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

export function readSessionToken(request: NextRequest): string | undefined {
  return request.cookies.get(sessionCookieName())?.value;
}

/**
 * Defensa CSRF para peticiones que modifican estado: el navegador envía
 * siempre `Origin` en POST/DELETE, y debe coincidir con el host de la
 * aplicación. Se suma a SameSite=Lax y a exigir JSON.
 */
export function assertSameOrigin(request: NextRequest): void {
  const origin = request.headers.get("origin");
  const host = request.headers.get("host") ?? request.nextUrl.host;
  let originHost: string | null = null;

  try {
    originHost = origin ? new URL(origin).host : null;
  } catch {
    originHost = null;
  }

  if (!originHost || originHost !== host) {
    throw new ProError(403, "Petición no permitida desde este origen.");
  }
}

export async function readJson(request: NextRequest): Promise<Record<string, unknown>> {
  if (!(request.headers.get("content-type") ?? "").includes("application/json")) {
    throw new ProError(400, "Se esperaba un cuerpo JSON.");
  }
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) {
    throw new ProError(400, "La petición es demasiado grande.");
  }

  const text = await request.text();

  if (text.length > MAX_BODY_BYTES) {
    throw new ProError(400, "La petición es demasiado grande.");
  }

  try {
    const body: unknown = JSON.parse(text || "{}");
    if (typeof body === "object" && body !== null && !Array.isArray(body)) {
      return body as Record<string, unknown>;
    }
  } catch {
    // se trata abajo
  }

  throw new ProError(400, "El cuerpo de la petición no es válido.");
}

export async function requireSession(
  db: Db,
  request: NextRequest,
): Promise<SessionContext> {
  const session = await getSession(db, readSessionToken(request));

  if (!session) throw new ProError(401, "Inicia sesión para continuar.");

  return session;
}

type Limiter = ReturnType<typeof createRateLimiter>;
const limiters = new Map<string, Limiter>();

/**
 * Límite de peticiones por cliente para rutas sensibles (acceso, registro).
 * En memoria: en serverless es por instancia, igual que el del analizador;
 * la primera línea debe ser una regla del WAF (ver docs/COST_ANALYSIS.md).
 */
export async function enforceRateLimit(
  request: NextRequest,
  name: string,
  limit: number,
  windowMs: number,
): Promise<void> {
  let limiter = limiters.get(name);

  if (!limiter) {
    limiter = createRateLimiter({
      limit,
      windowMs,
      prefix: `pro:${name}`,
      store: createMemoryStore(),
    });
    limiters.set(name, limiter);
  }

  const result = await limiter(getClientIdentity(request.headers).key);

  if (!result.allowed) {
    throw new ProError(429, "Demasiados intentos. Espera un momento y vuelve a probar.");
  }
}

/** Solo para tests: reinicia los contadores. */
export function resetRateLimitsForTests(): void {
  limiters.clear();
}

type Handler<C> = (context: {
  request: NextRequest;
  db: Db;
  params: C;
}) => Promise<NextResponse>;

/**
 * Envuelve un handler: abre la base de datos, exige mismo origen en las
 * peticiones que modifican estado y traduce los errores a respuestas JSON
 * sin filtrar detalles internos.
 */
export function route<C = Record<string, never>>(handler: Handler<C>) {
  return async (
    request: NextRequest,
    context: { params: Promise<C> },
  ): Promise<NextResponse> => {
    // Cuentas desactivadas: la ruta se comporta como si no existiera. Se
    // comprueba antes que nada: no se abre la base de datos, no se lee el
    // cuerpo y no se revela qué rutas hay.
    if (!accountsEnabled()) {
      return NextResponse.json(
        { error: "No encontrado." },
        { status: 404, headers: { "Cache-Control": "no-store" } },
      );
    }

    try {
      if (!isProConfigured()) {
        throw new ProError(503, "Las cuentas no están disponibles en este entorno.");
      }
      if (request.method !== "GET" && request.method !== "HEAD") {
        assertSameOrigin(request);
      }

      return await handler({
        request,
        db: await getDb(),
        params: await context.params,
      });
    } catch (error) {
      if (error instanceof ProError) {
        return NextResponse.json({ error: error.message }, { status: error.status });
      }

      console.error("Error inesperado en una ruta Pro:", error);

      return NextResponse.json(
        { error: "Ha ocurrido un error interno. Inténtalo de nuevo." },
        { status: 500 },
      );
    }
  };
}

/** Respuesta JSON que nunca debe guardarse en cachés compartidas. */
export function json(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}
