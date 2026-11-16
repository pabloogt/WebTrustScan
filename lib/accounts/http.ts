import { NextResponse, type NextRequest } from "next/server";
import { LimitsUnavailableError, RateLimitedError } from "../limits";
import { accountsEnabled, supabaseConfig } from "./config";
import type { AccountDeps, SessionUser } from "./ports";

/**
 * Utilidades HTTP de las rutas de cuentas: interruptor global, protección
 * de origen, lectura segura del cuerpo y traducción de errores.
 */

const MAX_BODY_BYTES = 8 * 1024;

/** Error esperado. El mensaje es seguro para mostrarlo al usuario. */
export class AccountError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 429 | 503,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "AccountError";
  }
}

let testDeps: (() => Promise<AccountDeps>) | null = null;

/** Solo para tests: sustituye Supabase por otra implementación. */
export function setAccountDepsForTests(factory: (() => Promise<AccountDeps>) | null): void {
  testDeps = factory;
}

/** Puertos de la petición. Con las cuentas activadas pero sin configurar, 503. */
export async function getDeps(): Promise<AccountDeps> {
  if (testDeps) return testDeps();

  const config = supabaseConfig();

  if (!config) {
    throw new AccountError(503, "Las cuentas no están configuradas en este entorno.");
  }

  // Import diferido: con las cuentas desactivadas este módulo no se carga.
  const { createSupabaseDeps } = await import("./supabasePorts");
  return createSupabaseDeps(config);
}

/**
 * Defensa CSRF para peticiones que modifican estado: el navegador envía
 * siempre `Origin` en POST/DELETE y debe coincidir con el host de la
 * aplicación. Se suma a SameSite=Lax y a exigir un cuerpo JSON.
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
    throw new AccountError(403, "Petición no permitida desde este origen.");
  }
}

export async function readJson(request: NextRequest): Promise<Record<string, unknown>> {
  if (!(request.headers.get("content-type") ?? "").includes("application/json")) {
    throw new AccountError(400, "Se esperaba un cuerpo JSON.");
  }
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) {
    throw new AccountError(400, "La petición es demasiado grande.");
  }

  const text = await request.text();

  if (text.length > MAX_BODY_BYTES) {
    throw new AccountError(400, "La petición es demasiado grande.");
  }

  try {
    const body: unknown = JSON.parse(text || "{}");
    if (typeof body === "object" && body !== null && !Array.isArray(body)) {
      return body as Record<string, unknown>;
    }
  } catch {
    // se trata abajo
  }

  throw new AccountError(400, "El cuerpo de la petición no es válido.");
}

export async function requireUser(deps: AccountDeps): Promise<SessionUser> {
  const user = await deps.auth.getUser();

  if (!user) throw new AccountError(401, "Inicia sesión para continuar.");

  return user;
}

/** Respuesta JSON que nunca debe guardarse en cachés compartidas. */
export function json(data: unknown, status = 200, headers: Record<string, string> = {}): NextResponse {
  return NextResponse.json(data, {
    status,
    headers: { "Cache-Control": "no-store", ...headers },
  });
}

/** Traduce cualquier error a una respuesta sin detalles internos. */
export function errorResponse(error: unknown): NextResponse {
  if (error instanceof AccountError) {
    return json({ error: error.message, ...error.extra }, error.status);
  }
  if (error instanceof RateLimitedError) {
    return json(
      { error: "Demasiados intentos. Espera un momento y vuelve a probar." },
      429,
      { "Retry-After": String(error.retryAfterSeconds) },
    );
  }
  if (error instanceof LimitsUnavailableError) {
    // El motivo exacto va al log del servidor, no al cliente.
    console.error("Control de abuso no disponible:", error.message);
    return json(
      { error: "El servicio no está disponible en este momento. Inténtalo más tarde." },
      503,
    );
  }

  console.error("Error inesperado en una ruta de cuentas:", error);
  return json({ error: "Ha ocurrido un error interno. Inténtalo de nuevo." }, 500);
}

type Handler<C> = (context: {
  request: NextRequest;
  deps: AccountDeps;
  params: C;
}) => Promise<NextResponse>;

/**
 * Envuelve una ruta de cuentas. Orden deliberado:
 *   1. Interruptor: desactivadas → 404, sin tocar Supabase ni leer el cuerpo.
 *   2. Mismo origen en todo lo que no sea GET.
 *   3. El handler, con sus errores traducidos.
 */
export function route<C = Record<string, never>>(handler: Handler<C>) {
  return async (
    request: NextRequest,
    context: { params: Promise<C> },
  ): Promise<NextResponse> => {
    if (!accountsEnabled()) {
      return json({ error: "No encontrado." }, 404);
    }

    try {
      if (request.method !== "GET" && request.method !== "HEAD") {
        assertSameOrigin(request);
      }

      return await handler({
        request,
        deps: await getDeps(),
        params: await context.params,
      });
    } catch (error) {
      return errorResponse(error);
    }
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value);
}

/**
 * Destino de una redirección tras autenticarse. Solo rutas internas: nunca
 * una URL absoluta ni `//host`, para que un enlace manipulado no pueda
 * enviar al usuario a otro sitio.
 */
export function safeNextPath(value: string | null | undefined, fallback = "/panel"): string {
  return typeof value === "string" && /^\/(?![/\\])[\w\-./]*$/.test(value) && !value.includes("..")
    ? value
    : fallback;
}
