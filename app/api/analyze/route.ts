import { NextRequest, NextResponse } from "next/server";
import { AuditError } from "@/lib/audit/errors";
import { analyzeForUser, analyzeForVisitor, validateTarget } from "@/lib/accounts/analyze";
import { accountsEnabled } from "@/lib/accounts/config";
import { AccountError, errorResponse, getDeps, isUuid } from "@/lib/accounts/http";
import type { AccountDeps, SessionUser } from "@/lib/accounts/ports";
import { createAnalyzeRateLimit } from "@/lib/analyzeRateLimit";
import { getClientIdentity } from "@/lib/clientIp";
import { runAudit } from "@/lib/engine/run";
import { LimitsUnavailableError, limitsMode, missingLimitsConfig } from "@/lib/limits";
import { randomUUID } from "node:crypto";

// El análisis tiene su propio tope de 20 s; se deja margen a la plataforma.
export const maxDuration = 30;

const MAX_BODY_BYTES = 4096;

const rateLimit = createAnalyzeRateLimit();

function plainError(message: string, status: number, headers?: Record<string, string>) {
  return NextResponse.json({ error: message }, { status, headers });
}

async function readBody(
  request: NextRequest,
): Promise<{ url: string; requestId: string | null } | null> {
  const declaredLength = Number(request.headers.get("content-length") ?? 0);

  if (declaredLength > MAX_BODY_BYTES) return null;

  const text = await request.text();

  if (text.length > MAX_BODY_BYTES) return null;

  try {
    const body: unknown = JSON.parse(text);

    if (typeof body !== "object" || body === null) return null;

    const { url, requestId } = body as { url?: unknown; requestId?: unknown };

    return typeof url === "string" && url.trim()
      ? { url, requestId: isUuid(requestId) ? requestId : null }
      : null;
  } catch {
    return null;
  }
}

/**
 * Sesión del usuario, si las cuentas están activadas y la petición viene de
 * la propia aplicación. Una petición de otro origen se trata como anónima:
 * nunca gasta la cuota de una cuenta.
 */
async function sessionFor(
  request: NextRequest,
): Promise<{ deps: AccountDeps; user: SessionUser } | null> {
  if (!accountsEnabled()) return null;

  const origin = request.headers.get("origin");
  const host = request.headers.get("host") ?? request.nextUrl.host;

  try {
    if (!origin || new URL(origin).host !== host) return null;

    const deps = await getDeps();
    const user = await deps.auth.getUser();

    return user ? { deps, user } : null;
  } catch (error) {
    // Cuentas mal configuradas o caídas: el analizador público sigue en pie.
    if (!(error instanceof AccountError)) {
      console.error("No se pudo comprobar la sesión:", error instanceof Error ? error.name : "error");
    }
    return null;
  }
}

export async function POST(request: NextRequest) {
  try {
    // Sin control de abuso configurado no se analiza: nunca sin límites.
    if (limitsMode() === "unavailable") {
      throw new LimitsUnavailableError(
        `Falta: ${missingLimitsConfig().join("; ")}.`,
      );
    }

    const limit = await rateLimit.check(getClientIdentity(request.headers).key);

    if (!limit.allowed) {
      return plainError(
        limit.scope === "global"
          ? "El servicio está recibiendo demasiados análisis ahora mismo. Vuelve a intentarlo en un momento."
          : "Has hecho demasiados análisis seguidos. Espera un momento y vuelve a intentarlo.",
        429,
        { "Retry-After": String(limit.retryAfterSeconds) },
      );
    }

    const body = await readBody(request);

    if (!body) return plainError("La URL es obligatoria.", 400);

    // Antes de consumir nada: una URL inválida o un destino no permitido
    // no gasta cuota ni límite diario.
    const url = validateTarget(body.url);
    const session = await sessionFor(request);

    const result = session
      ? await analyzeForUser(
          session.deps,
          session.user,
          url,
          body.requestId ?? randomUUID(),
          runAudit,
        )
      : await analyzeForVisitor(request.headers, url, runAudit);

    return NextResponse.json(
      "quota" in result && result.quota
        ? { ...result.report, quota: result.quota }
        : result.report,
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (error) {
    if (error instanceof AuditError) {
      return plainError(error.message, error.httpStatus);
    }

    return errorResponse(error);
  }
}
