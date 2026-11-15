import { NextRequest, NextResponse } from "next/server";
import { AuditError } from "@/lib/audit/errors";
import { createAnalyzeRateLimit } from "@/lib/analyzeRateLimit";
import { getClientIdentity } from "@/lib/clientIp";
import { runAudit } from "@/lib/engine/run";

// El análisis tiene su propio tope de 20 s; se deja margen a la plataforma.
export const maxDuration = 30;

const MAX_BODY_BYTES = 4096;

const rateLimit = createAnalyzeRateLimit();

function errorResponse(
  message: string,
  status: number,
  headers?: Record<string, string>,
) {
  return NextResponse.json({ error: message }, { status, headers });
}

async function readUrlFromBody(request: NextRequest): Promise<string | null> {
  const declaredLength = Number(request.headers.get("content-length") ?? 0);

  if (declaredLength > MAX_BODY_BYTES) return null;

  const text = await request.text();

  if (text.length > MAX_BODY_BYTES) return null;

  try {
    const body: unknown = JSON.parse(text);

    if (typeof body !== "object" || body === null) return null;

    const url = (body as { url?: unknown }).url;

    return typeof url === "string" && url.trim() ? url : null;
  } catch {
    return null;
  }
}

export async function POST(request: NextRequest) {
  const limit = await rateLimit.check(getClientIdentity(request.headers).key);

  if (!limit.allowed) {
    return errorResponse(
      limit.scope === "global"
        ? "El servicio está recibiendo demasiados análisis ahora mismo. Vuelve a intentarlo en un momento."
        : "Has hecho demasiados análisis seguidos. Espera un momento y vuelve a intentarlo.",
      429,
      { "Retry-After": String(limit.retryAfterSeconds) },
    );
  }

  const rawUrl = await readUrlFromBody(request);

  if (!rawUrl) {
    return errorResponse("La URL es obligatoria.", 400);
  }

  try {
    const result = await runAudit(rawUrl);

    return NextResponse.json(result, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (error) {
    if (error instanceof AuditError) {
      return errorResponse(error.message, error.httpStatus);
    }

    console.error("Error inesperado en /api/analyze:", error);

    return errorResponse(
      "No se pudo analizar la web por un error interno. Inténtalo de nuevo.",
      500,
    );
  }
}
