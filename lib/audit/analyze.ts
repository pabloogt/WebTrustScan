/**
 * MOTOR 1.x (CONGELADO). La aplicación usa el Engine 2.0 de `lib/engine`.
 * Este módulo se conserva sin cambios funcionales como referencia para el
 * laboratorio (tests/lab), que compara las puntuaciones antiguas y nuevas,
 * y para mantener la suite histórica. No añadir funcionalidad aquí.
 */
import type { AuditResult } from "@/types/audit";
import { normalizeUrl } from "../normalizeUrl";
import { buildChecks, type HttpRedirectResult } from "./checks";
import { AuditError } from "./errors";
import { fetchHeadersSafely, type SafeRequestOptions } from "./safeRequest";
import { buildSummary, calculateScore } from "./score";

export type AnalyzeOptions = SafeRequestOptions & {
  /** Tiempo máximo para el análisis completo. */
  totalTimeoutMs?: number;
  /** Puerto de la versión HTTP a comprobar (solo se cambia en tests). */
  httpPort?: number;
};

const DEFAULT_TOTAL_TIMEOUT_MS = 20_000;

function sameSite(a: string, b: string): boolean {
  const strip = (host: string) => host.toLowerCase().replace(/^www\./, "");
  return strip(a) === strip(b);
}

/**
 * Comprueba si la versión http:// del sitio acaba en https:// del mismo sitio.
 * Cualquier fallo (puerto 80 cerrado, timeout...) cuenta como "no confirmado".
 */
async function checkHttpToHttpsRedirect(
  hostname: string,
  options: AnalyzeOptions,
): Promise<HttpRedirectResult> {
  const port = options.httpPort ? `:${options.httpPort}` : "";

  try {
    const result = await fetchHeadersSafely(
      `http://${hostname}${port}/`,
      options,
    );
    const final = new URL(result.url);

    return final.protocol === "https:" && sameSite(final.hostname, hostname)
      ? "redirects"
      : "no-redirect";
  } catch (error) {
    // Un timeout global no debe quedar oculto como "no confirmado".
    if (options.signal?.aborted) throw error;
    return "unknown";
  }
}

export async function analyzeUrl(
  rawUrl: string,
  options: AnalyzeOptions = {},
): Promise<AuditResult> {
  const startUrl = normalizeUrl(rawUrl);

  const deadline = AbortSignal.timeout(
    options.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS,
  );
  const signal = options.signal
    ? AbortSignal.any([deadline, options.signal])
    : deadline;
  const requestOptions: AnalyzeOptions = { ...options, signal };

  try {
    const response = await fetchHeadersSafely(startUrl, requestOptions);
    const finalUrl = new URL(response.url);

    const httpRedirect = await checkHttpToHttpsRedirect(
      finalUrl.hostname,
      requestOptions,
    );

    const checks = buildChecks({
      finalUrl: response.url,
      headers: response.headers,
      httpRedirect,
    });
    const score = calculateScore(checks);

    return {
      url: response.url,
      httpStatus: response.status,
      score,
      summary: buildSummary(score),
      checks,
    };
  } catch (error) {
    if (!(error instanceof AuditError) && signal.aborted) {
      throw new AuditError(
        "TIMEOUT",
        "La web ha tardado demasiado en responder. Inténtalo de nuevo más tarde.",
      );
    }

    throw error;
  }
}
