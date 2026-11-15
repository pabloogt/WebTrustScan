import { AuditError } from "../audit/errors";
import {
  safeFetch,
  safeTlsProbe,
  type SafeFetchOptions,
  type SafeFetchResult,
  type SafeRequestOptions,
  type TlsProbeResult,
} from "../audit/safeRequest";
import { normalizeUrl } from "../normalizeUrl";
import { getDefinition } from "./catalog";
import { contentChecks } from "./checks/content";
import { cookieChecks } from "./checks/cookies";
import { corsChecks } from "./checks/cors";
import { disclosureChecks } from "./checks/disclosure";
import { dnsEmailChecks } from "./checks/dnsEmail";
import { headerChecks } from "./checks/headers";
import { transportChecks } from "./checks/transport";
import {
  TLS_VERSIONS,
  type Check,
  type Outcome,
  type Probe,
  type ResponseTrust,
  type ScanContext,
  type TlsVersion,
} from "./context";
import {
  collectDnsFacts,
  createSystemDnsClient,
  type DnsClient,
} from "./dnsClient";
import { parseCookies } from "./parse/cookies";
import { extractHtmlFacts } from "./parse/html";
import { assertCompleteFindings, scoreReport } from "./scoring";
import {
  ENGINE_VERSION,
  type AuditReport,
  type Finding,
  type ResponseCondition,
  type Severity,
} from "./types";

export type EngineOptions = SafeRequestOptions & {
  /** Tiempo máximo para el análisis completo. */
  totalTimeoutMs?: number;
  /** Puerto de la versión HTTP a comprobar (solo se cambia en tests). */
  httpPort?: number;
  /** Cliente DNS (inyectable en el laboratorio). */
  dnsClient?: DnsClient;
  now?: () => Date;
};

const DEFAULT_TOTAL_TIMEOUT_MS = 20_000;
/** Las sondas secundarias no deben agotar el presupuesto del análisis. */
const PROBE_TIMEOUT_MS = 6_000;
const MAX_BODY_BYTES = 512 * 1024;

/** Origen ficticio de la sonda CORS (.invalid no existe nunca, RFC 2606). */
export const CORS_PROBE_ORIGIN = "https://cors-probe.webtrustscan.invalid";

export const ALL_CHECKS: Check[] = [
  ...transportChecks,
  ...headerChecks,
  ...cookieChecks,
  ...corsChecks,
  ...contentChecks,
  ...disclosureChecks,
  ...dnsEmailChecks,
];

/** Ejecuta una sonda secundaria: su fallo nunca interrumpe el análisis. */
async function probe<T>(run: () => Promise<T>): Promise<Probe<T>> {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    return error instanceof AuditError
      ? { ok: false, code: error.code, reason: error.reason }
      : { ok: false, code: "INTERNAL", reason: null };
  }
}

const EDGE_SIGNATURES: [string, (headers: Record<string, string>) => boolean][] =
  [
    ["Cloudflare", (h) => "cf-ray" in h || /cloudflare/i.test(h.server ?? "")],
    ["Vercel", (h) => "x-vercel-id" in h],
    ["Amazon CloudFront", (h) => "x-amz-cf-id" in h],
    ["Fastly", (h) => "x-fastly-request-id" in h || /fastly/i.test(h["x-served-by"] ?? "")],
    ["Akamai", (h) => /akamai/i.test(h.server ?? "") || "x-akamai-transformed" in h],
    ["Netlify", (h) => "x-nf-request-id" in h],
    ["GitHub Pages", (h) => "x-github-request-id" in h],
    ["Azure Front Door", (h) => "x-azure-ref" in h],
    ["Sucuri", (h) => "x-sucuri-id" in h],
    ["Imperva", (h) => "x-iinfo" in h],
  ];

function detectEdge(headers: Record<string, string>): string | null {
  return EDGE_SIGNATURES.find(([, matches]) => matches(headers))?.[0] ?? null;
}

const CHALLENGE_MARKERS =
  /just a moment\.\.\.|cf-chl-|challenge-platform|attention required! \| cloudflare|errors\.edgesuite\.net|incapsula incident|sucuri website firewall|captcha-delivery|px-captcha/i;

function classifyResponse(response: SafeFetchResult): ResponseCondition {
  const { status, headers, body } = response;

  if ([403, 429, 503].includes(status)) {
    const challenged =
      "cf-mitigated" in headers ||
      "x-amzn-waf-action" in headers ||
      "x-sucuri-block" in headers ||
      CHALLENGE_MARKERS.test(body ?? "");

    if (challenged) return "blocked";
  }

  if (status === 429) return "rate-limited";
  if (status >= 500) return "server-error";
  if (status === 401 || status === 403 || status === 407) return "auth-required";
  if (status >= 400) return "client-error";

  return "ok";
}

const TRUST: Record<ResponseCondition, ResponseTrust> = {
  ok: "full",
  "client-error": "reduced",
  "auth-required": "reduced",
  "rate-limited": "none",
  "server-error": "none",
  blocked: "none",
};

function looksLikeHtml(response: SafeFetchResult): boolean {
  const type = response.headers["content-type"]?.toLowerCase();

  if (type) return type.includes("text/html") || type.includes("xhtml");

  // Sin Content-Type el navegador lo deduce del contenido.
  return /^\s*(<!doctype html|<html)/i.test(response.body ?? "");
}

function lowerSeverity(severity: Severity): Severity {
  if (severity === "critical") return "high";
  if (severity === "high") return "medium";
  return "low";
}

function toFinding(check: Check, outcome: Outcome): Finding {
  const definition = getDefinition(check.id);
  const scored = ["pass", "warning", "fail"].includes(outcome.status);
  const credit =
    outcome.status === "pass"
      ? 1
      : outcome.status === "fail"
        ? 0
        : outcome.status === "warning"
          ? Math.min(Math.max(outcome.credit ?? 0.5, 0), 1)
          : null;

  return {
    id: definition.id,
    report: definition.report,
    category: definition.category,
    title: definition.title,
    status: outcome.status,
    severity:
      outcome.severity ??
      (outcome.status === "fail"
        ? definition.severity
        : outcome.status === "warning"
          ? lowerSeverity(definition.severity)
          : "info"),
    confidence: outcome.confidence ?? "high",
    credit: scored ? credit : null,
    weight: definition.weight,
    description: outcome.description,
    remediation: outcome.remediation ?? null,
    evidence: outcome.evidence ?? [],
    references: definition.references,
    method: definition.method,
  };
}

function runChecks(context: ScanContext): Finding[] {
  return ALL_CHECKS.map((check) => {
    try {
      return toFinding(check, check.run(context));
    } catch (error) {
      // Un fallo del propio motor nunca se convierte en un fallo del sitio.
      console.error(`Error interno en el check ${check.id}:`, error);

      return toFinding(check, {
        status: "error",
        description:
          "Esta comprobación ha fallado por un error interno del analizador. No afecta a la puntuación.",
      });
    }
  });
}

function buildNotices(context: ScanContext): string[] {
  const notices: string[] = [];
  const status = context.primary.status;

  switch (context.condition) {
    case "blocked":
      notices.push(
        `El sistema de protección de la web${context.edge ? ` (${context.edge})` : ""} ha bloqueado al analizador (HTTP ${status}). Solo se han evaluado los controles que no dependen del contenido de la página; el resto figura como «No comprobado».`,
      );
      break;
    case "rate-limited":
      notices.push(
        "La web ha respondido con un límite de peticiones (HTTP 429). Los controles que dependen de la respuesta no se han evaluado. Vuelve a intentarlo más tarde.",
      );
      break;
    case "server-error":
      notices.push(
        `La web ha respondido con un error temporal (HTTP ${status}). Los controles que dependen de la respuesta no se han evaluado, porque una página de error no representa la configuración normal del sitio.`,
      );
      break;
    case "auth-required":
      notices.push(
        `La dirección analizada exige autenticación o deniega el acceso (HTTP ${status}). Se ha evaluado esa respuesta; lo que hay detrás del inicio de sesión queda fuera del análisis.`,
      );
      break;
    case "client-error":
      notices.push(
        `La dirección analizada ha devuelto un error (HTTP ${status}). El análisis corresponde a esa página de error; comprueba que la URL es correcta.`,
      );
      break;
    default:
  }

  if (context.httpsFailure) {
    notices.push(
      "La versión https:// no ha respondido, así que se ha analizado la versión http://.",
    );
  }

  if (context.edge && context.condition === "ok") {
    notices.push(
      `La web se sirve a través de ${context.edge}. Las cabeceras analizadas son las que recibe un visitante; algunas pueden haberlas añadido la CDN y no el servidor de origen.`,
    );
  }

  if (context.primary.redirects >= 3) {
    notices.push(
      `Se han seguido ${context.primary.redirects} redirecciones hasta llegar a la página analizada.`,
    );
  }

  if (
    context.isHtml &&
    context.html &&
    context.html.textLength < 200 &&
    context.html.resources.some((resource) => resource.kind === "script")
  ) {
    notices.push(
      "La página parece una aplicación que se construye con JavaScript (SPA). El contenido generado en el navegador —formularios incluidos— no se analiza.",
    );
  }

  if (context.primary.bodyTruncated) {
    notices.push(
      "La página es muy grande: solo se han analizado sus primeros 512 KB.",
    );
  }

  return notices;
}

/**
 * Un saludo TLS por versión, cada uno limitado a esa única versión: así se
 * sabe qué admite el servidor, no solo qué negocia con un cliente moderno.
 */
async function probeTlsVersions(
  origin: string,
  options: SafeRequestOptions,
): Promise<Record<TlsVersion, TlsProbeResult>> {
  const results = await Promise.all(
    TLS_VERSIONS.map((version) =>
      Promise.resolve()
        .then(() =>
          safeTlsProbe(origin, { minVersion: version, maxVersion: version }, options),
        )
        .catch((): TlsProbeResult => ({ outcome: "error", reason: "BLOCKED" })),
    ),
  );

  return Object.fromEntries(
    TLS_VERSIONS.map((version, index) => [version, results[index]]),
  ) as Record<TlsVersion, TlsProbeResult>;
}

/** Errores de HTTPS tras los que tiene sentido probar la versión HTTP. */
function shouldFallbackToHttp(error: unknown): error is AuditError {
  return (
    error instanceof AuditError &&
    error.code === "UNREACHABLE" &&
    error.reason !== "ENOTFOUND" &&
    error.reason !== "EAI_AGAIN" &&
    error.reason !== "BAD_REDIRECT"
  );
}

export async function runAudit(
  rawUrl: string,
  options: EngineOptions = {},
): Promise<AuditReport> {
  const started = Date.now();
  const now = (options.now ?? (() => new Date()))();
  const startUrl = normalizeUrl(rawUrl);

  const deadline = AbortSignal.timeout(
    options.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS,
  );
  const signal = options.signal
    ? AbortSignal.any([deadline, options.signal])
    : deadline;
  const base: SafeRequestOptions = {
    addressPolicy: options.addressPolicy,
    allowedPorts: options.allowedPorts,
    requestTimeoutMs: options.requestTimeoutMs,
    maxRedirects: options.maxRedirects,
    dnsLookup: options.dnsLookup,
    tlsCa: options.tlsCa,
    signal,
  };
  const primaryOptions: SafeFetchOptions = {
    ...base,
    maxBodyBytes: MAX_BODY_BYTES,
    // Un certificado inválido es un hallazgo del sitio, no un error del análisis.
    tlsMode: "inspect",
  };
  const probeOptions: SafeFetchOptions = {
    ...base,
    tlsMode: "inspect",
    requestTimeoutMs: Math.min(
      options.requestTimeoutMs ?? PROBE_TIMEOUT_MS,
      PROBE_TIMEOUT_MS,
    ),
  };

  let primary: SafeFetchResult;
  let httpsFailure: string | null = null;

  try {
    try {
      primary = await safeFetch(startUrl, primaryOptions);
    } catch (error) {
      const requested = new URL(startUrl);

      if (requested.protocol !== "https:" || !shouldFallbackToHttp(error)) {
        throw error;
      }

      // Una web sin HTTPS debe recibir un informe (con ese fallo), no un error.
      const port = options.httpPort ? `:${options.httpPort}` : "";
      httpsFailure = `sin respuesta (${error.reason ?? "error de conexión"})`;

      try {
        primary = await safeFetch(
          `http://${requested.hostname}${port}${requested.pathname}${requested.search}`,
          primaryOptions,
        );
      } catch {
        throw error;
      }
    }
  } catch (error) {
    if (!(error instanceof AuditError) && signal.aborted) {
      throw new AuditError(
        "TIMEOUT",
        "La web ha tardado demasiado en responder. Inténtalo de nuevo más tarde.",
        "TIMEOUT",
      );
    }

    throw error;
  }

  const finalUrl = new URL(primary.url);
  const isHttps = finalUrl.protocol === "https:";
  const httpPort = options.httpPort ? `:${options.httpPort}` : "";

  const [httpProbe, corsProbe, securityTxt, tlsVersions, dns] = await Promise.all([
    isHttps
      ? probe(() => safeFetch(`http://${finalUrl.hostname}${httpPort}/`, probeOptions))
      : Promise.resolve<Probe<SafeFetchResult>>({
          ok: false,
          code: "SKIPPED",
          reason: null,
        }),
    probe(() =>
      safeFetch(finalUrl.href, {
        ...probeOptions,
        maxRedirects: 2,
        headers: { origin: CORS_PROBE_ORIGIN },
      }),
    ),
    probe(() =>
      safeFetch(new URL("/.well-known/security.txt", finalUrl).href, {
        ...probeOptions,
        maxRedirects: 2,
        maxBodyBytes: 16 * 1024,
      }),
    ),
    isHttps ? probeTlsVersions(finalUrl.origin, probeOptions) : Promise.resolve(null),
    collectDnsFacts(
      finalUrl.hostname,
      options.dnsClient ?? createSystemDnsClient(),
    ).catch(() => null),
  ]);

  const condition = classifyResponse(primary);
  const isHtml = looksLikeHtml(primary);

  const context: ScanContext = {
    now,
    input: rawUrl,
    finalUrl,
    isHttps,
    httpsFailure,
    primary,
    headers: primary.headers,
    condition,
    responseTrust: TRUST[condition],
    isHtml,
    edge: detectEdge(primary.headers),
    html:
      isHtml && primary.body
        ? extractHtmlFacts(primary.body, finalUrl, primary.bodyTruncated)
        : null,
    cookies: parseCookies(primary.setCookies, now),
    httpProbe,
    corsOrigin: CORS_PROBE_ORIGIN,
    corsProbe,
    tlsVersions,
    securityTxt,
    dns,
  };

  const findings = runChecks(context);
  assertCompleteFindings(findings);

  return {
    engineVersion: ENGINE_VERSION,
    scannedAt: now.toISOString(),
    durationMs: Date.now() - started,
    target: {
      input: rawUrl.trim(),
      url: primary.url,
      host: finalUrl.hostname,
      httpStatus: primary.status,
      contentType: primary.headers["content-type"] ?? null,
      redirects: primary.chain.map((hop) => ({ url: hop.url, status: hop.status })),
      edge: context.edge,
      condition,
    },
    notices: buildNotices(context),
    web: scoreReport("web", findings),
    dnsEmail: scoreReport("dns-email", findings),
    findings,
  };
}
