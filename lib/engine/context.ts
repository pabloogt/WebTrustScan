import type { SafeFetchResult, TlsProbeResult } from "../audit/safeRequest";
import type { CheckId } from "./catalog";
import type { DnsFacts } from "./dnsClient";
import type { ParsedCookie } from "./parse/cookies";
import type { HtmlFacts } from "./parse/html";
import type {
  CheckStatus,
  Confidence,
  Evidence,
  ResponseCondition,
  Severity,
} from "./types";

/** Resultado de una sonda secundaria: nunca lanza, siempre se describe. */
export type Probe<T> =
  | { ok: true; value: T }
  | { ok: false; code: string; reason: string | null };

/**
 * Cuánto representan las cabeceras de la respuesta al sitio real.
 * - full: respuesta normal.
 * - reduced: página de error de la aplicación (401/403/404): se evalúa, con
 *   confianza media.
 * - none: bloqueo de WAF, 429 o 5xx. Esas cabeceras son de la página de
 *   error o del intermediario, no del sitio: no se evalúan.
 */
export type ResponseTrust = "full" | "reduced" | "none";

export type ScanContext = {
  now: Date;
  input: string;
  finalUrl: URL;
  isHttps: boolean;
  /** Si se pidió HTTPS y no respondió, motivo por el que se analizó HTTP. */
  httpsFailure: string | null;
  primary: SafeFetchResult;
  headers: Record<string, string>;
  condition: ResponseCondition;
  responseTrust: ResponseTrust;
  isHtml: boolean;
  edge: string | null;
  html: HtmlFacts | null;
  cookies: ParsedCookie[];
  httpProbe: Probe<SafeFetchResult>;
  corsOrigin: string;
  corsProbe: Probe<SafeFetchResult>;
  /** null cuando la URL final no es HTTPS. */
  legacyTls: TlsProbeResult | null;
  securityTxt: Probe<SafeFetchResult>;
  /** null cuando el host es una IP (no hay dominio que consultar). */
  dns: DnsFacts | null;
};

export type Outcome = {
  status: CheckStatus;
  description: string;
  remediation?: string | null;
  /** Fracción del peso conseguida; solo para `warning`. */
  credit?: number;
  severity?: Severity;
  confidence?: Confidence;
  evidence?: Evidence[];
};

export type Check = { id: CheckId; run: (context: ScanContext) => Outcome };

type Extra = Pick<Outcome, "severity" | "confidence" | "evidence">;

export const pass = (description: string, extra: Extra = {}): Outcome => ({
  status: "pass",
  description,
  ...extra,
});

export const fail = (
  description: string,
  remediation: string,
  extra: Extra = {},
): Outcome => ({ status: "fail", description, remediation, ...extra });

export const warning = (
  credit: number,
  description: string,
  remediation: string,
  extra: Extra = {},
): Outcome => ({ status: "warning", credit, description, remediation, ...extra });

export const info = (
  description: string,
  extra: Extra & { remediation?: string } = {},
): Outcome => ({ status: "info", description, ...extra });

export const notApplicable = (description: string): Outcome => ({
  status: "not_applicable",
  description,
});

export const notTested = (description: string, extra: Extra = {}): Outcome => ({
  status: "not_tested",
  description,
  ...extra,
});

export const errored = (description: string, extra: Extra = {}): Outcome => ({
  status: "error",
  description,
  ...extra,
});

/** Evidencia: una cabecera tal y como se recibió (o su ausencia). */
export function headerEvidence(
  context: ScanContext,
  ...names: string[]
): Evidence[] {
  return names.map((name) => ({
    label: name,
    value: context.headers[name] ?? "(no enviada)",
  }));
}

const CONDITION_TEXT: Record<ResponseCondition, string> = {
  ok: "",
  "client-error": "una página de error",
  "auth-required": "una respuesta que exige autenticación",
  "rate-limited": "un límite de peticiones (HTTP 429)",
  "server-error": "un error temporal del servidor",
  blocked: "un bloqueo de su sistema de protección (WAF/CDN)",
};

/**
 * Envuelve un control que depende de las cabeceras o del cuerpo de la
 * respuesta. Si esa respuesta no representa al sitio no se evalúa; si es una
 * página de error de la aplicación, se evalúa con confianza reducida.
 */
export function responseLevel(
  context: ScanContext,
  evaluate: () => Outcome,
): Outcome {
  if (context.responseTrust === "none") {
    return notTested(
      `La web respondió con ${CONDITION_TEXT[context.condition]} (HTTP ${context.primary.status}). Lo recibido pertenece a esa respuesta, no al sitio funcionando con normalidad, así que este control no se ha evaluado.`,
    );
  }

  const outcome = evaluate();

  if (
    context.responseTrust === "reduced" &&
    (outcome.status === "fail" || outcome.status === "warning") &&
    (outcome.confidence ?? "high") === "high"
  ) {
    return { ...outcome, confidence: "medium" };
  }

  return outcome;
}

/** Controles que solo protegen documentos HTML. */
export function htmlOnly(context: ScanContext, evaluate: () => Outcome): Outcome {
  return responseLevel(context, () =>
    context.isHtml
      ? evaluate()
      : notApplicable(
          `La respuesta no es una página HTML (${context.headers["content-type"] ?? "sin Content-Type"}). Este control protege documentos que el navegador renderiza.`,
        ),
  );
}

export function sameSite(a: string, b: string): boolean {
  const strip = (host: string) => host.toLowerCase().replace(/^www\./, "");
  return strip(a) === strip(b);
}
