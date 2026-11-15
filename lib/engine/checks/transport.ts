import type { TlsInfo } from "../../audit/safeRequest";
import {
  errored,
  fail,
  notApplicable,
  notTested,
  pass,
  sameSite,
  warning,
  type Check,
  type ScanContext,
} from "../context";
import { firstHeaderValue, parseHstsMaxAge } from "../parse/csp";
import type { Evidence } from "../types";

const DAY_MS = 86_400_000;
const HSTS_MIN_MAX_AGE = 15_552_000; // 180 días
const HSTS_PRELOAD_MIN_MAX_AGE = 31_536_000; // 1 año

const NOT_HTTPS = notApplicable(
  "La web no usa HTTPS, así que este control no se puede aplicar. El problema de fondo ya está recogido en «HTTPS disponible».",
);

const CERTIFICATE_ERRORS: Record<string, string> = {
  CERT_HAS_EXPIRED: "el certificado ha caducado",
  CERT_NOT_YET_VALID: "el certificado todavía no es válido",
  DEPTH_ZERO_SELF_SIGNED_CERT: "el certificado es autofirmado",
  SELF_SIGNED_CERT_IN_CHAIN:
    "la cadena incluye un certificado autofirmado que no es de confianza",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    "falta el certificado intermedio o lo emite una autoridad no reconocida",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    "lo emite una autoridad que no es de confianza",
  UNABLE_TO_GET_ISSUER_CERT: "no se puede verificar quién lo emite",
  ERR_TLS_CERT_ALTNAME_INVALID: "el certificado no corresponde a este dominio",
  CERT_REVOKED: "el certificado ha sido revocado",
};

function certificateEvidence(tls: TlsInfo): Evidence[] {
  const entries: [string, string | null][] = [
    ["Emitido para", tls.subject],
    ["Nombres (SAN)", tls.subjectAltName],
    ["Emisor", tls.issuer],
    ["Válido desde", tls.validFrom],
    ["Válido hasta", tls.validTo],
    ["Error de validación", tls.authorizationError],
  ];

  return entries
    .filter((entry): entry is [string, string] => Boolean(entry[1]))
    .map(([label, value]) => ({ label, value }));
}

function httpsCheck(context: ScanContext) {
  if (context.isHttps) {
    return pass("La web se sirve por HTTPS: la conexión va cifrada.", {
      evidence: [{ label: "URL final", value: context.finalUrl.href }],
    });
  }

  const evidence: Evidence[] = [
    { label: "URL final", value: context.finalUrl.href },
  ];
  const downgrade = context.primary.chain.some((hop) =>
    hop.url.startsWith("https://"),
  );
  let description = "La web se sirve por HTTP, sin cifrar.";

  if (context.httpsFailure) {
    description =
      "La versión https:// de la web no responde, así que solo está disponible por HTTP sin cifrar.";
    evidence.push({ label: "Intento por HTTPS", value: context.httpsFailure });
  } else if (downgrade) {
    description =
      "La versión https:// redirige a http://: la web acaba cargándose sin cifrar.";
    evidence.push({
      label: "Redirecciones",
      value: context.primary.chain.map((hop) => hop.url).join(" → "),
    });
  }

  const passwordForms =
    (context.html?.forms.filter((form) => form.hasPassword).length ?? 0) +
    (context.html?.loosePasswordInputs ?? 0);

  if (passwordForms > 0) {
    description +=
      " Además, la página pide una contraseña, que viajaría legible por la red.";
    evidence.push({
      label: "Campos de contraseña",
      value: String(passwordForms),
    });
  }

  return fail(
    description,
    "Instala un certificado TLS (por ejemplo, gratuito con Let's Encrypt o el de tu proveedor) y sirve toda la web por HTTPS.",
    { evidence },
  );
}

function certificateCheck(context: ScanContext) {
  if (!context.isHttps) return NOT_HTTPS;

  const hops = context.primary.chain.filter((hop) => hop.tls !== null);
  const broken = hops.find((hop) => hop.tls && !hop.tls.authorized);

  if (broken?.tls) {
    const code = broken.tls.authorizationError ?? "UNKNOWN";

    return fail(
      `El certificado HTTPS no es válido: ${CERTIFICATE_ERRORS[code] ?? `el navegador lo rechazaría (${code})`}. Los visitantes ven una advertencia de seguridad a pantalla completa.`,
      "Renueva o reinstala el certificado: debe estar vigente, incluir este dominio y servirse con su cadena intermedia completa.",
      {
        evidence: [
          { label: "URL", value: broken.url },
          ...certificateEvidence(broken.tls),
        ],
      },
    );
  }

  const tls = context.primary.tls;

  if (!tls || !tls.validTo || !tls.validFrom) {
    return errored("No se pudieron leer los datos del certificado.");
  }

  const expires = Date.parse(tls.validTo);
  const issued = Date.parse(tls.validFrom);

  if (Number.isNaN(expires) || Number.isNaN(issued)) {
    return errored("No se pudieron interpretar las fechas del certificado.", {
      evidence: certificateEvidence(tls),
    });
  }

  const remaining = expires - context.now.getTime();
  const days = Math.floor(remaining / DAY_MS);
  // Los certificados se renuevan mucho antes de caducar. El umbral es
  // proporcional a su duración para no alarmar con certificados de vida corta.
  const threshold = Math.min((expires - issued) * 0.15, 14 * DAY_MS);

  if (remaining < threshold) {
    return warning(
      0.6,
      `El certificado es válido, pero caduca en ${days <= 0 ? "menos de un día" : `${days} día${days === 1 ? "" : "s"}`}. A estas alturas ya debería haberse renovado.`,
      "Comprueba que la renovación automática del certificado funciona, o renuévalo manualmente.",
      { evidence: certificateEvidence(tls), severity: "medium" },
    );
  }

  return pass(
    `El certificado es de confianza, corresponde al dominio y caduca en ${days} días.`,
    { evidence: certificateEvidence(tls) },
  );
}

function tlsVersionCheck(context: ScanContext) {
  if (!context.isHttps) return NOT_HTTPS;

  const protocol = context.primary.tls?.protocol;

  if (!protocol) return errored("No se pudo leer la versión de TLS negociada.");

  const evidence = [
    { label: "Protocolo negociado", value: protocol },
    { label: "Cifrado", value: context.primary.tls?.cipher ?? "desconocido" },
  ];

  return protocol === "TLSv1.3" || protocol === "TLSv1.2"
    ? pass(`La conexión usa ${protocol}, una versión actual.`, { evidence })
    : fail(
        `La mejor versión que ofrece el servidor es ${protocol}, un protocolo retirado por inseguro.`,
        "Activa TLS 1.2 y TLS 1.3 en el servidor o en tu proveedor de hosting.",
        { evidence },
      );
}

function legacyTlsCheck(context: ScanContext) {
  if (!context.isHttps || !context.legacyTls) return NOT_HTTPS;

  const protocol = context.primary.tls?.protocol;

  if (protocol && protocol !== "TLSv1.3" && protocol !== "TLSv1.2") {
    return notApplicable(
      "El servidor ni siquiera ofrece una versión actual de TLS; ya está recogido en «Versión de TLS negociada».",
    );
  }

  const probe = context.legacyTls;

  if (probe.outcome === "accepted") {
    return fail(
      `El servidor todavía acepta conexiones con ${probe.protocol ?? "TLS 1.0/1.1"}, protocolos retirados en 2021 (RFC 8996).`,
      "Desactiva TLS 1.0 y TLS 1.1 y deja solo TLS 1.2 y 1.3.",
      { evidence: [{ label: "Saludo TLS 1.0–1.1", value: "aceptado" }] },
    );
  }

  if (probe.outcome === "rejected") {
    return pass("El servidor rechaza TLS 1.0 y TLS 1.1.", {
      evidence: [
        { label: "Saludo TLS 1.0–1.1", value: `rechazado (${probe.reason})` },
      ],
    });
  }

  return notTested(
    probe.reason === "UNSUPPORTED_RUNTIME"
      ? "El entorno del analizador no permite intentar conexiones con TLS 1.0/1.1, así que no se ha podido comprobar."
      : "No se ha podido completar la prueba de protocolos TLS antiguos.",
    { evidence: [{ label: "Motivo", value: probe.reason }] },
  );
}

function httpRedirectCheck(context: ScanContext) {
  if (!context.isHttps) return NOT_HTTPS;

  const probe = context.httpProbe;

  if (!probe.ok) {
    if (probe.reason === "ECONNREFUSED") {
      return pass(
        "La web no acepta conexiones HTTP sin cifrar (el puerto está cerrado), así que nadie puede entrar por una versión insegura.",
        { evidence: [{ label: "Petición http://", value: "conexión rechazada" }] },
      );
    }

    return notTested(
      "La versión http:// no ha respondido a tiempo, así que no se ha podido confirmar si redirige a HTTPS. No se penaliza.",
      { evidence: [{ label: "Motivo", value: probe.reason ?? probe.code }] },
    );
  }

  const chain = probe.value.chain.map((hop) => hop.url).join(" → ");
  const evidence = [{ label: "Redirecciones", value: chain }];
  const final = new URL(probe.value.url);

  if (final.protocol !== "https:") {
    return fail(
      "La versión http:// responde sin llevar a la versión segura: quien entre por ahí navega sin cifrar.",
      "Configura una redirección permanente (301) de todo el tráfico HTTP a HTTPS.",
      { evidence },
    );
  }

  if (!sameSite(final.hostname, context.finalUrl.hostname)) {
    return warning(
      0.5,
      `La versión http:// redirige a HTTPS, pero de otro sitio (${final.hostname}).`,
      "Comprueba que la redirección de HTTP apunta a la versión HTTPS de este mismo dominio.",
      { evidence },
    );
  }

  return pass("La versión http:// redirige a la versión segura.", { evidence });
}

function hstsCheck(context: ScanContext) {
  if (!context.isHttps) return NOT_HTTPS;

  const raw = context.headers["strict-transport-security"];
  // RFC 6797 §8.1: si llegan varias cabeceras solo cuenta la primera.
  const value = firstHeaderValue(raw);
  const evidence = [
    { label: "strict-transport-security", value: raw ?? "(no enviada)" },
  ];
  const example = '"Strict-Transport-Security: max-age=31536000; includeSubDomains"';

  if (!value) {
    // HSTS se aplica a todo el host, pero una página de bloqueo puede no
    // llevarla aunque el sitio sí: sin evidencia no se concluye.
    if (context.responseTrust === "none") {
      return notTested(
        "La respuesta recibida es una página de bloqueo o error temporal y no lleva HSTS; no se puede saber si el sitio la envía normalmente.",
        { evidence },
      );
    }

    return fail(
      "La web no envía Strict-Transport-Security: la primera visita de cada usuario puede ser interceptada antes de pasar a HTTPS.",
      `Añade la cabecera ${example}.`,
      { evidence },
    );
  }

  const maxAge = parseHstsMaxAge(value);

  if (maxAge === null) {
    return fail(
      "La cabecera Strict-Transport-Security no tiene un max-age válido, así que el navegador la ignora.",
      `Usa ${example}.`,
      { evidence },
    );
  }

  if (maxAge === 0) {
    return fail(
      'La web envía Strict-Transport-Security con "max-age=0", que ordena al navegador OLVIDAR la protección.',
      `Usa ${example}.`,
      { evidence },
    );
  }

  if (maxAge < HSTS_MIN_MAX_AGE) {
    return warning(
      0.5,
      `HSTS está activo, pero con una duración corta (max-age=${maxAge} s, unos ${Math.max(1, Math.round(maxAge / 86_400))} día(s)). Se recomienda al menos 6 meses.`,
      `Sube max-age a un año: ${example}.`,
      { evidence },
    );
  }

  const lower = value.toLowerCase();
  const includeSubDomains = /;\s*includesubdomains\b/.test(lower);
  const preload = /;\s*preload\b/.test(lower);
  const notes: string[] = [];

  if (!includeSubDomains) {
    notes.push("no cubre subdominios (falta includeSubDomains)");
  }
  if (preload && (!includeSubDomains || maxAge < HSTS_PRELOAD_MIN_MAX_AGE)) {
    notes.push(
      "declara preload sin cumplir sus requisitos (1 año e includeSubDomains)",
    );
  }

  return pass(
    notes.length > 0
      ? `HSTS está activo. Mejora opcional: ${notes.join("; ")}.`
      : "HSTS está activo y cubre también los subdominios.",
    { evidence },
  );
}

export const transportChecks: Check[] = [
  { id: "transport.https", run: httpsCheck },
  { id: "transport.certificate", run: certificateCheck },
  { id: "transport.tls-version", run: tlsVersionCheck },
  { id: "transport.legacy-tls", run: legacyTlsCheck },
  { id: "transport.http-redirect", run: httpRedirectCheck },
  { id: "transport.hsts", run: hstsCheck },
];
