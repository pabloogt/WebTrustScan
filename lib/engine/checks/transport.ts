import type { TlsInfo, TlsProbeResult } from "../../audit/safeRequest";
import {
  errored,
  fail,
  notApplicable,
  notTested,
  pass,
  sameSite,
  warning,
  TLS_VERSIONS,
  type Check,
  type ScanContext,
  type TlsVersion,
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

const TLS_LABEL: Record<TlsVersion, string> = {
  TLSv1: "TLS 1.0",
  "TLSv1.1": "TLS 1.1",
  "TLSv1.2": "TLS 1.2",
  "TLSv1.3": "TLS 1.3",
};

const OPENSSL_FLAG: Record<TlsVersion, string> = {
  TLSv1: "-tls1 -cipher 'DEFAULT:@SECLEVEL=0'",
  "TLSv1.1": "-tls1_1 -cipher 'DEFAULT:@SECLEVEL=0'",
  "TLSv1.2": "-tls1_2",
  "TLSv1.3": "-tls1_3",
};

function describeProbe(probe: TlsProbeResult): string {
  if (probe.outcome === "accepted") return "aceptado (saludo completado)";

  if (probe.outcome === "rejected") {
    return probe.explicit
      ? `rechazado (el servidor responde que no admite la versión: ${probe.reason})`
      : `no completado (el servidor cortó el saludo sin indicar el motivo: ${probe.reason})`;
  }

  return probe.reason === "UNSUPPORTED_RUNTIME"
    ? "no comprobable (el entorno del analizador no puede usar esta versión)"
    : `no comprobable (la prueba no llegó a ser válida: ${probe.reason})`;
}

/** Una línea de evidencia por versión, más la de la conexión normal. */
function tlsEvidence(context: ScanContext): Evidence[] {
  const versions = context.tlsVersions;
  const evidence: Evidence[] = [
    { label: "Host", value: context.finalUrl.host },
    {
      label: "Conexión normal (cliente actual)",
      value: `negocia ${context.primary.tls?.protocol ?? "versión desconocida"}${context.primary.tls?.cipher ? ` con ${context.primary.tls.cipher}` : ""}`,
    },
  ];

  if (versions) {
    for (const version of TLS_VERSIONS) {
      evidence.push({
        label: `Saludo solo con ${TLS_LABEL[version]}`,
        value: describeProbe(versions[version]),
      });
    }
  }

  return evidence;
}

function tlsVersionCheck(context: ScanContext) {
  if (!context.isHttps) return NOT_HTTPS;

  const protocol = context.primary.tls?.protocol;

  if (!protocol) return errored("No se pudo leer la versión de TLS negociada.");

  const evidence = tlsEvidence(context);

  if (protocol !== "TLSv1.3" && protocol !== "TLSv1.2") {
    return fail(
      `Con un cliente actual, el servidor negocia ${protocol}: no ofrece ninguna versión vigente de TLS.`,
      "Activa TLS 1.2 y TLS 1.3 en el servidor o en tu proveedor de hosting.",
      { evidence },
    );
  }

  const tls13 = context.tlsVersions?.["TLSv1.3"];
  const note =
    protocol === "TLSv1.2" && tls13?.outcome === "rejected"
      ? " El servidor no ofrece TLS 1.3; TLS 1.2 sigue siendo válido, pero conviene activar también la versión más reciente."
      : "";

  return pass(
    `Con un cliente actual (como un navegador moderno) la conexión se establece con ${protocol}, una versión vigente.${note}`,
    { evidence },
  );
}

function legacyTlsCheck(context: ScanContext) {
  if (!context.isHttps || !context.tlsVersions) return NOT_HTTPS;

  const negotiated = context.primary.tls?.protocol;

  if (negotiated && negotiated !== "TLSv1.3" && negotiated !== "TLSv1.2") {
    return notApplicable(
      "El servidor ni siquiera ofrece una versión actual de TLS; ya está recogido en «Versión de TLS negociada».",
    );
  }

  const legacy = (["TLSv1", "TLSv1.1"] as const).map((version) => ({
    version,
    probe: context.tlsVersions![version],
  }));
  const accepted = legacy.filter(({ probe }) => probe.outcome === "accepted");
  const untestable = legacy.filter(({ probe }) => probe.outcome === "error");
  const evidence = tlsEvidence(context);
  const list = (items: typeof legacy) =>
    items.map(({ version }) => TLS_LABEL[version]).join(" y ");

  if (accepted.length > 0) {
    const rest = legacy.filter(({ probe }) => probe.outcome !== "accepted");
    const others =
      rest.length === 0
        ? ""
        : untestable.length > 0
          ? ` ${list(rest)} no se ha podido comprobar.`
          : ` ${list(rest)} no se ha aceptado.`;

    return fail(
      `El servidor todavía acepta conexiones con ${list(accepted)}, ${accepted.length > 1 ? "versiones retiradas" : "una versión retirada"} en 2021 (RFC 8996).${others} Esto no cambia cómo conectan los navegadores actuales, que con este servidor negocian ${negotiated ?? "una versión vigente"}: solo un cliente antiguo, o uno forzado a bajar de versión, usaría ${accepted.length > 1 ? "esas versiones" : "esa versión"}. Normas como PCI DSS exigen desactivarlas.`,
      "Desactiva TLS 1.0 y TLS 1.1 y deja TLS 1.2 y 1.3. Si das servicio a dispositivos muy antiguos, valora antes el impacto.",
      {
        evidence: [
          ...evidence,
          ...accepted.map(({ version }) => ({
            label: `Cómo reproducirlo (${TLS_LABEL[version]})`,
            value: `openssl s_client -connect ${context.finalUrl.hostname}:443 -servername ${context.finalUrl.hostname} ${OPENSSL_FLAG[version]}`,
          })),
        ],
      },
    );
  }

  if (untestable.length > 0) {
    // Un fallo del cliente o de la red no demuestra nada sobre el servidor.
    return notTested(
      `No se ha podido realizar una prueba válida de ${list(untestable)}, así que no se puede afirmar si el servidor ${untestable.length > 1 ? "las" : "la"} acepta o ${untestable.length > 1 ? "las" : "la"} rechaza. No se penaliza.`,
      { evidence },
    );
  }

  const explicit = legacy.every(
    ({ probe }) => probe.outcome === "rejected" && probe.explicit,
  );

  return pass(
    explicit
      ? "El servidor rechaza TLS 1.0 y TLS 1.1: responde que no admite esas versiones."
      : "El servidor no ha completado ningún saludo con TLS 1.0 ni TLS 1.1. En algún caso cortó la conexión sin indicar el motivo, lo que es coherente con que no las admita.",
    { evidence, confidence: explicit ? "high" : "medium" },
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

const HSTS_BASE = '"Strict-Transport-Security: max-age=31536000"';

/**
 * Recomendación progresiva. `includeSubDomains` y `preload` nunca se
 * sugieren como primer paso: obligan a que TODOS los subdominios funcionen
 * por HTTPS, y eso no se puede comprobar desde un análisis de una sola web.
 */
const HSTS_ROLLOUT =
  'Empieza con un valor corto para probar, por ejemplo "Strict-Transport-Security: max-age=86400" (un día), y cuando compruebes que todo funciona súbelo a un año ("max-age=31536000"). Añade "includeSubDomains" solo después de verificar que todos los subdominios, actuales y previstos, funcionan por HTTPS: con esa opción el navegador dejará de abrir por HTTP cualquier subdominio. "preload" es todavía más difícil de revertir y no es necesario.';

function hstsCheck(context: ScanContext) {
  if (!context.isHttps) return NOT_HTTPS;

  const raw = context.headers["strict-transport-security"];
  // RFC 6797 §8.1: si llegan varias cabeceras solo cuenta la primera.
  const value = firstHeaderValue(raw);
  const evidence = [
    { label: "strict-transport-security", value: raw ?? "(no enviada)" },
  ];

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
      "La web no envía Strict-Transport-Security. Sin ella, cuando alguien escribe la dirección sin «https://» o sigue un enlace http://, la primera petición viaja sin cifrar y podría ser interceptada antes de la redirección a HTTPS.",
      HSTS_ROLLOUT,
      { evidence },
    );
  }

  const maxAge = parseHstsMaxAge(value);

  if (maxAge === null) {
    return fail(
      "La cabecera Strict-Transport-Security no tiene un max-age válido, así que el navegador la ignora.",
      `Usa ${HSTS_BASE}. ${HSTS_ROLLOUT}`,
      { evidence },
    );
  }

  if (maxAge === 0) {
    return fail(
      'La web envía Strict-Transport-Security con "max-age=0", que ordena al navegador OLVIDAR la protección.',
      `Si no es intencionado (max-age=0 se usa para retirar HSTS), usa ${HSTS_BASE}.`,
      { evidence },
    );
  }

  if (maxAge < HSTS_MIN_MAX_AGE) {
    return warning(
      0.5,
      `HSTS está activo, pero con una duración corta (max-age=${maxAge} s, unos ${Math.max(1, Math.round(maxAge / 86_400))} día(s)). Es razonable mientras se prueba; para una protección estable se recomienda al menos 6 meses.`,
      `Cuando hayas comprobado que todo funciona por HTTPS, sube la duración a un año: ${HSTS_BASE}.`,
      { evidence },
    );
  }

  const lower = value.toLowerCase();
  const includeSubDomains = /;\s*includesubdomains\b/.test(lower);
  const preload = /;\s*preload\b/.test(lower);
  let detail = includeSubDomains
    ? " La cabecera incluye includeSubDomains, así que también se aplica a los subdominios."
    : " Se aplica solo a este nombre de host: no incluye includeSubDomains, que es opcional y solo conviene añadir si todos los subdominios funcionan por HTTPS.";

  if (preload && (!includeSubDomains || maxAge < HSTS_PRELOAD_MIN_MAX_AGE)) {
    detail +=
      ' Declara "preload" sin cumplir sus requisitos (un año e includeSubDomains), así que no tiene efecto.';
  }

  return pass(`HSTS está activo con una duración suficiente.${detail}`, {
    evidence,
  });
}

export const transportChecks: Check[] = [
  { id: "transport.https", run: httpsCheck },
  { id: "transport.certificate", run: certificateCheck },
  { id: "transport.tls-version", run: tlsVersionCheck },
  { id: "transport.legacy-tls", run: legacyTlsCheck },
  { id: "transport.http-redirect", run: httpRedirectCheck },
  { id: "transport.hsts", run: hstsCheck },
];
