import type { CategoryId, CheckDefinition, ReportId } from "./types";

/**
 * Catálogo central de comprobaciones. Es la única fuente de verdad de
 * identificadores, categorías, severidades y pesos: los módulos de análisis
 * solo deciden el RESULTADO de cada control, nunca cuánto pesa.
 *
 * Criterio de pesos (ver SCORING_MODEL.md):
 *   crítico 10 · alto 6–10 · medio 4–8 · bajo 1–4 · informativo 0
 */

const REF = {
  hsts: "RFC 6797 · OWASP Secure Headers: Strict-Transport-Security",
  tls: "RFC 8996 (retirada de TLS 1.0/1.1) · OWASP WSTG-CRYP-01",
  cert: "RFC 5280 · RFC 9525 · OWASP WSTG-CRYP-01",
  csp: "W3C CSP Level 3 · OWASP WSTG-CONF-12 · ASVS 5.0 V3.4",
  frame: "CSP3 frame-ancestors · RFC 7034 · OWASP WSTG-CLNT-09",
  nosniff: "WHATWG Fetch (X-Content-Type-Options) · ASVS 5.0 V3.4",
  referrer: "W3C Referrer Policy · ASVS 5.0 V3.4",
  permissions: "W3C Permissions Policy · OWASP Secure Headers",
  cookies: "RFC 6265bis · OWASP WSTG-SESS-02 · ASVS 5.0 V3.3",
  cors: "WHATWG Fetch (CORS) · OWASP WSTG-CLNT-07 · ASVS 5.0 V3.4",
  mixed: "W3C Mixed Content · OWASP WSTG-CRYP-03",
  sri: "W3C Subresource Integrity · ASVS 5.0 V3.6",
  disclosure: "OWASP WSTG-INFO-02 · RFC 9110 §10.2.4",
  securityTxt: "RFC 9116 (security.txt)",
  coop: "WHATWG HTML (COOP/COEP) · OWASP Secure Headers",
  caa: "RFC 8659 (CAA)",
  spf: "RFC 7208 (SPF)",
  dmarc: "RFC 7489 (DMARC)",
};

export const CATALOG = [
  /* ---------- Transporte ---------- */
  {
    id: "transport.https",
    report: "web",
    category: "transport",
    title: "HTTPS disponible",
    summary: "La web se sirve por una conexión cifrada.",
    severity: "critical",
    weight: 10,
    method: "passive",
    capOnFail: 35,
    references: [REF.tls],
  },
  {
    id: "transport.certificate",
    report: "web",
    category: "transport",
    title: "Certificado válido",
    summary:
      "El certificado es de confianza, corresponde al dominio y no ha caducado.",
    severity: "critical",
    weight: 10,
    method: "passive",
    capOnFail: 30,
    references: [REF.cert],
  },
  {
    id: "transport.tls-version",
    report: "web",
    category: "transport",
    title: "Versión de TLS negociada",
    summary: "La conexión se establece con TLS 1.2 o superior.",
    severity: "high",
    weight: 4,
    method: "passive",
    references: [REF.tls],
  },
  {
    id: "transport.legacy-tls",
    report: "web",
    category: "transport",
    title: "Protocolos TLS obsoletos",
    summary: "El servidor rechaza TLS 1.0 y TLS 1.1.",
    // Solo afecta a clientes obsoletos: los navegadores actuales no
    // negocian estas versiones.
    severity: "low",
    weight: 3,
    method: "active",
    references: [REF.tls],
  },
  {
    id: "transport.http-redirect",
    report: "web",
    category: "transport",
    title: "Redirección de HTTP a HTTPS",
    summary: "La versión http:// lleva a la versión segura del mismo sitio.",
    severity: "medium",
    weight: 6,
    method: "active",
    references: [REF.hsts],
  },
  {
    id: "transport.hsts",
    report: "web",
    category: "transport",
    title: "Strict-Transport-Security (HSTS)",
    summary: "El navegador recuerda usar siempre HTTPS con este sitio.",
    severity: "medium",
    weight: 8,
    method: "passive",
    references: [REF.hsts],
  },

  /* ---------- Cabeceras del navegador ---------- */
  {
    id: "headers.csp",
    report: "web",
    category: "headers",
    title: "Content-Security-Policy",
    summary: "Existe una política que limita de dónde se ejecutan scripts.",
    // Es una defensa en profundidad: su ausencia no es una vulnerabilidad
    // por sí misma. Pesa mucho en la nota, pero su severidad es media.
    severity: "medium",
    weight: 10,
    method: "passive",
    references: [REF.csp],
  },
  {
    id: "headers.clickjacking",
    report: "web",
    category: "headers",
    title: "Protección frente a clickjacking",
    summary:
      "frame-ancestors (CSP) o X-Frame-Options impiden incrustar la web en páginas ajenas.",
    severity: "medium",
    weight: 6,
    method: "passive",
    references: [REF.frame],
  },
  {
    id: "headers.nosniff",
    report: "web",
    category: "headers",
    title: "X-Content-Type-Options",
    summary: "El navegador no reinterpreta el tipo de los archivos.",
    severity: "low",
    weight: 4,
    method: "passive",
    references: [REF.nosniff],
  },
  {
    id: "headers.referrer-policy",
    report: "web",
    category: "headers",
    title: "Referrer-Policy",
    summary: "Se limita la información de navegación enviada a otros sitios.",
    severity: "low",
    weight: 2,
    method: "passive",
    references: [REF.referrer],
  },
  {
    id: "headers.permissions-policy",
    report: "web",
    category: "headers",
    title: "Permissions-Policy",
    summary: "Se restringen funciones del navegador que la web no necesita.",
    severity: "low",
    weight: 2,
    method: "passive",
    references: [REF.permissions],
  },
  {
    id: "headers.cross-origin-isolation",
    report: "web",
    category: "headers",
    title: "Aislamiento entre orígenes (COOP/COEP/CORP)",
    summary:
      "Cabeceras de aislamiento. Solo son necesarias para funciones concretas.",
    severity: "info",
    weight: 0,
    method: "passive",
    references: [REF.coop],
  },

  /* ---------- Cookies ---------- */
  {
    id: "cookies.secure",
    report: "web",
    category: "cookies",
    title: "Cookies con atributo Secure",
    summary: "Las cookies solo viajan por conexiones cifradas.",
    severity: "medium",
    weight: 6,
    method: "passive",
    references: [REF.cookies],
  },
  {
    id: "cookies.httponly",
    report: "web",
    category: "cookies",
    title: "Cookies de sesión con HttpOnly",
    summary: "Las cookies de sesión no son accesibles desde JavaScript.",
    severity: "medium",
    weight: 6,
    method: "passive",
    references: [REF.cookies],
  },
  {
    id: "cookies.samesite",
    report: "web",
    category: "cookies",
    title: "Cookies con SameSite",
    summary: "Las cookies declaran cuándo pueden enviarse desde otros sitios.",
    severity: "low",
    weight: 3,
    method: "passive",
    references: [REF.cookies],
  },

  /* ---------- CORS ---------- */
  {
    id: "cors.policy",
    report: "web",
    category: "cors",
    title: "Política CORS",
    summary:
      "El sitio no concede acceso con credenciales a orígenes arbitrarios.",
    severity: "high",
    weight: 4,
    method: "active",
    references: [REF.cors],
  },

  /* ---------- Contenido ---------- */
  {
    id: "content.mixed-content",
    report: "web",
    category: "content",
    title: "Contenido mixto",
    summary: "La página HTTPS no carga recursos por HTTP sin cifrar.",
    severity: "medium",
    weight: 4,
    method: "passive",
    references: [REF.mixed],
  },
  {
    id: "content.insecure-forms",
    report: "web",
    category: "content",
    title: "Formularios enviados sin cifrar",
    summary: "Ningún formulario envía datos (o contraseñas) por HTTP.",
    severity: "high",
    weight: 6,
    method: "passive",
    references: [REF.mixed],
  },
  {
    id: "content.sri",
    report: "web",
    category: "content",
    title: "Integridad de recursos de terceros (SRI)",
    summary: "Los scripts y estilos de otros dominios llevan `integrity`.",
    severity: "low",
    weight: 2,
    method: "passive",
    references: [REF.sri],
  },

  /* ---------- Exposición de información ---------- */
  {
    id: "disclosure.banner",
    report: "web",
    category: "disclosure",
    title: "Versiones de software expuestas",
    summary: "Las cabeceras no revelan versiones exactas del software.",
    severity: "low",
    weight: 1,
    method: "passive",
    references: [REF.disclosure],
  },
  {
    id: "disclosure.security-txt",
    report: "web",
    category: "disclosure",
    title: "security.txt",
    summary: "Existe un canal publicado para comunicar vulnerabilidades.",
    severity: "info",
    weight: 0,
    method: "active",
    references: [REF.securityTxt],
  },

  /* ---------- DNS y correo (informe independiente) ---------- */
  {
    id: "dns.caa",
    report: "dns-email",
    category: "dns",
    title: "Registros CAA",
    summary: "El dominio limita qué autoridades pueden emitir certificados.",
    // CAA es opcional (RFC 8659) y la mayoría de dominios no lo publica:
    // se recomienda, pero su ausencia no puntúa.
    severity: "info",
    weight: 0,
    method: "passive",
    references: [REF.caa],
  },
  {
    id: "email.spf",
    report: "dns-email",
    category: "email",
    title: "SPF",
    summary: "El dominio declara qué servidores pueden enviar su correo.",
    severity: "medium",
    weight: 5,
    method: "passive",
    references: [REF.spf],
  },
  {
    id: "email.dmarc",
    report: "dns-email",
    category: "email",
    title: "DMARC",
    summary:
      "El dominio indica qué hacer con el correo que suplanta su identidad.",
    severity: "medium",
    weight: 6,
    method: "passive",
    references: [REF.dmarc],
  },
] as const satisfies readonly CheckDefinition[];

export type CheckId = (typeof CATALOG)[number]["id"];

const BY_ID = new Map<string, CheckDefinition>(
  CATALOG.map((definition) => [definition.id, definition]),
);

export function getDefinition(id: CheckId): CheckDefinition {
  const definition = BY_ID.get(id);
  if (!definition) throw new Error(`Check desconocido: ${id}`);
  return definition;
}

export const CATEGORY_LABELS: Record<CategoryId, string> = {
  transport: "Cifrado y transporte",
  headers: "Protecciones del navegador",
  cookies: "Cookies y sesión",
  cors: "Acceso entre orígenes",
  content: "Contenido de la página",
  disclosure: "Exposición de información",
  dns: "DNS",
  email: "Autenticación del correo",
};

export const REPORT_LABELS: Record<ReportId, string> = {
  web: "Seguridad web",
  "dns-email": "Correo y DNS",
};

export const CATEGORY_ORDER: Record<ReportId, CategoryId[]> = {
  web: ["transport", "headers", "cookies", "cors", "content", "disclosure"],
  "dns-email": ["email", "dns"],
};
