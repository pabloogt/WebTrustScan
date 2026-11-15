/**
 * Por qué se considera que una cookie puede ser de sesión:
 * - "known": su nombre es el de sesión de un framework conocido (PHPSESSID…).
 * - "hint": su nombre sugiere sesión/autenticación Y su valor es lo bastante
 *   largo como para ser un identificador.
 * Desde fuera y sin iniciar sesión no se puede saber con certeza: es una
 * heurística, y la confianza del hallazgo lo refleja.
 */
export type SessionSignal = "known" | "hint";

export type ParsedCookie = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  /** Valor de SameSite en minúsculas, o null si no se declara. */
  sameSite: string | null;
  domain: string | null;
  path: string | null;
  /** true si no lleva Expires ni Max-Age (cookie de sesión del navegador). */
  sessionLifetime: boolean;
  sessionSignal: SessionSignal | null;
  /** Atajo: `sessionSignal !== null`. */
  sessionLike: boolean;
};

const KNOWN_SESSION_NAMES = new Set([
  "phpsessid",
  "jsessionid",
  "asp.net_sessionid",
  ".aspnetcore.session",
  ".aspnetcore.identity.application",
  "connect.sid",
  "laravel_session",
  "sessionid",
  "_session_id",
  "ci_session",
  "cfid",
  "cftoken",
]);

const SESSION_HINT =
  /(sess|^sid$|_sid$|auth|token|jwt|login|logged_in|remember|identity|passport)/i;
/** Los tokens anti-CSRF suelen tener que ser legibles desde JavaScript. */
const CSRF_HINT = /(csrf|xsrf)/i;

function nameSignal(name: string): SessionSignal | null {
  const lower = name.toLowerCase();

  if (CSRF_HINT.test(lower)) return null;
  if (KNOWN_SESSION_NAMES.has(lower)) return "known";

  return SESSION_HINT.test(lower) ? "hint" : null;
}

/** ¿El nombre, por sí solo, sugiere una cookie de sesión? */
export function isSessionLikeName(name: string): boolean {
  return nameSignal(name) !== null;
}

/**
 * Un identificador de sesión es largo. Un valor corto (un idioma, una fecha
 * en segundos, un indicador) no puede serlo. No se exige mezcla de letras y
 * cifras: hay identificadores solo numéricos o solo hexadecimales, y
 * descartarlos cambiaría falsos positivos por falsos negativos.
 */
export function looksOpaque(value: string): boolean {
  return value.length >= 16;
}

/**
 * Parsea una cabecera Set-Cookie. El valor de la cookie se descarta a
 * propósito: solo se usa aquí para decidir si parece un identificador, y
 * nunca se guarda ni se muestra en informes.
 *
 * Devuelve null para cabeceras sin nombre y para BORRADOS de cookie (valor
 * vacío, fecha de caducidad pasada o Max-Age ≤ 0): no establecen nada.
 */
export function parseSetCookie(
  header: string,
  now: Date = new Date(),
): ParsedCookie | null {
  const [pair, ...attributes] = header.split(";");
  const separator = pair.indexOf("=");
  const name = (separator === -1 ? pair : pair.slice(0, separator)).trim();
  const value = separator === -1 ? "" : pair.slice(separator + 1).trim();

  if (!name) return null;

  const signal = nameSignal(name);
  const cookie: ParsedCookie = {
    name,
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    sessionLifetime: true,
    sessionSignal:
      signal === "known" || (signal === "hint" && looksOpaque(value))
        ? signal
        : null,
    sessionLike: false,
  };
  cookie.sessionLike = cookie.sessionSignal !== null;

  const empty = value === "" || value === '""';
  // RFC 6265 §5.3: si hay Max-Age, Expires se ignora.
  let expiredByDate = false;
  let maxAge: number | null = null;

  for (const attribute of attributes) {
    const index = attribute.indexOf("=");
    const key = (index === -1 ? attribute : attribute.slice(0, index))
      .trim()
      .toLowerCase();
    const attributeValue = index === -1 ? "" : attribute.slice(index + 1).trim();

    if (key === "secure") cookie.secure = true;
    else if (key === "httponly") cookie.httpOnly = true;
    else if (key === "samesite") {
      cookie.sameSite = attributeValue.toLowerCase() || null;
    } else if (key === "domain") {
      cookie.domain = attributeValue.toLowerCase().replace(/^\./, "") || null;
    } else if (key === "path") cookie.path = attributeValue || null;
    else if (key === "expires") {
      cookie.sessionLifetime = false;
      const expires = Date.parse(attributeValue);
      if (!Number.isNaN(expires) && expires <= now.getTime()) expiredByDate = true;
    } else if (key === "max-age" && /^-?\d+$/.test(attributeValue)) {
      cookie.sessionLifetime = false;
      maxAge = Number(attributeValue);
    }
  }

  const deletion = empty || (maxAge !== null ? maxAge <= 0 : expiredByDate);

  return deletion ? null : cookie;
}

export function parseCookies(
  headers: string[],
  now: Date = new Date(),
): ParsedCookie[] {
  const byIdentity = new Map<string, ParsedCookie>();

  for (const header of headers) {
    const cookie = parseSetCookie(header, now);
    // Una cookie se identifica por nombre + dominio + ruta. Si se repite
    // exactamente la misma, el navegador se queda con la última.
    if (cookie) {
      byIdentity.set(
        `${cookie.name}|${cookie.domain ?? ""}|${cookie.path ?? ""}`,
        cookie,
      );
    }
  }

  return [...byIdentity.values()];
}

/** Descripción de una cookie para la evidencia (sin su valor). */
export function describeCookie(cookie: ParsedCookie): string {
  const flags = [
    cookie.secure ? "Secure" : null,
    cookie.httpOnly ? "HttpOnly" : null,
    cookie.sameSite ? `SameSite=${cookie.sameSite}` : null,
  ].filter(Boolean);
  const scope = cookie.domain ? ` (dominio ${cookie.domain})` : "";
  const reason =
    cookie.sessionSignal === "known"
      ? " · nombre de sesión de un framework conocido"
      : cookie.sessionSignal === "hint"
        ? " · el nombre sugiere sesión y el valor tiene longitud de identificador"
        : "";

  return `${cookie.name}${scope} → ${flags.length > 0 ? flags.join("; ") : "sin Secure, HttpOnly ni SameSite"}${reason}`;
}
