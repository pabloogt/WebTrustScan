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
  /** Heurística: parece una cookie de sesión o autenticación. */
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

export function isSessionLikeName(name: string): boolean {
  const lower = name.toLowerCase();

  if (CSRF_HINT.test(lower)) return false;

  return KNOWN_SESSION_NAMES.has(lower) || SESSION_HINT.test(lower);
}

/**
 * Parsea una cabecera Set-Cookie. El valor de la cookie se descarta a
 * propósito: nunca se guarda ni se muestra en informes.
 */
export function parseSetCookie(header: string): ParsedCookie | null {
  const [pair, ...attributes] = header.split(";");
  const separator = pair.indexOf("=");
  const name = (separator === -1 ? pair : pair.slice(0, separator)).trim();

  if (!name) return null;

  const cookie: ParsedCookie = {
    name,
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    sessionLifetime: true,
    sessionLike: isSessionLikeName(name),
  };

  for (const attribute of attributes) {
    const index = attribute.indexOf("=");
    const key = (index === -1 ? attribute : attribute.slice(0, index))
      .trim()
      .toLowerCase();
    const value = index === -1 ? "" : attribute.slice(index + 1).trim();

    if (key === "secure") cookie.secure = true;
    else if (key === "httponly") cookie.httpOnly = true;
    else if (key === "samesite") cookie.sameSite = value.toLowerCase() || null;
    else if (key === "domain") cookie.domain = value || null;
    else if (key === "path") cookie.path = value || null;
    else if (key === "expires" || key === "max-age") cookie.sessionLifetime = false;
  }

  return cookie;
}

export function parseCookies(headers: string[]): ParsedCookie[] {
  const byName = new Map<string, ParsedCookie>();

  for (const header of headers) {
    const cookie = parseSetCookie(header);
    // Si una cookie se repite, el navegador se queda con la última.
    if (cookie) byName.set(cookie.name, cookie);
  }

  return [...byName.values()];
}

/** Descripción de una cookie para la evidencia (sin su valor). */
export function describeCookie(cookie: ParsedCookie): string {
  const flags = [
    cookie.secure ? "Secure" : null,
    cookie.httpOnly ? "HttpOnly" : null,
    cookie.sameSite ? `SameSite=${cookie.sameSite}` : null,
  ].filter(Boolean);

  return `${cookie.name} → ${flags.length > 0 ? flags.join("; ") : "sin atributos de seguridad"}`;
}
