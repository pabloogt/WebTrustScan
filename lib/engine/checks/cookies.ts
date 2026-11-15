import {
  fail,
  notApplicable,
  pass,
  responseLevel,
  warning,
  type Check,
  type Outcome,
  type ScanContext,
} from "../context";
import { describeCookie, type ParsedCookie } from "../parse/cookies";
import type { Confidence, Evidence } from "../types";

const NO_COOKIES = notApplicable(
  "La web no ha establecido ninguna cookie en la página analizada, así que no hay nada que proteger. No tener cookies no es un problema.",
);

/**
 * Límite de lo que se puede afirmar: el análisis es anónimo, así que nunca
 * ve la cookie que se emite al iniciar sesión.
 */
const SCOPE_NOTE =
  " Qué cookies son de sesión se deduce de su nombre y de que su valor parece un identificador; el análisis no inicia sesión, así que no puede confirmarlo.";

function evidenceOf(cookies: ParsedCookie[]): Evidence[] {
  return cookies
    .slice(0, 12)
    .map((cookie) => ({ label: "Cookie", value: describeCookie(cookie) }));
}

function names(cookies: ParsedCookie[]): string {
  const list = cookies.slice(0, 4).map((cookie) => cookie.name);
  return list.join(", ") + (cookies.length > 4 ? "…" : "");
}

/**
 * Un nombre de sesión de framework conocido es un indicio razonable
 * (confianza media); un nombre "que suena a sesión" es más débil (baja).
 */
function confidenceOf(cookies: ParsedCookie[]): Confidence {
  return cookies.some((cookie) => cookie.sessionSignal === "known")
    ? "medium"
    : "low";
}

function withCookies(
  context: ScanContext,
  evaluate: (cookies: ParsedCookie[]) => Outcome,
): Outcome {
  return responseLevel(context, () =>
    context.cookies.length === 0 ? NO_COOKIES : evaluate(context.cookies),
  );
}

function secureCheck(context: ScanContext) {
  return withCookies(context, (cookies) => {
    if (!context.isHttps) {
      return notApplicable(
        "La web no usa HTTPS, así que el atributo Secure no puede aplicarse. El problema de fondo ya está recogido en «HTTPS disponible».",
      );
    }

    const missing = cookies.filter((cookie) => !cookie.secure);
    const remediation =
      'Añade el atributo "Secure" a todas las cookies para que nunca viajen por HTTP.';

    if (missing.length === 0) {
      return pass(
        `Las ${cookies.length} cookies establecidas llevan el atributo Secure.`,
        { evidence: evidenceOf(cookies) },
      );
    }

    // Los prefijos __Secure- y __Host- obligan a llevar Secure: sin él, el
    // navegador descarta la cookie. Esto es un hecho, no una heurística.
    const badPrefix = missing.filter((cookie) =>
      /^__(secure|host)-/i.test(cookie.name),
    );

    if (badPrefix.length > 0) {
      return fail(
        `Hay cookies con prefijo __Secure- o __Host- sin el atributo Secure (${names(badPrefix)}): el navegador las rechaza.`,
        remediation,
        { evidence: evidenceOf(badPrefix) },
      );
    }

    const sessionLike = missing.filter((cookie) => cookie.sessionLike);

    if (sessionLike.length > 0) {
      return fail(
        `Hay cookies que podrían ser de sesión sin el atributo Secure (${names(sessionLike)}): podrían enviarse por una conexión sin cifrar.${SCOPE_NOTE}`,
        remediation,
        {
          evidence: evidenceOf(sessionLike),
          confidence: confidenceOf(sessionLike),
        },
      );
    }

    return warning(
      0.6,
      `${missing.length} de ${cookies.length} cookies no llevan Secure (${names(missing)}). No parecen de sesión (preferencias, idioma o similares), pero pueden viajar sin cifrar si alguna petición se hace por HTTP.`,
      remediation,
      { evidence: evidenceOf(missing), severity: "low" },
    );
  });
}

function httpOnlyCheck(context: ScanContext) {
  return withCookies(context, (cookies) => {
    const sessionLike = cookies.filter((cookie) => cookie.sessionLike);

    if (sessionLike.length === 0) {
      return notApplicable(
        "Ninguna de las cookies establecidas parece de sesión o autenticación. HttpOnly solo es necesario en esas; otras cookies pueden necesitar que JavaScript las lea.",
      );
    }

    const missing = sessionLike.filter((cookie) => !cookie.httpOnly);

    return missing.length === 0
      ? pass(
          "Las cookies que parecen de sesión llevan HttpOnly: un script inyectado no puede leerlas.",
          { evidence: evidenceOf(sessionLike) },
        )
      : fail(
          `Hay cookies que podrían ser de sesión sin HttpOnly (${names(missing)}): si lo son, un script inyectado (XSS) podría leerlas.${SCOPE_NOTE}`,
          'Añade el atributo "HttpOnly" a las cookies de sesión y autenticación. Si la cookie no identifica una sesión, puedes ignorar este aviso.',
          { evidence: evidenceOf(missing), confidence: confidenceOf(missing) },
        );
  });
}

function sameSiteCheck(context: ScanContext) {
  return withCookies(context, (cookies) => {
    const noneWithoutSecure = cookies.filter(
      (cookie) => cookie.sameSite === "none" && !cookie.secure,
    );

    if (noneWithoutSecure.length > 0) {
      return fail(
        `Hay cookies con "SameSite=None" sin "Secure" (${names(noneWithoutSecure)}): los navegadores las rechazan.`,
        'Las cookies con "SameSite=None" deben llevar también "Secure".',
        { evidence: evidenceOf(noneWithoutSecure) },
      );
    }

    const undeclared = cookies.filter(
      (cookie) => cookie.sessionLike && cookie.sameSite === null,
    );

    return undeclared.length === 0
      ? pass(
          "Las cookies de sesión declaran SameSite (o no hay cookies de sesión que lo necesiten).",
          { evidence: evidenceOf(cookies) },
        )
      : warning(
          0.5,
          `Hay cookies que podrían ser de sesión sin SameSite (${names(undeclared)}). Chrome y Edge aplican "Lax" por defecto; Firefox y Safari no en todos los casos, lo que deja más margen a ataques CSRF.${SCOPE_NOTE}`,
          'Declara "SameSite=Lax" (o "Strict") en las cookies de sesión.',
          {
            evidence: evidenceOf(undeclared),
            confidence: confidenceOf(undeclared),
          },
        );
  });
}

export const cookieChecks: Check[] = [
  { id: "cookies.secure", run: secureCheck },
  { id: "cookies.httponly", run: httpOnlyCheck },
  { id: "cookies.samesite", run: sameSiteCheck },
];
