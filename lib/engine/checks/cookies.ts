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
import type { Evidence } from "../types";

const NO_COOKIES = notApplicable(
  "La web no ha establecido ninguna cookie en la página analizada, así que no hay nada que proteger. No tener cookies no es un problema.",
);

const SCOPE_NOTE =
  " (Solo se ven las cookies que la web establece a un visitante sin iniciar sesión.)";

function evidenceOf(cookies: ParsedCookie[]): Evidence[] {
  return cookies
    .slice(0, 12)
    .map((cookie) => ({ label: "Cookie", value: describeCookie(cookie) }));
}

function names(cookies: ParsedCookie[]): string {
  const list = cookies.slice(0, 4).map((cookie) => cookie.name);
  return list.join(", ") + (cookies.length > 4 ? "…" : "");
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

    const evidence = evidenceOf(cookies);
    const missing = cookies.filter((cookie) => !cookie.secure);
    const remediation =
      'Añade el atributo "Secure" a todas las cookies para que nunca viajen por HTTP.';

    // Los prefijos __Secure- y __Host- obligan a llevar Secure: sin él, el
    // navegador descarta la cookie.
    const badPrefix = missing.filter((cookie) =>
      /^__(secure|host)-/i.test(cookie.name),
    );

    if (missing.length === 0) {
      return pass(
        `Las ${cookies.length} cookies establecidas llevan el atributo Secure.`,
        { evidence },
      );
    }

    const sessionLike = missing.filter((cookie) => cookie.sessionLike);

    if (sessionLike.length > 0 || badPrefix.length > 0) {
      return fail(
        `Hay cookies que parecen de sesión sin el atributo Secure (${names(sessionLike.length > 0 ? sessionLike : badPrefix)}): podrían enviarse por una conexión sin cifrar.${SCOPE_NOTE}`,
        remediation,
        { evidence, confidence: "medium" },
      );
    }

    return warning(
      0.5,
      `${missing.length} de ${cookies.length} cookies no llevan Secure (${names(missing)}). No parecen de sesión, pero pueden viajar sin cifrar.`,
      remediation,
      { evidence },
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

    const evidence = evidenceOf(sessionLike);
    const missing = sessionLike.filter((cookie) => !cookie.httpOnly);

    return missing.length === 0
      ? pass(
          "Las cookies que parecen de sesión llevan HttpOnly: un script inyectado no puede leerlas.",
          { evidence },
        )
      : fail(
          `Hay cookies que parecen de sesión sin HttpOnly (${names(missing)}): un script inyectado (XSS) podría robarlas.${SCOPE_NOTE}`,
          'Añade el atributo "HttpOnly" a las cookies de sesión y autenticación.',
          // La clasificación "de sesión" se deduce del nombre: es una heurística.
          { evidence, confidence: "medium" },
        );
  });
}

function sameSiteCheck(context: ScanContext) {
  return withCookies(context, (cookies) => {
    const evidence = evidenceOf(cookies);
    const noneWithoutSecure = cookies.filter(
      (cookie) => cookie.sameSite === "none" && !cookie.secure,
    );

    if (noneWithoutSecure.length > 0) {
      return fail(
        `Hay cookies con "SameSite=None" sin "Secure" (${names(noneWithoutSecure)}): los navegadores las rechazan.`,
        'Las cookies con "SameSite=None" deben llevar también "Secure".',
        { evidence },
      );
    }

    const undeclared = cookies.filter(
      (cookie) => cookie.sessionLike && cookie.sameSite === null,
    );

    return undeclared.length === 0
      ? pass(
          "Las cookies de sesión declaran SameSite (o no hay cookies de sesión que lo necesiten).",
          { evidence },
        )
      : warning(
          0.5,
          `Hay cookies que parecen de sesión sin SameSite (${names(undeclared)}). Chrome y Edge aplican "Lax" por defecto, pero otros navegadores no, lo que facilita ataques CSRF.`,
          'Declara "SameSite=Lax" (o "Strict") en las cookies de sesión.',
          { evidence, confidence: "medium" },
        );
  });
}

export const cookieChecks: Check[] = [
  { id: "cookies.secure", run: secureCheck },
  { id: "cookies.httponly", run: httpOnlyCheck },
  { id: "cookies.samesite", run: sameSiteCheck },
];
