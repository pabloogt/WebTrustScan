/**
 * MOTOR 1.x (CONGELADO). La aplicación usa el Engine 2.0 de `lib/engine`.
 * Este módulo se conserva sin cambios funcionales como referencia para el
 * laboratorio (tests/lab), que compara las puntuaciones antiguas y nuevas,
 * y para mantener la suite histórica. No añadir funcionalidad aquí.
 */
import type { AuditCheck, CheckStatus } from "@/types/audit";

export type HttpRedirectResult = "redirects" | "no-redirect" | "unknown";

export type CheckInput = {
  /** URL final analizada (tras redirecciones). */
  finalUrl: string;
  /** Cabeceras de la respuesta final, con nombres en minúsculas. */
  headers: Record<string, string>;
  /** Resultado de la comprobación de redirección HTTP → HTTPS. */
  httpRedirect: HttpRedirectResult;
};

/**
 * Peso de cada check en la puntuación. Es la única fuente de verdad:
 * `buildChecks` genera exactamente estas claves (hay un test que lo garantiza).
 */
export const CHECK_WEIGHTS = {
  https: 20,
  "http-redirect": 10,
  hsts: 10,
  csp: 12,
  "frame-protection": 10,
  "x-content-type-options": 10,
  "referrer-policy": 8,
  "permissions-policy": 8,
} as const;

export type CheckKey = keyof typeof CHECK_WEIGHTS;

type Verdict = { status: CheckStatus; description: string; fix: string | null };

const HSTS_MIN_MAX_AGE = 15_552_000; // 180 días

const SAFE_REFERRER_POLICIES = new Set([
  "no-referrer",
  "same-origin",
  "origin",
  "strict-origin",
  "origin-when-cross-origin",
  "strict-origin-when-cross-origin",
]);

const LEAKY_REFERRER_POLICIES = new Set([
  "unsafe-url",
  "no-referrer-when-downgrade",
]);

/* ---------- utilidades de parseo ---------- */

type CspPolicy = Map<string, string[]>;

/**
 * Parsea una cabecera CSP. Si el servidor envía varias cabeceras llegan
 * unidas por comas, y cada una es una política independiente.
 */
export function parseCsp(value: string | undefined): CspPolicy[] {
  if (!value) return [];

  return value
    .split(",")
    .map((policy) => {
      const directives: CspPolicy = new Map();

      for (const raw of policy.split(";")) {
        const [name, ...sources] = raw.trim().split(/\s+/);
        if (!name) continue;

        const key = name.toLowerCase();
        // Según la especificación, las directivas repetidas se ignoran.
        if (!directives.has(key)) {
          directives.set(
            key,
            sources.map((source) => source.toLowerCase()),
          );
        }
      }

      return directives;
    })
    .filter((directives) => directives.size > 0);
}

function scriptSources(policy: CspPolicy): string[] | undefined {
  return policy.get("script-src") ?? policy.get("default-src");
}

function isWeakScriptPolicy(sources: string[]): boolean {
  const usesNonceOrHash = sources.some(
    (source) =>
      source.startsWith("'nonce-") ||
      source.startsWith("'sha256-") ||
      source.startsWith("'sha384-") ||
      source.startsWith("'sha512-") ||
      source === "'strict-dynamic'",
  );

  // Con nonce/hash los navegadores modernos ignoran 'unsafe-inline'.
  const allowsInline = sources.includes("'unsafe-inline'") && !usesNonceOrHash;
  const allowsAnyOrigin = sources.some((source) =>
    ["*", "http:", "https:", "data:"].includes(source),
  );

  return (
    allowsInline || (allowsAnyOrigin && !sources.includes("'strict-dynamic'"))
  );
}

function frameAncestorsVerdict(
  policies: CspPolicy[],
): "strict" | "open" | null {
  let verdict: "strict" | "open" | null = null;

  for (const policy of policies) {
    const sources = policy.get("frame-ancestors");
    if (!sources) continue;

    const open = sources.some((source) =>
      ["*", "http:", "https:"].includes(source),
    );

    // Con varias políticas se aplican todas: basta una estricta.
    if (!open) return "strict";
    verdict = "open";
  }

  return verdict;
}

export function parseHstsMaxAge(value: string): number | null {
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i.exec(value);
  return match ? Number(match[1]) : null;
}

/* ---------- checks ---------- */

function httpsCheck(isHttps: boolean): Verdict {
  return isHttps
    ? {
        status: "pass",
        description:
          "Tu web usa una conexión segura, lo que ayuda a proteger la información del usuario.",
        fix: null,
      }
    : {
        status: "fail",
        description:
          "Tu web no está usando una conexión segura en la URL final.",
        fix: "Activa HTTPS con un certificado SSL y configura la web para que cargue siempre en su versión segura.",
      };
}

function httpRedirectCheck(result: HttpRedirectResult): Verdict {
  if (result === "redirects") {
    return {
      status: "pass",
      description:
        "Si alguien entra por una versión insegura, tu web lo redirige correctamente a la versión segura.",
      fix: null,
    };
  }

  if (result === "no-redirect") {
    return {
      status: "fail",
      description:
        "La versión http:// de tu web responde sin redirigir a la versión segura.",
      fix: "Configura una redirección automática (301) de HTTP a HTTPS para que nadie entre por una versión insegura.",
    };
  }

  return {
    status: "warn",
    description:
      "No se ha podido confirmar que tu web redirija automáticamente desde HTTP a HTTPS (la versión http:// no ha respondido).",
    fix: "Comprueba que la versión http:// de tu web redirige a https://.",
  };
}

function hstsCheck(value: string | undefined, isHttps: boolean): Verdict {
  if (!isHttps) {
    return {
      status: "fail",
      description:
        "Strict-Transport-Security solo funciona sobre HTTPS, y tu web no lo está usando.",
      fix: 'Activa HTTPS primero y después añade la cabecera "Strict-Transport-Security".',
    };
  }

  if (!value) {
    return {
      status: "fail",
      description:
        "Tu web no indica al navegador que recuerde abrirse siempre con conexión segura.",
      fix: 'Añade la cabecera "Strict-Transport-Security", por ejemplo "max-age=31536000; includeSubDomains".',
    };
  }

  const maxAge = parseHstsMaxAge(value);

  if (maxAge === null || maxAge === 0) {
    return {
      status: "fail",
      description:
        maxAge === 0
          ? 'Tu web envía Strict-Transport-Security con "max-age=0", lo que desactiva la protección.'
          : "Tu web envía Strict-Transport-Security, pero sin un max-age válido, así que el navegador la ignora.",
      fix: 'Usa un valor como "max-age=31536000; includeSubDomains".',
    };
  }

  if (maxAge < HSTS_MIN_MAX_AGE) {
    return {
      status: "warn",
      description:
        "Tu web usa Strict-Transport-Security, pero durante un periodo corto (menos de 6 meses).",
      fix: 'Sube max-age a un año: "max-age=31536000; includeSubDomains".',
    };
  }

  return {
    status: "pass",
    description:
      "Tu web indica al navegador que debe usar siempre una conexión segura.",
    fix: null,
  };
}

function cspCheck(enforced: CspPolicy[], reportOnly: CspPolicy[]): Verdict {
  if (enforced.length === 0) {
    return reportOnly.length > 0
      ? {
          status: "warn",
          description:
            "Tu web parece estar probando una política CSP, pero no aplicándola todavía de forma estricta.",
          fix: 'Si ya estás usando "Content-Security-Policy-Report-Only", el siguiente paso es aplicar una política CSP real.',
        }
      : {
          status: "fail",
          description:
            "Tu web no muestra una política CSP visible para limitar scripts y recursos.",
          fix: 'Configura "Content-Security-Policy" para limitar scripts y recursos potencialmente peligrosos.',
        };
  }

  const scriptPolicies = enforced
    .map(scriptSources)
    .filter((sources): sources is string[] => sources !== undefined);

  if (scriptPolicies.length === 0) {
    return {
      status: "warn",
      description:
        "Tu web tiene una política CSP, pero no limita desde dónde se pueden cargar scripts.",
      fix: 'Añade "default-src" o "script-src" a tu Content-Security-Policy.',
    };
  }

  // Con varias políticas se aplican todas: basta con que una sea estricta.
  if (scriptPolicies.every(isWeakScriptPolicy)) {
    return {
      status: "warn",
      description:
        "Tu web tiene una política CSP, pero permite scripts en línea o de cualquier origen, lo que reduce mucho su protección.",
      fix: "Evita 'unsafe-inline' y comodines en script-src; usa nonces o hashes para los scripts que necesites.",
    };
  }

  return {
    status: "pass",
    description: "Tu web limita qué scripts y recursos pueden cargarse.",
    fix: null,
  };
}

function frameProtectionCheck(
  xFrameOptions: string | undefined,
  enforced: CspPolicy[],
  reportOnly: CspPolicy[],
): Verdict {
  const pass: Verdict = {
    status: "pass",
    description:
      "Tu web define protección para limitar que otras páginas la carguen dentro de un iframe.",
    fix: null,
  };
  const fix =
    'Añade "X-Frame-Options: SAMEORIGIN" o usa "frame-ancestors \'self\'" dentro de Content-Security-Policy.';

  const xfo = xFrameOptions?.trim().toLowerCase();
  const ancestors = frameAncestorsVerdict(enforced);

  if (ancestors === "strict" || xfo === "deny" || xfo === "sameorigin") {
    return pass;
  }

  if (ancestors === "open") {
    return {
      status: "warn",
      description:
        'Tu web define "frame-ancestors", pero con un valor que permite que cualquier página la cargue en un iframe.',
      fix,
    };
  }

  if (xfo) {
    return {
      status: "warn",
      description:
        'Tu web envía "X-Frame-Options" con un valor que los navegadores actuales no reconocen, así que no protege.',
      fix,
    };
  }

  if (frameAncestorsVerdict(reportOnly)) {
    return {
      status: "warn",
      description:
        'Tu web declara "frame-ancestors" solo en modo Report-Only, donde el navegador no lo aplica.',
      fix,
    };
  }

  return {
    status: "fail",
    description:
      "Tu web no muestra una protección clara frente a carga en iframes de otras páginas.",
    fix,
  };
}

function contentTypeOptionsCheck(value: string | undefined): Verdict {
  const fix =
    'Añade la cabecera "X-Content-Type-Options" con el valor "nosniff".';

  if (!value) {
    return {
      status: "fail",
      description:
        "Tu web no está indicando al navegador que trate algunos archivos de forma estricta.",
      fix,
    };
  }

  const tokens = value.split(",").map((token) => token.trim().toLowerCase());

  if (tokens[0] !== "nosniff") {
    return {
      status: "fail",
      description:
        'Tu web envía "X-Content-Type-Options" con un valor distinto de "nosniff", así que no tiene efecto.',
      fix,
    };
  }

  return {
    status: "pass",
    description:
      "Tu web evita que el navegador interprete ciertos archivos de una forma insegura.",
    fix: null,
  };
}

function referrerPolicyCheck(value: string | undefined): Verdict {
  const fix =
    'Añade una cabecera "Referrer-Policy", por ejemplo "strict-origin-when-cross-origin".';

  if (!value) {
    return {
      status: "warn",
      description:
        "Tu web no define Referrer-Policy. Los navegadores actuales aplican un valor razonable por defecto, pero los antiguos no.",
      fix,
    };
  }

  // El navegador usa el último valor de la lista que reconoce.
  const effective = value
    .split(",")
    .map((token) => token.trim().toLowerCase())
    .filter(
      (token) =>
        SAFE_REFERRER_POLICIES.has(token) || LEAKY_REFERRER_POLICIES.has(token),
    )
    .pop();

  if (!effective) {
    return {
      status: "fail",
      description:
        'Tu web envía "Referrer-Policy" con un valor que el navegador no reconoce.',
      fix,
    };
  }

  if (LEAKY_REFERRER_POLICIES.has(effective)) {
    return {
      status: "warn",
      description: `Tu web usa Referrer-Policy "${effective}", que comparte la dirección completa de la página con otras webs.`,
      fix: 'Cambia a un valor más restrictivo como "strict-origin-when-cross-origin".',
    };
  }

  return {
    status: "pass",
    description:
      "Tu web controla mejor qué información comparte el navegador al visitar otras páginas.",
    fix: null,
  };
}

function permissionsPolicyCheck(value: string | undefined): Verdict {
  return value?.trim()
    ? {
        status: "pass",
        description:
          "Tu web limita mejor permisos del navegador como cámara, micrófono o ubicación.",
        fix: null,
      }
    : {
        status: "fail",
        description:
          "Tu web no define restricciones para algunos permisos sensibles del navegador.",
        fix: 'Añade una cabecera "Permissions-Policy" para limitar funciones que no necesitas, por ejemplo "camera=(), microphone=(), geolocation=()".',
      };
}

const TITLES: Record<CheckKey, string> = {
  https: "HTTPS activo",
  "http-redirect": "Redirección de HTTP a HTTPS",
  hsts: "Strict-Transport-Security",
  csp: "Content-Security-Policy",
  "frame-protection": "Protección frente a iframes externos",
  "x-content-type-options": "X-Content-Type-Options",
  "referrer-policy": "Referrer-Policy",
  "permissions-policy": "Permissions-Policy",
};

export function buildChecks(input: CheckInput): AuditCheck[] {
  const { headers } = input;
  const isHttps = input.finalUrl.startsWith("https://");
  const enforcedCsp = parseCsp(headers["content-security-policy"]);
  const reportOnlyCsp = parseCsp(
    headers["content-security-policy-report-only"],
  );

  const verdicts: Record<CheckKey, Verdict> = {
    https: httpsCheck(isHttps),
    "http-redirect": httpRedirectCheck(input.httpRedirect),
    hsts: hstsCheck(headers["strict-transport-security"], isHttps),
    csp: cspCheck(enforcedCsp, reportOnlyCsp),
    "frame-protection": frameProtectionCheck(
      headers["x-frame-options"],
      enforcedCsp,
      reportOnlyCsp,
    ),
    "x-content-type-options": contentTypeOptionsCheck(
      headers["x-content-type-options"],
    ),
    "referrer-policy": referrerPolicyCheck(headers["referrer-policy"]),
    "permissions-policy": permissionsPolicyCheck(headers["permissions-policy"]),
  };

  return (Object.keys(CHECK_WEIGHTS) as CheckKey[]).map((key) => ({
    key,
    title: TITLES[key],
    ...verdicts[key],
  }));
}
