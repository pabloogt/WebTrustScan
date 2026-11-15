import {
  fail,
  headerEvidence,
  htmlOnly,
  info,
  pass,
  responseLevel,
  warning,
  type Check,
  type ScanContext,
} from "../context";
import {
  assessScripts,
  firstHeaderValue,
  frameAncestors,
  parseCsp,
} from "../parse/csp";
import { siteOf } from "../parse/html";
import { classifyResource } from "../parse/thirdParty";
import type { Evidence } from "../types";

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

/**
 * Recomendación de CSP adaptada a lo que carga la página. Nunca se propone
 * aplicar una política restrictiva directamente: en sitios con plantillas,
 * plugins, analítica o publicidad rompería funciones legítimas.
 */
function cspAdvice(context: ScanContext): string {
  const page = context.finalUrl.hostname;
  const resources = context.html?.resources ?? [];
  const thirdParties = [
    ...new Set(
      resources
        .filter(
          (resource) =>
            resource.kind !== "image" &&
            resource.kind !== "media" &&
            classifyResource(resource.url, page) !== "first-party",
        )
        .map((resource) => siteOf(resource.host)),
    ),
  ].slice(0, 6);
  const wordpress = resources.some((resource) =>
    /\/wp-(content|includes)\//.test(resource.url),
  );
  const parts = [
    'No apliques una política restrictiva de golpe: puede bloquear funciones legítimas de la web. Publícala primero en modo de prueba con la cabecera "Content-Security-Policy-Report-Only", revisa durante unos días las infracciones que registra el navegador, ajústala y, cuando no afecte a nada legítimo, pásala a "Content-Security-Policy".',
  ];

  if (thirdParties.length > 0) {
    parts.push(
      `En esta página se cargan recursos de ${thirdParties.join(", ")}: la política tendrá que permitirlos, igual que los servicios, fuentes e imágenes externas que uses en otras páginas.`,
    );
  }

  if (wordpress) {
    parts.push(
      "El sitio parece WordPress: la plantilla y los plugins suelen insertar scripts y estilos en línea, así que prueba la política con todos ellos activos antes de aplicarla.",
    );
  }

  return parts.join(" ");
}

function cspCheck(context: ScanContext) {
  return htmlOnly(context, () => {
    const headerPolicies = parseCsp(context.headers["content-security-policy"]);
    // Una CSP en <meta> también se aplica (salvo frame-ancestors, sandbox y
    // report-uri). Es la única opción en hostings estáticos sin cabeceras.
    const metaPolicies = (context.html?.metaCsp ?? []).flatMap((value) =>
      parseCsp(value),
    );
    const enforced = [...headerPolicies, ...metaPolicies];
    const reportOnly = parseCsp(
      context.headers["content-security-policy-report-only"],
    );
    const evidence: Evidence[] = [
      ...headerEvidence(context, "content-security-policy"),
      ...(context.html?.metaCsp ?? []).map((value) => ({
        label: '<meta http-equiv="Content-Security-Policy">',
        value,
      })),
      ...(reportOnly.length > 0
        ? headerEvidence(context, "content-security-policy-report-only")
        : []),
    ];
    const source =
      headerPolicies.length === 0 && metaPolicies.length > 0
        ? " (declarada en una etiqueta <meta>)"
        : "";

    if (enforced.length === 0) {
      return reportOnly.length > 0
        ? warning(
            0.2,
            'La web publica una CSP solo en modo de prueba (cabecera "Content-Security-Policy-Report-Only"): el navegador registra lo que la política bloquearía, pero no bloquea nada. No hay ninguna CSP aplicada.',
            'Es el primer paso correcto. Revisa las infracciones registradas y, cuando no afecten a nada legítimo, publica esa política también en la cabecera "Content-Security-Policy".',
            { evidence },
          )
        : fail(
            "La web no envía Content-Security-Policy. No es una vulnerabilidad por sí misma: es una capa de defensa que falta. Si la web tuviera un fallo de inyección (XSS), el navegador ejecutaría el script inyectado sin ninguna restricción.",
            cspAdvice(context),
            { evidence },
          );
    }

    const scripts = assessScripts(enforced);

    switch (scripts.strength) {
      case "unrestricted": {
        const declared = [
          ...new Set(enforced.flatMap((policy) => [...policy.keys()])),
        ];

        return warning(
          0.25,
          `La web aplica una CSP${source}, pero solo declara ${declared.map((name) => `"${name}"`).join(", ")}: ninguna de esas directivas limita desde dónde se ejecutan scripts, que es la función principal de CSP frente a XSS.${reportOnly.length > 0 ? " Además publica otra política en modo Report-Only, que registra infracciones pero no bloquea nada." : ""}`,
          `Para que la CSP proteja frente a XSS, la política aplicada necesita "script-src" (o "default-src"). ${cspAdvice(context)}`,
          { evidence, severity: "medium" },
        );
      }
      case "weak":
        return warning(
          0.5,
          `La web tiene una CSP${source}, pero ${scripts.issues.join(" y ")}. Eso anula buena parte de su protección frente a XSS.`,
          `El objetivo es sustituir 'unsafe-inline' y los comodines por nonces o hashes (con 'strict-dynamic' si cargas scripts de terceros). Hazlo por pasos: prueba la política más estricta en "Content-Security-Policy-Report-Only" mientras mantienes la actual, y cámbiala cuando no registre infracciones legítimas.`,
          { evidence, severity: "medium" },
        );
      case "eval-only":
        return warning(
          0.85,
          `La CSP${source} controla el origen de los scripts, aunque permite eval() ('unsafe-eval').`,
          "Si tu código o tus librerías no necesitan eval(), elimina 'unsafe-eval' de script-src.",
          { evidence, severity: "low" },
        );
      default:
        return pass(
          `La CSP${source} limita qué scripts pueden ejecutarse sin recurrir a 'unsafe-inline' ni comodines.`,
          { evidence },
        );
    }
  });
}

function clickjackingCheck(context: ScanContext) {
  return htmlOnly(context, () => {
    const enforced = parseCsp(context.headers["content-security-policy"]);
    const reportOnly = parseCsp(
      context.headers["content-security-policy-report-only"],
    );
    const ancestors = frameAncestors(enforced);
    const evidence = headerEvidence(
      context,
      "x-frame-options",
      "content-security-policy",
    );
    const remediation =
      "Añade \"frame-ancestors 'self'\" a tu Content-Security-Policy (o \"X-Frame-Options: SAMEORIGIN\" si necesitas compatibilidad con navegadores antiguos).";

    // Origen y CDN pueden añadir la misma cabecera: valores repetidos e
    // idénticos son válidos; valores contradictorios, no.
    const xfoValues = [
      ...new Set(
        (context.headers["x-frame-options"] ?? "")
          .split(",")
          .map((token) => token.trim().toLowerCase())
          .filter(Boolean),
      ),
    ];
    const xfoValid =
      xfoValues.length === 1 &&
      (xfoValues[0] === "deny" || xfoValues[0] === "sameorigin");

    if (ancestors === "strict") {
      // frame-ancestors sustituye a X-Frame-Options: no se exige también.
      return pass(
        xfoValid
          ? "La web impide que otras páginas la incrusten (frame-ancestors y X-Frame-Options)."
          : 'La web impide que otras páginas la incrusten mediante "frame-ancestors", el mecanismo actual. X-Frame-Options no es necesario.',
        { evidence },
      );
    }

    if (xfoValid) {
      return pass(
        `La web impide que otras páginas la incrusten (X-Frame-Options: ${xfoValues[0].toUpperCase()}).`,
        { evidence },
      );
    }

    if (ancestors === "open") {
      return warning(
        0.25,
        'La web declara "frame-ancestors", pero con un valor que permite que cualquier página la incruste.',
        remediation,
        { evidence },
      );
    }

    if (xfoValues.length > 0) {
      return warning(
        0.25,
        xfoValues.length > 1
          ? "La web envía X-Frame-Options con valores contradictorios; los navegadores no lo interpretan de forma uniforme."
          : `La web envía "X-Frame-Options: ${xfoValues[0]}", un valor que los navegadores actuales no reconocen, así que no protege.`,
        remediation,
        { evidence },
      );
    }

    if (frameAncestors(reportOnly)) {
      return warning(
        0.2,
        'La web declara "frame-ancestors" solo en modo Report-Only, donde el navegador no lo aplica.',
        remediation,
        {
          evidence: headerEvidence(
            context,
            "content-security-policy-report-only",
          ),
        },
      );
    }

    return fail(
      "Cualquier página puede incrustar esta web en un iframe invisible y engañar al usuario para que haga clic en ella (clickjacking).",
      remediation,
      { evidence },
    );
  });
}

function nosniffCheck(context: ScanContext) {
  return responseLevel(context, () => {
    const evidence = headerEvidence(context, "x-content-type-options");
    const remediation = 'Añade la cabecera "X-Content-Type-Options: nosniff".';
    const value = firstHeaderValue(context.headers["x-content-type-options"]);

    if (!value) {
      return fail(
        "La web no envía X-Content-Type-Options: el navegador puede reinterpretar un archivo como script u hoja de estilos.",
        remediation,
        { evidence },
      );
    }

    return value.toLowerCase() === "nosniff"
      ? pass("El navegador respeta el tipo declarado de cada archivo.", {
          evidence,
        })
      : fail(
          `La web envía "X-Content-Type-Options: ${value}", un valor sin efecto. El único válido es "nosniff".`,
          remediation,
          { evidence },
        );
  });
}

function referrerPolicyCheck(context: ScanContext) {
  return htmlOnly(context, () => {
    const evidence = headerEvidence(context, "referrer-policy");
    const remediation =
      'Usa "Referrer-Policy: strict-origin-when-cross-origin" (o "no-referrer" si no necesitas analítica de procedencia).';
    const value = context.headers["referrer-policy"];

    if (!value) {
      return info(
        'La web no define Referrer-Policy. Los navegadores actuales aplican por defecto "strict-origin-when-cross-origin", que ya es razonable, así que no se penaliza.',
        { evidence, remediation },
      );
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
      return warning(
        0.5,
        `La web envía "Referrer-Policy: ${value}", que el navegador no reconoce; se aplica el valor por defecto.`,
        remediation,
        { evidence },
      );
    }

    return LEAKY_REFERRER_POLICIES.has(effective)
      ? fail(
          `La web usa Referrer-Policy "${effective}", que envía la dirección completa de cada página (incluidos parámetros) a los sitios externos.`,
          remediation,
          { evidence },
        )
      : pass(`La web limita la información de procedencia (${effective}).`, {
          evidence,
        });
  });
}

function permissionsPolicyCheck(context: ScanContext) {
  return htmlOnly(context, () => {
    const evidence = headerEvidence(context, "permissions-policy");
    const remediation =
      'Añade "Permissions-Policy" desactivando lo que no uses, por ejemplo "camera=(), microphone=(), geolocation=()".';
    const value = context.headers["permissions-policy"]?.trim();

    if (value) {
      return /[a-z-]+\s*=/.test(value)
        ? pass("La web restringe funciones sensibles del navegador.", {
            evidence,
          })
        : fail(
            "La web envía Permissions-Policy, pero su contenido no tiene un formato válido.",
            remediation,
            { evidence },
          );
    }

    if (context.headers["feature-policy"]) {
      return warning(
        0.5,
        "La web usa Feature-Policy, la versión antigua de esta cabecera, que los navegadores actuales ya no aplican.",
        remediation,
        { evidence: headerEvidence(context, "feature-policy") },
      );
    }

    return fail(
      "La web no limita funciones del navegador como cámara, micrófono o ubicación. Si se inyecta código o un iframe de terceros, podría solicitarlas.",
      remediation,
      { evidence },
    );
  });
}

function crossOriginIsolationCheck(context: ScanContext) {
  return responseLevel(context, () => {
    const names = [
      "cross-origin-opener-policy",
      "cross-origin-embedder-policy",
      "cross-origin-resource-policy",
    ];
    const present = names.filter((name) => context.headers[name]);

    return info(
      present.length > 0
        ? `La web declara ${present.length} de las 3 cabeceras de aislamiento entre orígenes.`
        : "La web no declara cabeceras de aislamiento entre orígenes. Solo son necesarias para funciones como SharedArrayBuffer o para aislar ventanas emergentes, así que no se puntúan.",
      { evidence: headerEvidence(context, ...names) },
    );
  });
}

export const headerChecks: Check[] = [
  { id: "headers.csp", run: cspCheck },
  { id: "headers.clickjacking", run: clickjackingCheck },
  { id: "headers.nosniff", run: nosniffCheck },
  { id: "headers.referrer-policy", run: referrerPolicyCheck },
  { id: "headers.permissions-policy", run: permissionsPolicyCheck },
  { id: "headers.cross-origin-isolation", run: crossOriginIsolationCheck },
];
