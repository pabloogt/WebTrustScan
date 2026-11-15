import {
  errored,
  fail,
  htmlOnly,
  notApplicable,
  pass,
  warning,
  type Check,
  type Outcome,
  type ScanContext,
} from "../context";
import { parseCsp, upgradesInsecureRequests } from "../parse/csp";
import { siteOf, type HtmlFacts } from "../parse/html";

const LIMIT_NOTE =
  " (Se analiza el HTML que entrega el servidor; lo que la web genere después con JavaScript no se ve.)";

function withHtml(
  context: ScanContext,
  evaluate: (html: HtmlFacts) => Outcome,
): Outcome {
  return htmlOnly(context, () =>
    context.html
      ? evaluate(context.html)
      : errored(
          "No se ha podido leer el contenido de la página (cuerpo vacío o con una codificación no soportada).",
        ),
  );
}

function sample(urls: string[]) {
  return urls
    .slice(0, 5)
    .map((url) => ({ label: "Recurso", value: url.slice(0, 200) }));
}

function mixedContentCheck(context: ScanContext) {
  return withHtml(context, (html) => {
    if (!context.isHttps) {
      return notApplicable(
        "La página se sirve por HTTP, así que todo su contenido viaja sin cifrar. Ya está recogido en «HTTPS disponible».",
      );
    }

    const insecure = html.resources.filter((resource) => resource.insecure);

    if (insecure.length === 0) {
      return pass(
        `Los ${html.resources.length} recursos referenciados en la página se cargan por HTTPS.${LIMIT_NOTE}`,
      );
    }

    const evidence = sample(insecure.map((resource) => resource.url));
    const policies = [
      ...parseCsp(context.headers["content-security-policy"]),
      ...html.metaCsp.flatMap((value) => parseCsp(value)),
    ];

    if (upgradesInsecureRequests(policies)) {
      return pass(
        `La página referencia ${insecure.length} recursos por http://, pero su CSP ordena al navegador cargarlos por HTTPS (upgrade-insecure-requests).`,
        { evidence },
      );
    }

    const active = insecure.filter(
      (resource) => resource.kind !== "image" && resource.kind !== "media",
    );
    const remediation =
      'Cambia esas direcciones a https:// o añade "upgrade-insecure-requests" a tu Content-Security-Policy.';

    return active.length > 0
      ? fail(
          `La página carga ${active.length} scripts, estilos o marcos por http://. Los navegadores los bloquean, así que parte de la web puede no funcionar; si no los bloquearan, un atacante en la red podría modificarlos.`,
          remediation,
          { evidence: sample(active.map((resource) => resource.url)) },
        )
      : warning(
          0.5,
          `La página carga ${insecure.length} imágenes o medios por http://. El navegador intenta actualizarlos a HTTPS y, si no puede, no los muestra.`,
          remediation,
          { evidence, severity: "low" },
        );
  });
}

function insecureFormsCheck(context: ScanContext) {
  return withHtml(context, (html) => {
    if (html.forms.length === 0 && html.loosePasswordInputs === 0) {
      return notApplicable(
        `La página analizada no contiene formularios, así que no hay envíos que proteger.${LIMIT_NOTE}`,
      );
    }

    if (!context.isHttps) {
      return notApplicable(
        "La página se sirve por HTTP: cualquier formulario viaja sin cifrar. Ya está recogido en «HTTPS disponible».",
      );
    }

    const insecure = html.forms.filter((form) => form.insecureAction);

    if (insecure.length === 0) {
      return pass(
        `Los ${html.forms.length} formularios de la página envían sus datos por HTTPS.`,
      );
    }

    const withPassword = insecure.some((form) => form.hasPassword);

    return fail(
      withPassword
        ? "Un formulario con contraseña envía sus datos a una dirección http://: la contraseña viajaría legible por la red."
        : `${insecure.length} formulario(s) envían sus datos a una dirección http://, sin cifrar.`,
      'Cambia el atributo "action" de esos formularios a una dirección https://.',
      {
        severity: withPassword ? "high" : "medium",
        evidence: insecure
          .slice(0, 5)
          .map((form) => ({ label: "action", value: form.action.slice(0, 200) })),
      },
    );
  });
}

function sriCheck(context: ScanContext) {
  return withHtml(context, (html) => {
    const site = siteOf(context.finalUrl.hostname);
    const thirdParty = html.resources.filter(
      (resource) =>
        (resource.kind === "script" || resource.kind === "style") &&
        siteOf(resource.host) !== site,
    );

    if (thirdParty.length === 0) {
      return notApplicable(
        `La página no carga scripts ni estilos de otros dominios, así que no hay nada que verificar con SRI.${LIMIT_NOTE}`,
      );
    }

    const missing = thirdParty.filter((resource) => !resource.hasIntegrity);

    if (missing.length === 0) {
      return pass(
        `Los ${thirdParty.length} scripts y estilos de terceros llevan el atributo integrity.`,
      );
    }

    return warning(
      (thirdParty.length - missing.length) / thirdParty.length,
      `${missing.length} de ${thirdParty.length} scripts o estilos de otros dominios se cargan sin "integrity": si ese proveedor fuera comprometido, su código se ejecutaría en tu web. Algunos servicios (analítica, etiquetas) cambian su código a menudo y no admiten SRI.`,
      'Añade integrity="sha384-…" y crossorigin="anonymous" a los recursos de terceros con versión fija, o sírvelos desde tu propio dominio.',
      {
        severity: "low",
        // No se puede saber desde fuera si el recurso tiene versión fija.
        confidence: "medium",
        evidence: sample(missing.map((resource) => resource.url)),
      },
    );
  });
}

export const contentChecks: Check[] = [
  { id: "content.mixed-content", run: mixedContentCheck },
  { id: "content.insecure-forms", run: insecureFormsCheck },
  { id: "content.sri", run: sriCheck },
];
