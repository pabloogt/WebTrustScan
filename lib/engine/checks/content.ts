import {
  errored,
  fail,
  htmlOnly,
  info,
  notApplicable,
  pass,
  warning,
  type Check,
  type Outcome,
  type ScanContext,
} from "../context";
import { parseCsp, upgradesInsecureRequests } from "../parse/csp";
import type { HtmlFacts } from "../parse/html";
import { classifyResource } from "../parse/thirdParty";

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
    const assets = html.resources
      .filter((resource) => resource.kind === "script" || resource.kind === "style")
      .map((resource) => ({
        ...resource,
        origin: classifyResource(resource.url, context.finalUrl.hostname),
      }));
    const of = (origin: (typeof assets)[number]["origin"]) =>
      assets.filter((asset) => asset.origin === origin);
    const pinned = of("pinned");
    const dynamic = of("dynamic");
    const unknown = of("unknown");
    const sameBrand = of("same-brand");
    const hosts = (list: typeof assets) =>
      [...new Set(list.map((asset) => asset.host))].slice(0, 4).join(", ");

    // Lo que no puntúa también se enseña, con el motivo de su clasificación.
    const context_ = [
      ...dynamic.slice(0, 4).map((asset) => ({
        label: "Servicio de contenido cambiante (SRI no aplicable)",
        value: asset.url.slice(0, 200),
      })),
      ...unknown.slice(0, 4).map((asset) => ({
        label: "Tercero sin versión visible en la URL (no se puede saber si es fijo)",
        value: asset.url.slice(0, 200),
      })),
      ...(sameBrand.length > 0
        ? [
            {
              label: "Dominios tratados como propios por su nombre (no verificado)",
              value: hosts(sameBrand),
            },
          ]
        : []),
    ];
    const brandNote =
      sameBrand.length > 0
        ? ` ${sameBrand.length} recurso(s) de ${hosts(sameBrand)} se han tratado como propios porque el nombre del dominio coincide con la marca del sitio; es un indicio, no una comprobación.`
        : "";

    if (pinned.length === 0 && dynamic.length === 0 && unknown.length === 0) {
      return notApplicable(
        `La página no carga scripts ni estilos de otras organizaciones, así que no hay nada que verificar con SRI.${brandNote}${LIMIT_NOTE}`,
      );
    }

    if (pinned.length === 0) {
      const parts: string[] = [];

      if (dynamic.length > 0) {
        parts.push(
          `${dynamic.length} de servicios que cambian su código por diseño (analítica, publicidad, fuentes o similares), a los que SRI no se puede aplicar`,
        );
      }
      if (unknown.length > 0) {
        parts.push(
          `${unknown.length} de terceros sin número de versión en la URL, de los que no se puede saber desde fuera si su contenido es fijo`,
        );
      }

      // Sin evidencia de que SRI sea aplicable no se puntúa, pero tampoco se
      // afirma que todo esté bien: se informa de lo que hay.
      return info(
        `La página carga scripts o estilos de otras organizaciones: ${parts.join("; ")}. Ninguno puede evaluarse con certeza para SRI, así que este control no puntúa. Su código se ejecuta con los mismos permisos que el de la propia web.${brandNote}`,
        {
          evidence: context_,
          confidence: "medium",
          remediation:
            unknown.length > 0
              ? 'Si alguno de esos recursos es un fichero fijo (una librería concreta), cárgalo con una URL versionada y añade integrity="sha384-…" y crossorigin="anonymous". Limita con Content-Security-Policy los orígenes desde los que pueden ejecutarse scripts.'
              : "Revisa periódicamente qué terceros cargas y limita con Content-Security-Policy los orígenes desde los que pueden ejecutarse scripts.",
        },
      );
    }

    const missing = pinned.filter((asset) => !asset.hasIntegrity);

    if (missing.length === 0) {
      return pass(
        `Los ${pinned.length} recursos de terceros con versión fija llevan el atributo integrity.${brandNote}`,
        { evidence: context_ },
      );
    }

    return warning(
      (pinned.length - missing.length) / pinned.length,
      `${missing.length} de ${pinned.length} recursos de terceros con versión fija se cargan sin "integrity": si ese CDN fuera comprometido, el código modificado se ejecutaría en la web sin que el navegador lo detecte.${brandNote}`,
      'Añade integrity="sha384-…" y crossorigin="anonymous" a esas etiquetas (el propio CDN suele ofrecer el valor), o sirve los ficheros desde tu dominio.',
      {
        severity: "low",
        // «Versión fija» se deduce de la URL (número de versión o hash).
        confidence: "medium",
        evidence: [
          ...missing.slice(0, 5).map((asset) => ({
            label: "Sin integrity",
            value: asset.url.slice(0, 200),
          })),
          ...context_,
        ],
      },
    );
  });
}

export const contentChecks: Check[] = [
  { id: "content.mixed-content", run: mixedContentCheck },
  { id: "content.insecure-forms", run: insecureFormsCheck },
  { id: "content.sri", run: sriCheck },
];
