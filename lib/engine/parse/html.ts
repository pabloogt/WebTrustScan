export type ResourceKind = "script" | "style" | "frame" | "image" | "media";

export type HtmlResource = {
  kind: ResourceKind;
  url: string;
  host: string;
  /** Se carga por http:// (sin cifrar). */
  insecure: boolean;
  hasIntegrity: boolean;
};

export type HtmlForm = {
  /** URL absoluta del destino (la propia página si no hay `action`). */
  action: string;
  insecureAction: boolean;
  hasPassword: boolean;
};

export type HtmlFacts = {
  resources: HtmlResource[];
  forms: HtmlForm[];
  /** Campos de contraseña fuera de un <form>. */
  loosePasswordInputs: number;
  /** Políticas declaradas con <meta http-equiv="Content-Security-Policy">. */
  metaCsp: string[];
  /** Texto visible aproximado; sirve para detectar páginas tipo SPA. */
  textLength: number;
  truncated: boolean;
};

const TAG =
  /<(\/?)(script|link|img|iframe|frame|form|input|video|audio|source|embed|meta|base)\b((?:"[^"]*"|'[^']*'|[^'">])*)>/gi;
const ATTRIBUTE =
  /([^\s"'=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;

function attributes(raw: string): Map<string, string> {
  const result = new Map<string, string>();

  for (const match of raw.matchAll(ATTRIBUTE)) {
    const name = match[1].toLowerCase();
    if (!result.has(name)) {
      result.set(name, (match[2] ?? match[3] ?? match[4] ?? "").trim());
    }
  }

  return result;
}

function resolve(value: string | undefined, base: URL): URL | null {
  if (!value) return null;

  try {
    const url = new URL(value, base);
    return url.protocol === "http:" || url.protocol === "https:" ? url : null;
  } catch {
    return null;
  }
}

const KIND_BY_TAG: Record<string, ResourceKind> = {
  script: "script",
  iframe: "frame",
  frame: "frame",
  embed: "frame",
  img: "image",
  video: "media",
  audio: "media",
  source: "media",
};

/**
 * Extrae de un HTML los datos que usan las comprobaciones de contenido.
 * Es un escáner de etiquetas tolerante, no un navegador: no ejecuta
 * JavaScript, así que no ve lo que una SPA genera en el cliente.
 */
export function extractHtmlFacts(
  html: string,
  pageUrl: URL,
  truncated = false,
): HtmlFacts {
  // Fuera comentarios y el interior de script/style: su texto no es marcado.
  const cleaned = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/(<script\b[^>]*>)[\s\S]*?(<\/script\s*>)/gi, "$1$2")
    .replace(/(<style\b[^>]*>)[\s\S]*?(<\/style\s*>)/gi, "");

  const facts: HtmlFacts = {
    resources: [],
    forms: [],
    loosePasswordInputs: 0,
    metaCsp: [],
    textLength: cleaned.replace(/<[^>]*>/g, "").replace(/\s+/g, " ").trim()
      .length,
    truncated,
  };

  let base = pageUrl;
  let currentForm: HtmlForm | null = null;

  const addResource = (
    kind: ResourceKind,
    url: URL | null,
    integrity: boolean,
  ) => {
    if (!url) return;

    facts.resources.push({
      kind,
      url: url.href,
      host: url.hostname,
      insecure: url.protocol === "http:",
      hasIntegrity: integrity,
    });
  };

  for (const match of cleaned.matchAll(TAG)) {
    const closing = match[1] === "/";
    const tag = match[2].toLowerCase();

    if (closing) {
      if (tag === "form") currentForm = null;
      continue;
    }

    const attrs = attributes(match[3]);

    switch (tag) {
      case "base": {
        const href = resolve(attrs.get("href"), pageUrl);
        if (href) base = href;
        break;
      }
      case "meta": {
        if (
          attrs.get("http-equiv")?.toLowerCase() === "content-security-policy" &&
          attrs.get("content")
        ) {
          facts.metaCsp.push(attrs.get("content") as string);
        }
        break;
      }
      case "link": {
        const rel = (attrs.get("rel") ?? "").toLowerCase().split(/\s+/);
        const asScript =
          (rel.includes("preload") && attrs.get("as") === "script") ||
          rel.includes("modulepreload");

        if (rel.includes("stylesheet") || asScript) {
          addResource(
            asScript ? "script" : "style",
            resolve(attrs.get("href"), base),
            Boolean(attrs.get("integrity")),
          );
        }
        break;
      }
      case "form": {
        const action = resolve(attrs.get("action") || base.href, base) ?? base;

        currentForm = {
          action: action.href,
          insecureAction: action.protocol === "http:",
          hasPassword: false,
        };
        facts.forms.push(currentForm);
        break;
      }
      case "input": {
        if (attrs.get("type")?.toLowerCase() === "password") {
          if (currentForm) currentForm.hasPassword = true;
          else facts.loosePasswordInputs += 1;
        }
        break;
      }
      default: {
        addResource(
          KIND_BY_TAG[tag],
          resolve(attrs.get("src"), base),
          Boolean(attrs.get("integrity")),
        );
      }
    }
  }

  return facts;
}

/**
 * Dominio "registrable" aproximado (sin lista de sufijos públicos): los dos
 * últimos niveles, o tres para sufijos tipo co.uk / com.es.
 */
export function siteOf(host: string): string {
  const labels = host.toLowerCase().split(".");

  if (labels.length <= 2) return labels.join(".");

  const tld = labels[labels.length - 1];
  const second = labels[labels.length - 2];
  const compound = tld.length === 2 && second.length <= 3;

  return labels.slice(compound ? -3 : -2).join(".");
}
