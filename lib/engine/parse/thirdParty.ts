import { siteOf } from "./html";

/**
 * Clasificación de un script u hoja de estilos respecto a la página:
 * - first-party: mismo sitio, o un dominio de recursos de la misma marca.
 * - pinned: de un tercero y con contenido fijo (versión o hash en la URL).
 *   Es donde SRI se puede y se debe usar.
 * - dynamic: de un tercero que sirve código cambiante por diseño (analítica,
 *   publicidad, pagos, fuentes). SRI no es viable: romper­ía el servicio.
 */
export type ResourceOrigin = "first-party" | "pinned" | "dynamic";

/** Servicios que entregan código distinto según el momento o el navegador. */
const DYNAMIC_HOSTS = [
  "googletagmanager.com",
  "google-analytics.com",
  "googlesyndication.com",
  "googleadservices.com",
  "doubleclick.net",
  "google.com",
  "gstatic.com",
  "fonts.googleapis.com",
  "maps.googleapis.com",
  "connect.facebook.net",
  "platform.twitter.com",
  "js.stripe.com",
  "paypal.com",
  "paypalobjects.com",
  "hs-scripts.com",
  "hs-analytics.net",
  "hotjar.com",
  "clarity.ms",
  "cloudflareinsights.com",
  "challenges.cloudflare.com",
  "segment.com",
  "intercom.io",
  "intercomcdn.com",
  "cookielaw.org",
  "cookiebot.com",
  "onetrust.com",
  "typekit.net",
  "youtube.com",
  "vimeo.com",
  "addthis.com",
  "disqus.com",
  "recaptcha.net",
  "hcaptcha.com",
  "matomo.cloud",
  "plausible.io",
];

/** Versión explícita o hash de contenido en la ruta. */
const PINNED_PATH =
  /(@\d+\.\d+)|(\/v?\d+\.\d+(\.\d+)?\/)|([-.]\d+\.\d+\.\d+)|([-._][0-9a-f]{8,}\.(js|css)$)/i;

function matchesHost(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

/** Etiqueta principal del dominio registrable: "amazon" en www.amazon.es. */
function brandOf(host: string): string {
  return siteOf(host).split(".")[0];
}

export function classifyResource(
  resourceUrl: string,
  pageHost: string,
): ResourceOrigin {
  let url: URL;

  try {
    url = new URL(resourceUrl);
  } catch {
    return "dynamic";
  }

  const host = url.hostname.toLowerCase();

  if (siteOf(host) === siteOf(pageHost)) return "first-party";

  // Dominios de recursos de la misma organización (media-amazon.com para
  // amazon.es, githubassets.com para github.com…). Con marcas muy cortas la
  // coincidencia sería casual, así que se exige un mínimo de 4 letras.
  const brand = brandOf(pageHost);
  if (brand.length >= 4 && brandOf(host).includes(brand)) return "first-party";

  if (DYNAMIC_HOSTS.some((domain) => matchesHost(host, domain))) {
    return "dynamic";
  }

  return PINNED_PATH.test(url.pathname) ? "pinned" : "dynamic";
}
