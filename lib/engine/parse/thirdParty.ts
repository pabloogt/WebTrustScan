import { siteOf } from "./html";

/**
 * Clasificación de un script u hoja de estilos respecto a la página:
 * - first-party: el mismo sitio.
 * - same-brand: otro dominio cuyo nombre indica la misma organización
 *   (media-amazon.com para amazon.es). Es un indicio, no una certeza.
 * - pinned: de un tercero y con contenido fijo (versión o hash en la URL).
 *   Es donde SRI se puede y se debe usar.
 * - dynamic: de un servicio conocido que entrega código cambiante por diseño
 *   (analítica, publicidad, pagos, fuentes). SRI lo rompería.
 * - unknown: de un tercero sin versión visible en la URL. No se puede saber
 *   desde fuera si su contenido es fijo.
 */
export type ResourceOrigin =
  | "first-party"
  | "same-brand"
  | "pinned"
  | "dynamic"
  | "unknown";

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

/** Sufijos y prefijos habituales en dominios de recursos de una marca. */
const ASSET_WORDS = [
  "assets",
  "static",
  "cdn",
  "img",
  "images",
  "media",
  "content",
  "usercontent",
];

function matchesHost(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

/** Etiqueta principal del dominio registrable: "amazon" en www.amazon.es. */
function brandOf(host: string): string {
  return siteOf(host).split(".")[0];
}

/**
 * ¿El nombre del dominio de recursos contiene la marca como palabra
 * completa? Vale "media-amazon" o "githubassets" para "amazon" / "github",
 * pero NO "shopify" para "shop": una subcadena no basta.
 */
export function sameBrand(resourceHost: string, pageHost: string): boolean {
  const brand = brandOf(pageHost);
  const other = brandOf(resourceHost);

  // Con marcas muy cortas la coincidencia sería casual.
  if (brand.length < 4) return false;
  if (other === brand) return true;
  if (other.split("-").includes(brand)) return true;

  return ASSET_WORDS.some(
    (word) => other === `${brand}${word}` || other === `${word}${brand}`,
  );
}

export function classifyResource(
  resourceUrl: string,
  pageHost: string,
): ResourceOrigin {
  let url: URL;

  try {
    url = new URL(resourceUrl);
  } catch {
    return "unknown";
  }

  const host = url.hostname.toLowerCase();

  if (siteOf(host) === siteOf(pageHost)) return "first-party";
  if (sameBrand(host, pageHost)) return "same-brand";

  if (DYNAMIC_HOSTS.some((domain) => matchesHost(host, domain))) {
    return "dynamic";
  }

  return PINNED_PATH.test(url.pathname) ? "pinned" : "unknown";
}
