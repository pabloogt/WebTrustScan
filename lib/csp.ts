/**
 * Content-Security-Policy de las páginas. Se genera por petición con un nonce,
 * así que no necesita 'unsafe-inline': solo se ejecutan los scripts que
 * Next.js marca con ese nonce (y los que estos carguen, por 'strict-dynamic').
 */
export function buildContentSecurityPolicy(options: {
  nonce: string;
  isDev: boolean;
}): string {
  const { nonce, isDev } = options;

  return [
    "default-src 'self'",
    // En desarrollo React necesita eval para depurar; en producción no.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // En desarrollo Next.js inyecta estilos en línea sin nonce. Si la directiva
    // lleva un nonce el navegador ignora 'unsafe-inline', así que en ese modo
    // no se incluye.
    isDev
      ? "style-src 'self' 'unsafe-inline'"
      : `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    `connect-src 'self'${isDev ? " ws: wss:" : ""}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/** CSP para respuestas que no son páginas (la API devuelve solo JSON). */
export const API_CONTENT_SECURITY_POLICY =
  "default-src 'none'; frame-ancestors 'none'";

export function generateNonce(): string {
  return Buffer.from(crypto.randomUUID()).toString("base64");
}
