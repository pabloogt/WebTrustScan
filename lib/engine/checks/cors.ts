import {
  fail,
  notTested,
  pass,
  warning,
  type Check,
  type ScanContext,
} from "../context";

/**
 * Sonda CORS: se repite la petición con una cabecera `Origin` ajena y se
 * observa si el sitio concede acceso a ese origen. Es una única petición GET
 * inocua; no se intenta leer ningún dato.
 */
function corsCheck(context: ScanContext) {
  const probe = context.corsProbe;

  if (!probe.ok) {
    return notTested(
      "No se ha podido completar la prueba de CORS (la petición adicional no obtuvo respuesta). No se penaliza.",
      { evidence: [{ label: "Motivo", value: probe.reason ?? probe.code }] },
    );
  }

  const { status, headers } = probe.value;

  if (status === 429 || status >= 500 || context.responseTrust === "none") {
    return notTested(
      `La prueba de CORS recibió una respuesta de error o bloqueo (HTTP ${status}), que no representa la política real del sitio.`,
    );
  }

  const allowOrigin = headers["access-control-allow-origin"]?.trim();
  const credentials =
    headers["access-control-allow-credentials"]?.trim().toLowerCase() === "true";
  const variesOnOrigin = (headers.vary ?? "")
    .toLowerCase()
    .split(",")
    .some((token) => token.trim() === "origin" || token.trim() === "*");
  const evidence = [
    { label: "Origin enviado", value: context.corsOrigin },
    {
      label: "access-control-allow-origin",
      value: allowOrigin ?? "(no enviada)",
    },
    {
      label: "access-control-allow-credentials",
      value: headers["access-control-allow-credentials"] ?? "(no enviada)",
    },
    { label: "vary", value: headers.vary ?? "(no enviada)" },
  ];
  const remediation =
    "Responde con Access-Control-Allow-Origin solo para una lista cerrada de orígenes de confianza y no combines orígenes dinámicos con Allow-Credentials.";

  if (!allowOrigin) {
    return pass(
      "El sitio no concede acceso a otros orígenes: se aplica la política del mismo origen del navegador.",
      { evidence },
    );
  }

  const reflected = allowOrigin === context.corsOrigin;

  if ((reflected || allowOrigin === "null") && credentials) {
    return fail(
      `El sitio acepta peticiones con credenciales desde ${reflected ? "cualquier origen (devuelve el que se le envía)" : 'el origen "null"'}. Una web maliciosa podría leer respuestas en nombre de un usuario con sesión iniciada. El impacto real depende de que existan páginas o APIs autenticadas por cookie.`,
      remediation,
      { evidence },
    );
  }

  if (allowOrigin === "*" && credentials) {
    return warning(
      0.6,
      'El sitio combina "Access-Control-Allow-Origin: *" con Allow-Credentials. Los navegadores rechazan esa combinación, pero indica una política CORS mal definida.',
      remediation,
      { evidence, severity: "low" },
    );
  }

  if (reflected || allowOrigin === "null") {
    return warning(
      0.6,
      `El sitio concede lectura a ${reflected ? "cualquier origen que se lo pida" : 'el origen "null"'}, aunque sin credenciales. Solo es un problema si esta respuesta contiene datos que no deberían ser públicos${reflected && !variesOnOrigin ? '; además falta "Vary: Origin", lo que puede provocar errores de caché' : ""}.`,
      remediation,
      { evidence, severity: "low", confidence: "medium" },
    );
  }

  return pass(
    allowOrigin === "*"
      ? 'El sitio permite lectura pública sin credenciales ("Access-Control-Allow-Origin: *"). Es lo habitual en recursos y APIs públicas.'
      : "El sitio solo concede acceso a un origen concreto.",
    { evidence },
  );
}

export const corsChecks: Check[] = [{ id: "cors.policy", run: corsCheck }];
