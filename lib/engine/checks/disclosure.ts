import {
  fail,
  info,
  notTested,
  pass,
  warning,
  type Check,
  type ScanContext,
} from "../context";

const BANNER_HEADERS = [
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-aspnetmvc-version",
  "x-generator",
];
const VERSION = /\d+\.\d+/;

function bannerCheck(context: ScanContext) {
  const present = BANNER_HEADERS.filter((name) => context.headers[name]);
  const evidence = present.map((name) => ({
    label: name,
    value: context.headers[name],
  }));
  const versioned = present.filter((name) => VERSION.test(context.headers[name]));
  const remediation =
    "Configura el servidor para no anunciar versiones (por ejemplo, server_tokens off en nginx, ServerTokens Prod en Apache, o elimina X-Powered-By).";

  if (versioned.length > 0) {
    return fail(
      `Las cabeceras revelan la versión exacta del software (${versioned.join(", ")}). No es una vulnerabilidad en sí, pero ayuda a un atacante a buscar fallos conocidos de esa versión.`,
      remediation,
      { evidence },
    );
  }

  const frameworks = present.filter((name) => name !== "server");

  if (frameworks.length > 0) {
    return warning(
      0.5,
      `Las cabeceras revelan la tecnología usada (${frameworks.join(", ")}), aunque no su versión.`,
      remediation,
      { evidence },
    );
  }

  // En una página de bloqueo la ausencia no demuestra nada sobre el origen.
  if (context.responseTrust === "none") {
    return notTested(
      "La respuesta recibida procede de una página de error o bloqueo, así que no se puede saber qué cabeceras envía el servidor de origen.",
    );
  }

  return pass("Las cabeceras no revelan versiones de software.", { evidence });
}

function securityTxtCheck(context: ScanContext) {
  const probe = context.securityTxt;

  if (!probe.ok) {
    return notTested("No se ha podido comprobar si existe security.txt.", {
      evidence: [{ label: "Motivo", value: probe.reason ?? probe.code }],
    });
  }

  const { status, body, headers, url } = probe.value;
  const isText = (headers["content-type"] ?? "").includes("text/plain");
  const valid = status === 200 && isText && /^contact:/im.test(body ?? "");

  if (valid) {
    const expires = /^expires:\s*(.+)$/im.exec(body ?? "")?.[1]?.trim();
    const expired =
      expires !== undefined && Date.parse(expires) < context.now.getTime();

    return expired
      ? info(
          "La web publica security.txt, pero su fecha Expires ya ha pasado; conviene actualizarlo.",
          { evidence: [{ label: "Expires", value: expires }] },
        )
      : pass(
          "La web publica un security.txt con un contacto para comunicar vulnerabilidades.",
          { evidence: [{ label: "URL", value: url }] },
        );
  }

  if (status === 429 || status >= 500) {
    return notTested(
      `No se ha podido comprobar security.txt (HTTP ${status}).`,
    );
  }

  return info(
    "La web no publica /.well-known/security.txt. Es opcional, pero facilita que alguien que encuentre un fallo sepa a quién avisar.",
    {
      remediation:
        'Crea /.well-known/security.txt con al menos las líneas "Contact:" y "Expires:" (RFC 9116).',
      evidence: [{ label: "Respuesta", value: `HTTP ${status}` }],
    },
  );
}

export const disclosureChecks: Check[] = [
  { id: "disclosure.banner", run: bannerCheck },
  { id: "disclosure.security-txt", run: securityTxtCheck },
];
