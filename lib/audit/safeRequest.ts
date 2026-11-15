import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { isIP, type LookupFunction, type Socket } from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";
import { AuditError } from "./errors";
import { isPublicAddress } from "./ipGuard";

export type AddressPolicy = (address: string) => boolean;

/** Resolución DNS con la firma de `dns.lookup` (inyectable en tests). */
export type DnsLookup = (
  hostname: string,
  options: dns.LookupAllOptions,
  callback: (
    error: NodeJS.ErrnoException | null,
    addresses: dns.LookupAddress[],
  ) => void,
) => void;

export type SafeRequestOptions = {
  /** Decide si se permite conectar a una IP. Por defecto, solo IPs públicas. */
  addressPolicy?: AddressPolicy;
  /** Puertos permitidos. `null` desactiva la restricción (solo para tests). */
  allowedPorts?: readonly number[] | null;
  /** Tiempo máximo por petición (conexión + cabeceras). */
  requestTimeoutMs?: number;
  maxRedirects?: number;
  /** Señal global para cancelar todo el análisis. */
  signal?: AbortSignal;
  /** Resolución DNS a usar. Por defecto `dns.lookup` (solo se cambia en tests). */
  dnsLookup?: DnsLookup;
  /** CA adicional de confianza (solo para el laboratorio de pruebas). */
  tlsCa?: string | Buffer;
};

export type HeadersResult = {
  /** URL final tras seguir las redirecciones. */
  url: string;
  status: number;
  headers: Record<string, string>;
  redirects: number;
  /** IP real del socket que sirvió la respuesta final. */
  remoteAddress: string;
};

/** Datos del certificado y de la sesión TLS de una conexión. */
export type TlsInfo = {
  /** true si la cadena y el nombre del host se validaron correctamente. */
  authorized: boolean;
  /** Código del fallo de validación (p. ej. "CERT_HAS_EXPIRED"). */
  authorizationError: string | null;
  /** Versión negociada, p. ej. "TLSv1.3". */
  protocol: string | null;
  cipher: string | null;
  validFrom: string | null;
  validTo: string | null;
  subject: string | null;
  issuer: string | null;
  subjectAltName: string | null;
};

export type RedirectHop = {
  url: string;
  status: number;
  tls: TlsInfo | null;
};

export type SafeFetchOptions = SafeRequestOptions & {
  method?: "GET" | "HEAD" | "OPTIONS";
  /** Cabeceras extra de la petición (p. ej. `origin` para la sonda CORS). */
  headers?: Record<string, string>;
  /** Bytes del cuerpo a leer. 0 (por defecto) = solo cabeceras. */
  maxBodyBytes?: number;
  /**
   * "strict" (por defecto): un certificado inválido aborta la petición.
   * "inspect": se completa la petición y el fallo del certificado se devuelve
   * en `tls`, para poder informarlo como hallazgo. La validación de IP/SSRF
   * es idéntica en ambos modos.
   */
  tlsMode?: "strict" | "inspect";
};

export type SafeFetchResult = HeadersResult & {
  /** Valores de Set-Cookie sin unir (uno por cookie). */
  setCookies: string[];
  /** Saltos de redirección recorridos, incluido el final. */
  chain: RedirectHop[];
  tls: TlsInfo | null;
  body: string | null;
  bodyTruncated: boolean;
};

const DEFAULT_ALLOWED_PORTS = [80, 443] as const;
const DEFAULT_REQUEST_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const USER_AGENT = "WebTrustScan/2.0 (+analizador de configuracion de seguridad web)";

const BLOCKED_MESSAGE =
  "Esa dirección no se puede analizar: solo se admiten webs públicas en los puertos 80 y 443.";

const TLS_ERROR_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

function stripBrackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function effectivePort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

/** Valida una URL de destino antes de abrir ninguna conexión. */
export function assertAllowedTarget(
  url: URL,
  addressPolicy: AddressPolicy,
  allowedPorts: readonly number[] | null,
): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new AuditError("BLOCKED_TARGET", BLOCKED_MESSAGE);
  }

  if (url.username || url.password) {
    throw new AuditError("BLOCKED_TARGET", BLOCKED_MESSAGE);
  }

  if (allowedPorts && !allowedPorts.includes(effectivePort(url))) {
    throw new AuditError("BLOCKED_TARGET", BLOCKED_MESSAGE);
  }

  const host = stripBrackets(url.hostname);

  if (isIP(host) && !addressPolicy(host)) {
    throw new AuditError("BLOCKED_TARGET", BLOCKED_MESSAGE);
  }
}

/** Forma canónica de una IP para poder comparar direcciones entre sí. */
export function canonicalAddress(address: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return mapped[1];

  if (isIP(address) === 6) {
    try {
      return new URL(`http://[${address}]/`).hostname.slice(1, -1);
    } catch {
      return address.toLowerCase();
    }
  }

  return address;
}

/**
 * `lookup` de DNS que rechaza el destino si CUALQUIERA de las IPs resueltas
 * no está permitida. Se pasa al socket, así que no hay una resolución para
 * validar y otra para conectar: la respuesta DNS que se valida es la misma
 * que usa `net.connect`. Eso cierra la ventana de DNS rebinding.
 *
 * `onValidated` recibe las IPs aprobadas para poder comprobar después que el
 * socket se conectó exactamente a una de ellas.
 */
export function createGuardedLookup(
  addressPolicy: AddressPolicy,
  dnsLookup: DnsLookup = dns.lookup as DnsLookup,
  onValidated?: (addresses: string[]) => void,
): LookupFunction {
  const guarded = (
    hostname: string,
    options: dns.LookupOptions,
    callback: (
      error: NodeJS.ErrnoException | null,
      address: string | dns.LookupAddress[],
      family?: number,
    ) => void,
  ) => {
    dnsLookup(
      hostname,
      { family: options.family, hints: options.hints, all: true },
      (error, addresses) => {
        if (error) {
          callback(error, "", 0);
          return;
        }

        if (
          !Array.isArray(addresses) ||
          addresses.length === 0 ||
          addresses.some((entry) => !addressPolicy(entry.address))
        ) {
          callback(new AuditError("BLOCKED_TARGET", BLOCKED_MESSAGE), "", 0);
          return;
        }

        onValidated?.(addresses.map((entry) => entry.address));

        if (options.all) {
          callback(null, addresses);
        } else {
          callback(null, addresses[0].address, addresses[0].family);
        }
      },
    );
  };

  return guarded as unknown as LookupFunction;
}

function flattenHeaders(
  headers: http.IncomingHttpHeaders,
): Record<string, string> {
  const flat: Record<string, string> = {};

  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    flat[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
  }

  return flat;
}

function toAuditError(error: unknown, signal: AbortSignal): AuditError {
  if (error instanceof AuditError) return error;

  const code = (error as NodeJS.ErrnoException | null)?.code ?? "";
  const name = (error as Error | null)?.name ?? "";

  if (signal.aborted || name === "AbortError" || name === "TimeoutError") {
    return new AuditError(
      "TIMEOUT",
      "La web ha tardado demasiado en responder. Inténtalo de nuevo más tarde.",
      "TIMEOUT",
    );
  }

  if (TLS_ERROR_CODES.has(code)) {
    return new AuditError(
      "TLS_ERROR",
      "El certificado HTTPS de la web no es válido (caducado, autofirmado o de otro dominio).",
      code,
    );
  }

  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return new AuditError(
      "UNREACHABLE",
      "No se ha encontrado ese dominio. Comprueba que está bien escrito.",
      code,
    );
  }

  return new AuditError(
    "UNREACHABLE",
    "No se pudo conectar con la web. Comprueba que la URL existe y responde correctamente.",
    code || "UNKNOWN",
  );
}

type RawResponse = {
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  remoteAddress: string;
  tls: TlsInfo | null;
  body: string | null;
  bodyTruncated: boolean;
};

type RequestConfig = {
  addressPolicy: AddressPolicy;
  dnsLookup: DnsLookup | undefined;
  tlsCa: string | Buffer | undefined;
  method: "GET" | "HEAD" | "OPTIONS";
  extraHeaders: Record<string, string>;
  maxBodyBytes: number;
  tlsMode: "strict" | "inspect";
};

function nameOf(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;

  const record = value as Record<string, unknown>;
  const parts = [record.CN, record.O].filter(
    (part): part is string => typeof part === "string" && part.length > 0,
  );

  return parts.length > 0 ? parts.join(" · ") : null;
}

function readTlsInfo(socket: Socket): TlsInfo | null {
  if (!(socket instanceof tls.TLSSocket)) return null;

  const certificate = socket.getPeerCertificate();
  const hasCertificate = certificate && Object.keys(certificate).length > 0;
  const error = socket.authorizationError as unknown;

  return {
    authorized: socket.authorized,
    authorizationError: socket.authorized
      ? null
      : typeof error === "string"
        ? error
        : ((error as NodeJS.ErrnoException | null)?.code ??
          (error as Error | null)?.message ??
          "UNKNOWN"),
    protocol: socket.getProtocol(),
    cipher: socket.getCipher()?.name ?? null,
    validFrom: hasCertificate ? certificate.valid_from : null,
    validTo: hasCertificate ? certificate.valid_to : null,
    subject: hasCertificate ? nameOf(certificate.subject) : null,
    issuer: hasCertificate ? nameOf(certificate.issuer) : null,
    subjectAltName: hasCertificate
      ? (certificate.subjectaltname ?? null)
      : null,
  };
}

/** Descomprime lo leído, aunque el cuerpo esté truncado. Nunca lanza. */
function decodeBody(
  buffer: Buffer,
  encoding: string | undefined,
): string | null {
  const limit = { maxOutputLength: 4 * 1024 * 1024 };

  try {
    switch ((encoding ?? "").trim().toLowerCase()) {
      case "":
      case "identity":
        return buffer.toString("utf8");
      case "gzip":
      case "x-gzip":
        return zlib
          .gunzipSync(buffer, {
            ...limit,
            finishFlush: zlib.constants.Z_SYNC_FLUSH,
          })
          .toString("utf8");
      case "deflate":
        return zlib
          .inflateSync(buffer, {
            ...limit,
            finishFlush: zlib.constants.Z_SYNC_FLUSH,
          })
          .toString("utf8");
      case "br":
        return zlib
          .brotliDecompressSync(buffer, {
            ...limit,
            finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH,
          })
          .toString("utf8");
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * Crea el `lookup` guardado y el comprobador de la IP real del socket que
 * comparten TODAS las conexiones salientes (HTTP, HTTPS y sondas TLS).
 */
function createPeerGuard(
  host: string,
  addressPolicy: AddressPolicy,
  dnsLookup: DnsLookup | undefined,
) {
  // IPs a las que se permite que acabe conectado el socket de ESTA petición:
  // la IP literal de la URL, o las que apruebe el lookup guardado.
  const approved = new Set<string>();
  if (isIP(host)) approved.add(canonicalAddress(host));

  const lookup = createGuardedLookup(addressPolicy, dnsLookup, (addresses) => {
    for (const address of addresses) approved.add(canonicalAddress(address));
  });

  /**
   * Segunda barrera: la IP real del socket tiene que ser una de las
   * aprobadas. Si algo esquivara el lookup (un proxy de entorno, un agente
   * distinto, un cambio en Node), la petición se corta aquí.
   */
  const isApprovedPeer = (socket: Socket): boolean => {
    const peer = socket.remoteAddress;

    return (
      peer !== undefined &&
      approved.has(canonicalAddress(peer)) &&
      addressPolicy(canonicalAddress(peer))
    );
  };

  return { lookup, isApprovedPeer };
}

const blockedError = () => new AuditError("BLOCKED_TARGET", BLOCKED_MESSAGE);

function performRequest(
  url: URL,
  config: RequestConfig,
  signal: AbortSignal,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const host = stripBrackets(url.hostname);
    const { lookup, isApprovedPeer } = createPeerGuard(
      host,
      config.addressPolicy,
      config.dnsLookup,
    );

    const request = transport.request(
      url,
      {
        method: config.method,
        // Sin reutilizar conexiones: cada petición resuelve y valida su IP.
        agent: false,
        lookup,
        signal,
        ...(url.protocol === "https:"
          ? {
              rejectUnauthorized: config.tlsMode === "strict",
              ...(config.tlsCa ? { ca: config.tlsCa } : {}),
            }
          : {}),
        headers: {
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
          ...config.extraHeaders,
        },
      },
      (response) => {
        if (!isApprovedPeer(response.socket)) {
          response.destroy();
          reject(blockedError());
          return;
        }

        const rawCookies = response.headers["set-cookie"];
        const base = {
          status: response.statusCode ?? 0,
          headers: flattenHeaders(response.headers),
          setCookies: Array.isArray(rawCookies) ? rawCookies : [],
          remoteAddress: canonicalAddress(response.socket.remoteAddress ?? ""),
          tls: readTlsInfo(response.socket),
        };

        if (config.maxBodyBytes <= 0 || config.method === "HEAD") {
          resolve({ ...base, body: null, bodyTruncated: false });
          // Solo interesan las cabeceras: se corta la descarga del cuerpo.
          response.destroy();
          return;
        }

        const chunks: Buffer[] = [];
        let size = 0;
        let settled = false;

        const finish = (truncated: boolean) => {
          if (settled) return;
          settled = true;
          resolve({
            ...base,
            body: decodeBody(
              Buffer.concat(chunks),
              base.headers["content-encoding"],
            ),
            bodyTruncated: truncated,
          });
          response.destroy();
        };

        response.on("data", (chunk: Buffer) => {
          const room = config.maxBodyBytes - size;
          chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
          size += Math.min(chunk.length, room);
          if (size >= config.maxBodyBytes) finish(true);
        });
        response.on("end", () => finish(false));
        // Si el cuerpo se corta a medias se conserva lo leído: las cabeceras
        // ya son válidas y no se debe perder el análisis por ello.
        response.on("error", () => finish(true));
        response.on("close", () => finish(true));
      },
    );

    request.on("socket", (socket) => {
      socket.once("connect", () => {
        if (!isApprovedPeer(socket)) request.destroy(blockedError());
      });
    });

    request.on("error", (error) => reject(toAuditError(error, signal)));
    request.end();
  });
}

/**
 * Pide una URL siguiendo redirecciones a mano para validar cada salto.
 * Es el ÚNICO punto por el que el motor hace peticiones HTTP(S) salientes.
 */
export async function safeFetch(
  startUrl: string,
  options: SafeFetchOptions = {},
): Promise<SafeFetchResult> {
  const addressPolicy = options.addressPolicy ?? isPublicAddress;
  const allowedPorts =
    options.allowedPorts === undefined
      ? DEFAULT_ALLOWED_PORTS
      : options.allowedPorts;
  const requestTimeoutMs =
    options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const config: RequestConfig = {
    addressPolicy,
    dnsLookup: options.dnsLookup,
    tlsCa: options.tlsCa,
    method: options.method ?? "GET",
    extraHeaders: options.headers ?? {},
    maxBodyBytes: options.maxBodyBytes ?? 0,
    tlsMode: options.tlsMode ?? "strict",
  };
  const chain: RedirectHop[] = [];
  let current = new URL(startUrl);

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    assertAllowedTarget(current, addressPolicy, allowedPorts);

    const timeout = AbortSignal.timeout(requestTimeoutMs);
    const signal = options.signal
      ? AbortSignal.any([timeout, options.signal])
      : timeout;

    const response = await performRequest(current, config, signal);
    const location = response.headers.location;

    chain.push({
      url: current.href,
      status: response.status,
      tls: response.tls,
    });

    if (!REDIRECT_STATUSES.has(response.status) || !location) {
      return { url: current.href, redirects, chain, ...response };
    }

    try {
      current = new URL(location, current);
    } catch {
      throw new AuditError(
        "UNREACHABLE",
        "La web redirige a una dirección que no es válida.",
        "BAD_REDIRECT",
      );
    }
  }

  throw new AuditError(
    "TOO_MANY_REDIRECTS",
    "La web encadena demasiadas redirecciones y no se ha podido analizar.",
  );
}

/**
 * Pide una URL y devuelve estado y cabeceras de la respuesta final.
 * (API original del motor 1.x; usa el mismo núcleo que `safeFetch`.)
 */
export async function fetchHeadersSafely(
  startUrl: string,
  options: SafeRequestOptions = {},
): Promise<HeadersResult> {
  const { url, status, headers, redirects, remoteAddress } = await safeFetch(
    startUrl,
    options,
  );

  return { url, status, headers, redirects, remoteAddress };
}

export type TlsProbeResult =
  /** El saludo se completó con esa versión. */
  | { outcome: "accepted"; protocol: string | null }
  /**
   * El servidor no completó el saludo. `explicit` indica si lo dijo con una
   * alerta de versión de protocolo (concluyente) o si solo cortó el saludo
   * (compatible con un rechazo, pero sin indicar el motivo).
   */
  | { outcome: "rejected"; reason: string; explicit: boolean }
  /**
   * La prueba no fue válida: fallo de red, tiempo agotado, destino bloqueado
   * o un cliente que no puede hablar esa versión. NO dice nada del servidor.
   */
  | { outcome: "error"; reason: string };

/** El servidor responde que no admite la versión pedida. */
const TLS_EXPLICIT_REJECTION =
  /PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL|VERSION_TOO_LOW/i;

/** El servidor corta el saludo sin decir por qué. */
const TLS_IMPLICIT_REJECTION =
  /HANDSHAKE_FAILURE|NO_SHARED_CIPHER|INTERNAL_ERROR|ECONNRESET|EPIPE|socket hang up/i;

/** El propio cliente no ha podido formular la prueba. */
const TLS_CLIENT_LIMITATION =
  /NO_PROTOCOLS_AVAILABLE|NO_CIPHERS_AVAILABLE|NO_CIPHER_MATCH|ERR_TLS_INVALID_PROTOCOL|ERR_TLS_PROTOCOL_VERSION_CONFLICT/i;

const LEGACY_TLS = new Set(["TLSv1", "TLSv1.1"]);

/**
 * Intenta un único saludo TLS limitado a un rango de versiones (normalmente
 * una sola) para saber si el servidor la admite. No envía datos de
 * aplicación. Pasa por la misma validación de IP que las peticiones HTTP.
 */
export function safeTlsProbe(
  target: string,
  versions: { minVersion: tls.SecureVersion; maxVersion: tls.SecureVersion },
  options: SafeRequestOptions = {},
): Promise<TlsProbeResult> {
  const addressPolicy = options.addressPolicy ?? isPublicAddress;
  const allowedPorts =
    options.allowedPorts === undefined
      ? DEFAULT_ALLOWED_PORTS
      : options.allowedPorts;
  const url = new URL(target);

  assertAllowedTarget(url, addressPolicy, allowedPorts);

  const host = stripBrackets(url.hostname);
  const { lookup, isApprovedPeer } = createPeerGuard(
    host,
    addressPolicy,
    options.dnsLookup,
  );
  const timeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;

  return new Promise((resolve) => {
    let socket: tls.TLSSocket | undefined;
    let done = false;

    const finish = (result: TlsProbeResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      socket?.destroy();
      resolve(result);
    };
    const onAbort = () => finish({ outcome: "error", reason: "TIMEOUT" });
    const timer = setTimeout(onAbort, timeoutMs);

    if (options.signal?.aborted) {
      onAbort();
      return;
    }
    options.signal?.addEventListener("abort", onAbort, { once: true });

    try {
      socket = tls.connect({
        host,
        port: effectivePort(url),
        ...(isIP(host) ? {} : { servername: host }),
        lookup,
        // Solo interesa la versión: el certificado lo valida la petición principal.
        rejectUnauthorized: false,
        minVersion: versions.minVersion,
        maxVersion: versions.maxVersion,
        // Las versiones antiguas requieren bajar el nivel de seguridad de
        // OpenSSL SOLO en su sonda, que no transmite ningún dato.
        ...(LEGACY_TLS.has(versions.maxVersion)
          ? { ciphers: "DEFAULT:@SECLEVEL=0" }
          : {}),
      });
    } catch (error) {
      // El propio runtime no puede hablar esa versión: no es comprobable.
      finish({
        outcome: "error",
        reason: (error as NodeJS.ErrnoException).code ?? "UNSUPPORTED_RUNTIME",
      });
      return;
    }

    const connection = socket;

    connection.once("connect", () => {
      if (!isApprovedPeer(connection)) {
        finish({ outcome: "error", reason: "BLOCKED" });
      }
    });
    connection.once("secureConnect", () => {
      finish(
        isApprovedPeer(connection)
          ? { outcome: "accepted", protocol: connection.getProtocol() }
          : { outcome: "error", reason: "BLOCKED" },
      );
    });
    connection.once("error", (error: NodeJS.ErrnoException) => {
      const reason = error.code ?? error.message ?? "UNKNOWN";

      if (error instanceof AuditError) {
        finish({ outcome: "error", reason: "BLOCKED" });
      } else if (TLS_CLIENT_LIMITATION.test(reason)) {
        finish({ outcome: "error", reason: "UNSUPPORTED_RUNTIME" });
      } else if (TLS_EXPLICIT_REJECTION.test(reason)) {
        finish({ outcome: "rejected", reason, explicit: true });
      } else if (TLS_IMPLICIT_REJECTION.test(reason)) {
        finish({ outcome: "rejected", reason, explicit: false });
      } else {
        // DNS, red, etc.: la prueba no ha llegado a ser válida.
        finish({ outcome: "error", reason });
      }
    });
    // El servidor cierra antes de terminar el saludo y sin alerta.
    connection.once("close", () => {
      finish({ outcome: "rejected", reason: "CONNECTION_CLOSED", explicit: false });
    });
  });
}
