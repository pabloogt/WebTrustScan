import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import path from "node:path";
import type tls from "node:tls";
import { analyzeUrl } from "@/lib/audit/analyze";
import { AuditError } from "@/lib/audit/errors";
import type { DnsLookup } from "@/lib/audit/safeRequest";
import type { DnsClient } from "@/lib/engine/dnsClient";
import { runAudit, type EngineOptions } from "@/lib/engine/run";
import type { AuditReport } from "@/lib/engine/types";

/**
 * Laboratorio de WebTrustScan: sitios HTTP/HTTPS simulados en 127.0.0.1 bajo
 * el dominio ficticio *.lab.test, con una CA propia y una zona DNS simulada.
 * Nada de lo que hay aquí sale a Internet.
 */

const CERTS = path.join(__dirname, "certs");
const read = (name: string) => fs.readFileSync(path.join(CERTS, name));

export const LAB_CA = read("ca.crt");
const SERVER_KEY = read("server.key");

export type CertName = "valid" | "expired" | "wronghost" | "selfsigned";

export type Handler = http.RequestListener;

export type SiteSpec = {
  /** Etiqueta del host: el sitio será https://<name>.lab.test:<puerto>/ */
  name: string;
  /** Certificado del servidor HTTPS, o false si el sitio no tiene HTTPS. */
  cert?: CertName | false;
  /** Opciones TLS extra (p. ej. para aceptar TLS 1.0). */
  tls?: tls.SecureContextOptions;
  handler: Handler;
  /**
   * Comportamiento del puerto HTTP:
   * - redirect (por defecto): 301 a la versión HTTPS.
   * - serve: sirve el mismo contenido sin redirigir.
   * - closed: el puerto no escucha (conexión rechazada).
   * - hang: acepta la conexión y nunca responde.
   */
  http?: "redirect" | "serve" | "closed" | "hang" | Handler;
};

export type Site = {
  host: string;
  url: string;
  httpPort: number;
  httpsPort: number | null;
  close: () => Promise<void>;
};

function listen(server: http.Server | https.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve((server.address() as AddressInfo).port),
    );
  });
}

function close(server: http.Server | https.Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

/** Devuelve un puerto en el que seguro que no escucha nadie. */
export async function closedPort(): Promise<number> {
  const server = http.createServer();
  const port = await listen(server);
  await close(server);
  return port;
}

export async function startSite(spec: SiteSpec): Promise<Site> {
  const host = `${spec.name}.lab.test`;
  const servers: (http.Server | https.Server)[] = [];
  let httpsPort: number | null = null;

  if (spec.cert !== false) {
    const secure = https.createServer(
      {
        key: SERVER_KEY,
        cert: Buffer.concat([
          read(`${spec.cert ?? "valid"}.crt`),
          spec.cert === "selfsigned" ? Buffer.alloc(0) : LAB_CA,
        ]),
        ...spec.tls,
      },
      spec.handler,
    );
    httpsPort = await listen(secure);
    servers.push(secure);
  }

  const mode = spec.http ?? (spec.cert === false ? "serve" : "redirect");
  let httpPort: number;

  if (mode === "closed") {
    httpPort = await closedPort();
  } else {
    const handler: Handler =
      typeof mode === "function"
        ? mode
        : mode === "serve"
          ? spec.handler
          : mode === "hang"
            ? () => {}
            : (req, res) => {
                res.writeHead(301, {
                  location: `https://${host}:${httpsPort}${req.url ?? "/"}`,
                });
                res.end();
              };
    const plain = http.createServer(handler);
    httpPort = await listen(plain);
    servers.push(plain);
  }

  return {
    host,
    url: httpsPort
      ? `https://${host}:${httpsPort}/`
      : `http://${host}:${httpPort}/`,
    httpPort,
    httpsPort,
    close: async () => {
      await Promise.all(servers.map(close));
    },
  };
}

/** DNS del laboratorio: cualquier *.lab.test apunta a 127.0.0.1. */
export const labLookup: DnsLookup = (hostname, _options, callback) => {
  if (hostname === "lab.test" || hostname.endsWith(".lab.test")) {
    callback(null, [{ address: "127.0.0.1", family: 4 }]);
    return;
  }

  const error: NodeJS.ErrnoException = new Error(`ENOTFOUND ${hostname}`);
  error.code = "ENOTFOUND";
  callback(error, []);
};

export type Zone = {
  mx?: Record<string, string[]>;
  txt?: Record<string, string[]>;
  caa?: Record<string, string[]>;
  /** Simula un resolvedor que no responde. */
  failing?: boolean;
};

export function zoneClient(zone: Zone = {}): DnsClient {
  const answer = (table: Record<string, string[]> | undefined, name: string) => {
    if (zone.failing) {
      const error: NodeJS.ErrnoException = new Error("queryTxt ETIMEOUT");
      error.code = "ETIMEOUT";
      return Promise.reject(error);
    }

    return Promise.resolve(table?.[name] ?? []);
  };

  return {
    resolveTxt: (name) => answer(zone.txt, name),
    resolveMx: (name) => answer(zone.mx, name),
    resolveCaa: (name) => answer(zone.caa, name),
  };
}

export const loopbackOnly = (address: string) => address === "127.0.0.1";

export function labOptions(site: Site, zone?: Zone): EngineOptions {
  return {
    addressPolicy: loopbackOnly,
    allowedPorts: null,
    dnsLookup: labLookup,
    tlsCa: LAB_CA,
    httpPort: site.httpPort,
    requestTimeoutMs: 1_500,
    totalTimeoutMs: 10_000,
    dnsClient: zoneClient(zone),
  };
}

/** Ejecuta el motor 2.0 contra un sitio del laboratorio. */
export function scan(
  site: Site,
  zone?: Zone,
  overrides: Partial<EngineOptions> = {},
): Promise<AuditReport> {
  return runAudit(site.url, { ...labOptions(site, zone), ...overrides });
}

export type LegacyOutcome =
  | { kind: "score"; score: number; statuses: Record<string, string> }
  | { kind: "error"; code: string };

/** Ejecuta el motor 1.x (congelado) contra el mismo sitio, para comparar. */
export async function scanLegacy(site: Site): Promise<LegacyOutcome> {
  try {
    const result = await analyzeUrl(site.url, {
      addressPolicy: loopbackOnly,
      allowedPorts: null,
      dnsLookup: labLookup,
      tlsCa: LAB_CA,
      httpPort: site.httpPort,
      requestTimeoutMs: 1_500,
      totalTimeoutMs: 10_000,
    });

    return {
      kind: "score",
      score: result.score,
      statuses: Object.fromEntries(
        result.checks.map((check) => [check.key, check.status]),
      ),
    };
  } catch (error) {
    return {
      kind: "error",
      code: error instanceof AuditError ? error.code : "INTERNAL",
    };
  }
}

/* ---------- respuestas de ejemplo ---------- */

export const GOOD_HEADERS: Record<string, string | string[]> = {
  "content-type": "text/html; charset=utf-8",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

export const SIMPLE_PAGE =
  '<!doctype html><html lang="es"><head><title>Lab</title><link rel="stylesheet" href="/app.css"></head><body><h1>Sitio de laboratorio</h1><p>Contenido estático de ejemplo para las pruebas del motor de auditoría de WebTrustScan, con texto suficiente para no parecer una aplicación de una sola página generada por completo en el navegador.</p><script src="/app.js" nonce="abc123"></script></body></html>';

/** Handler que responde siempre lo mismo (y 404 a security.txt). */
export function respond(
  headers: Record<string, string | string[]> = {},
  body: string = SIMPLE_PAGE,
  status = 200,
): Handler {
  return (req, res) => {
    if (req.url?.startsWith("/.well-known/")) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }

    res.writeHead(status, headers);
    res.end(body);
  };
}

export function finding(report: AuditReport, id: string) {
  const found = report.findings.find((entry) => entry.id === id);
  if (!found) throw new Error(`Sin hallazgo para ${id}`);
  return found;
}
