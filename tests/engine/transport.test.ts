import zlib from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { safeFetch, safeTlsProbe } from "@/lib/audit/safeRequest";
import { runAudit } from "@/lib/engine/run";
import {
  GOOD_HEADERS,
  LAB_CA,
  finding,
  labLookup,
  loopbackOnly,
  respond,
  scan,
  startSite,
  type Site,
} from "../lab/harness";

/**
 * Regresión de seguridad de la capa de comunicación ampliada en el Engine
 * 2.0: las nuevas capacidades (cuerpo, TLS en modo inspección, sondas) no
 * deben abrir ninguna vía que esquive las protecciones SSRF existentes.
 */

const sites: Site[] = [];
const lab = { addressPolicy: loopbackOnly, allowedPorts: null, dnsLookup: labLookup, tlsCa: LAB_CA };

afterEach(async () => {
  await Promise.all(sites.splice(0).map((site) => site.close()));
});

async function site(spec: Parameters<typeof startSite>[0]) {
  const started = await startSite(spec);
  sites.push(started);
  return started;
}

describe("safeFetch · nuevas capacidades", () => {
  it("lee el cuerpo hasta el límite y marca el truncado", async () => {
    const big = await site({
      name: "big",
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("x".repeat(50_000));
      },
    });

    const limited = await safeFetch(big.url, { ...lab, maxBodyBytes: 1_000 });
    expect(limited.body).toHaveLength(1_000);
    expect(limited.bodyTruncated).toBe(true);

    const full = await safeFetch(big.url, { ...lab, maxBodyBytes: 100_000 });
    expect(full.body).toHaveLength(50_000);
    expect(full.bodyTruncated).toBe(false);

    const headersOnly = await safeFetch(big.url, lab);
    expect(headersOnly.body).toBeNull();
  });

  it("descomprime gzip y no revienta con una bomba de compresión", async () => {
    const gz = await site({
      name: "gz",
      handler: (req, res) => {
        const bomb = req.url === "/bomb";
        res.writeHead(200, { "content-encoding": "gzip" });
        res.end(zlib.gzipSync(bomb ? Buffer.alloc(64 * 1024 * 1024) : "<p>hola</p>"));
      },
    });

    expect((await safeFetch(gz.url, { ...lab, maxBodyBytes: 4_096 })).body).toBe("<p>hola</p>");

    // 64 MB de ceros comprimidos: se descarta el cuerpo, no se agota la memoria.
    const bomb = await safeFetch(`${gz.url}bomb`, { ...lab, maxBodyBytes: 512 * 1024 });
    expect(bomb.body).toBeNull();
    expect(bomb.status).toBe(200);
  });

  it("conserva cada Set-Cookie por separado y la cadena de redirecciones", async () => {
    const target = await site({
      name: "cookies",
      handler: (req, res) => {
        if (req.url === "/") {
          res.writeHead(302, { location: "/fin" });
          res.end();
          return;
        }
        res.writeHead(200, {
          "set-cookie": ["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2"],
        });
        res.end();
      },
    });

    const result = await safeFetch(target.url, lab);

    expect(result.setCookies).toEqual(["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2"]);
    expect(result.chain.map((hop) => hop.status)).toEqual([302, 200]);
    expect(result.tls).toMatchObject({ authorized: true, protocol: "TLSv1.3" });
  });

  it("modo strict: un certificado inválido aborta; modo inspect: lo describe", async () => {
    const expired = await site({ name: "exp", cert: "expired", handler: respond() });

    await expect(safeFetch(expired.url, lab)).rejects.toMatchObject({
      code: "TLS_ERROR",
      reason: "CERT_HAS_EXPIRED",
    });

    const inspected = await safeFetch(expired.url, { ...lab, tlsMode: "inspect" });
    expect(inspected.status).toBe(200);
    expect(inspected.tls).toMatchObject({
      authorized: false,
      authorizationError: "CERT_HAS_EXPIRED",
    });
  });
});

describe("protecciones SSRF en las vías nuevas", () => {
  it.each([
    "https://127.0.0.1/",
    "https://10.0.0.5/",
    "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/",
    "https://[::ffff:127.0.0.1]/",
  ])("el modo inspect no relaja el bloqueo de %s", async (url) => {
    await expect(
      safeFetch(url, { tlsMode: "inspect", maxBodyBytes: 1_024 }),
    ).rejects.toMatchObject({ code: "BLOCKED_TARGET" });
  });

  it("la sonda TLS valida destino, puerto e IP resuelta", async () => {
    const versions = { minVersion: "TLSv1", maxVersion: "TLSv1.1" } as const;

    expect(() => safeTlsProbe("https://127.0.0.1", versions)).toThrow(/no se puede analizar/);
    expect(() => safeTlsProbe("https://example.com:8443", versions)).toThrow();
    expect(() => safeTlsProbe("ftp://example.com", versions)).toThrow();

    // Un dominio público que resuelve a una IP interna (rebinding).
    const rebind = await safeTlsProbe("https://rebind.lab.test", versions, {
      dnsLookup: labLookup,
    });
    expect(rebind).toEqual({ outcome: "error", reason: "BLOCKED" });
  });

  it("una redirección a una IP interna corta el análisis completo", async () => {
    const evil = await site({
      name: "evil",
      handler: (_req, res) => {
        res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
        res.end();
      },
    });

    // La política del laboratorio solo admite 127.0.0.1: el salto a la IP de
    // metadatos debe cortarse igual que en producción.
    await expect(runAudit(evil.url, lab)).rejects.toMatchObject({
      code: "BLOCKED_TARGET",
    });
  });

  it("el motor rechaza destinos internos con la configuración por defecto", async () => {
    for (const url of ["http://127.0.0.1", "localhost", "http://[::1]", "https://192.168.1.1"]) {
      await expect(runAudit(url)).rejects.toMatchObject({ code: "BLOCKED_TARGET" });
    }
    await expect(runAudit("file:///etc/passwd")).rejects.toMatchObject({ code: "INVALID_URL" });
  });

  it("las sondas secundarias que apuntan a un destino bloqueado no puntúan en contra", async () => {
    // La sonda HTTP va al puerto del laboratorio; con la política por
    // defecto de puertos queda bloqueada y debe figurar como no comprobada.
    const target = await site({ name: "ports", handler: respond(GOOD_HEADERS) });
    const report = await scan(target, undefined, { httpPort: undefined, allowedPorts: null });

    expect(["pass", "not_tested"]).toContain(
      finding(report, "transport.http-redirect").status,
    );
    expect(report.web.counts.status.fail).toBe(0);
  });
});

describe("runAudit · límites", () => {
  it("respeta el tiempo máximo total cuando el sitio no responde", async () => {
    const silent = await site({ name: "silent", handler: () => {} });

    await expect(
      scan(silent, undefined, { totalTimeoutMs: 400, requestTimeoutMs: 5_000 }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
  });

  it("si el tiempo se agota en las sondas, entrega el informe con lo comprobado", async () => {
    const slowProbes = await site({
      name: "slow",
      handler: (req, res) => {
        // Solo la petición principal responde; la sonda CORS y security.txt no.
        if (req.headers.origin || req.url !== "/") return;
        respond(GOOD_HEADERS)(req, res);
      },
      http: "hang",
    });

    const report = await scan(slowProbes, undefined, {
      totalTimeoutMs: 1_200,
      requestTimeoutMs: 800,
    });

    expect(finding(report, "cors.policy").status).toBe("not_tested");
    expect(finding(report, "transport.http-redirect").status).toBe("not_tested");
    expect(report.web.counts.status.fail).toBe(0);
    expect(report.web.score).toBe(100);
    expect(report.web.coverage).toBeLessThan(100);
  });

  it("no hace más de 5 peticiones al sitio por análisis", async () => {
    let requests = 0;
    const counted = await site({
      name: "count",
      handler: (req, res) => {
        requests += 1;
        respond(GOOD_HEADERS)(req, res);
      },
      http: (_req, res) => {
        requests += 1;
        res.writeHead(301, { location: counted.url });
        res.end();
      },
    });

    await scan(counted);

    // principal + CORS + security.txt + http:// (y su salto a https).
    expect(requests).toBeLessThanOrEqual(5);
  });
});
