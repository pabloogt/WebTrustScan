import { afterEach, describe, expect, it } from "vitest";
import { AuditError } from "@/lib/audit/errors";
import {
  createGuardedLookup,
  fetchHeadersSafely,
} from "@/lib/audit/safeRequest";
import { isPublicAddress } from "@/lib/audit/ipGuard";
import { loopbackOnly, startServer, type TestServer } from "./helpers";

const servers: TestServer[] = [];

async function serve(handler: Parameters<typeof startServer>[0]) {
  const server = await startServer(handler);
  servers.push(server);
  return server;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function expectAuditError(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toBeInstanceOf(AuditError);
  await expect(promise).rejects.toMatchObject({ code });
}

const permissive = { addressPolicy: loopbackOnly, allowedPorts: null };

describe("fetchHeadersSafely · protección SSRF (política por defecto)", () => {
  it("bloquea un servidor local real aunque esté escuchando", async () => {
    let hits = 0;
    const server = await serve((_req, res) => {
      hits += 1;
      res.end("secreto interno");
    });

    await expectAuditError(
      fetchHeadersSafely(server.origin, { allowedPorts: null }),
      "BLOCKED_TARGET",
    );
    expect(hits).toBe(0);
  });

  it.each([
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://2130706433/", // 127.0.0.1 en decimal
    "http://0x7f.0.0.1/", // 127.0.0.1 en hexadecimal
    "http://0/",
    "http://[::ffff:127.0.0.1]/",
  ])("bloquea %s", async (url) => {
    await expectAuditError(fetchHeadersSafely(url), "BLOCKED_TARGET");
  });

  it("bloquea puertos que no sean 80/443 aunque la IP sea pública", async () => {
    await expectAuditError(
      fetchHeadersSafely("http://8.8.8.8:22/"),
      "BLOCKED_TARGET",
    );
    await expectAuditError(
      fetchHeadersSafely("https://8.8.8.8:8443/"),
      "BLOCKED_TARGET",
    );
  });

  it("el lookup DNS rechaza nombres que resuelven a IPs internas", async () => {
    const lookup = createGuardedLookup(isPublicAddress);

    const error = await new Promise<unknown>((resolve) => {
      lookup("localhost", { all: true }, (err) => resolve(err));
    });

    expect(error).toBeInstanceOf(AuditError);
    expect((error as AuditError).code).toBe("BLOCKED_TARGET");
  });

  it("bloquea una redirección hacia una IP no permitida", async () => {
    let internalHits = 0;
    const internal = await serve((_req, res) => {
      internalHits += 1;
      res.end("interno");
    });
    const entry = await serve((_req, res) => {
      // 127.0.0.2 también es loopback, pero la política solo admite 127.0.0.1
      res.writeHead(302, { location: `http://127.0.0.2:${internal.port}/` });
      res.end();
    });

    await expectAuditError(
      fetchHeadersSafely(entry.origin, permissive),
      "BLOCKED_TARGET",
    );
    expect(internalHits).toBe(0);
  });

  it("bloquea redirecciones a esquemas que no son http(s)", async () => {
    const entry = await serve((_req, res) => {
      res.writeHead(302, { location: "file:///etc/passwd" });
      res.end();
    });

    await expectAuditError(
      fetchHeadersSafely(entry.origin, permissive),
      "BLOCKED_TARGET",
    );
  });
});

describe("fetchHeadersSafely · comportamiento", () => {
  it("devuelve estado y cabeceras en minúsculas", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(200, { "X-Frame-Options": "DENY" });
      res.end("ok");
    });

    const result = await fetchHeadersSafely(server.origin, permissive);

    expect(result.status).toBe(200);
    expect(result.headers["x-frame-options"]).toBe("DENY");
    expect(result.redirects).toBe(0);
    expect(result.url).toBe(`${server.origin}/`);
  });

  it("sigue redirecciones relativas y absolutas", async () => {
    const server = await serve((req, res) => {
      if (req.url === "/") {
        res.writeHead(301, { location: "/paso" });
      } else if (req.url === "/paso") {
        res.writeHead(307, { location: `http://127.0.0.1:${server.port}/fin` });
      } else {
        res.writeHead(200, { "x-final": "si" });
      }
      res.end();
    });

    const result = await fetchHeadersSafely(server.origin, permissive);

    expect(result.url).toBe(`${server.origin}/fin`);
    expect(result.headers["x-final"]).toBe("si");
    expect(result.redirects).toBe(2);
  });

  it("corta los bucles de redirección", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(302, { location: "/" });
      res.end();
    });

    await expectAuditError(
      fetchHeadersSafely(server.origin, { ...permissive, maxRedirects: 3 }),
      "TOO_MANY_REDIRECTS",
    );
  });

  it("aplica timeout si el servidor no responde", async () => {
    const server = await serve(() => {
      // nunca responde
    });

    const started = Date.now();
    await expectAuditError(
      fetchHeadersSafely(server.origin, {
        ...permissive,
        requestTimeoutMs: 300,
      }),
      "TIMEOUT",
    );
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("no descarga el cuerpo de la respuesta", async () => {
    let bytesSent = 0;
    const server = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/octet-stream" });
      const chunk = Buffer.alloc(64 * 1024);
      const timer = setInterval(() => {
        bytesSent += chunk.length;
        res.write(chunk);
      }, 5);
      res.on("close", () => clearInterval(timer));
    });

    const started = Date.now();
    const result = await fetchHeadersSafely(server.origin, permissive);

    expect(result.status).toBe(200);
    expect(Date.now() - started).toBeLessThan(2000);

    await new Promise((resolve) => setTimeout(resolve, 200));
    const afterWait = bytesSent;
    await new Promise((resolve) => setTimeout(resolve, 200));
    // La conexión se cerró: el servidor deja de enviar datos.
    expect(bytesSent).toBe(afterWait);
  });

  it("informa de puerto cerrado como UNREACHABLE", async () => {
    const server = await serve((_req, res) => res.end());
    const origin = server.origin;
    await server.close();

    await expectAuditError(
      fetchHeadersSafely(origin, permissive),
      "UNREACHABLE",
    );
  });
});
