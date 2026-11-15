import { afterEach, describe, expect, it } from "vitest";
import { analyzeUrl } from "@/lib/audit/analyze";
import { loopbackOnly, startServer, type TestServer } from "./helpers";

const servers: TestServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe("analyzeUrl (contra un servidor local)", () => {
  it("analiza las cabeceras reales de la respuesta", async () => {
    const server = await startServer((_req, res) => {
      res.writeHead(200, {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
      });
      res.end("hola");
    });
    servers.push(server);

    const result = await analyzeUrl(server.origin, {
      addressPolicy: loopbackOnly,
      allowedPorts: null,
      httpPort: server.port,
    });

    const status = (key: string) =>
      result.checks.find((check) => check.key === key)?.status;

    expect(result.url).toBe(`${server.origin}/`);
    expect(result.httpStatus).toBe(200);
    expect(status("https")).toBe("fail");
    expect(status("x-content-type-options")).toBe("pass");
    expect(status("referrer-policy")).toBe("pass");
    expect(status("csp")).not.toBe("pass");
    expect(status("http-redirect")).not.toBe("pass");
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it("devuelve el código HTTP del destino cuando responde con error", async () => {
    const server = await startServer((_req, res) => {
      res.writeHead(404);
      res.end();
    });
    servers.push(server);

    const result = await analyzeUrl(server.origin, {
      addressPolicy: loopbackOnly,
      allowedPorts: null,
      httpPort: server.port,
    });

    expect(result.httpStatus).toBe(404);
  });

  it("respeta el tiempo máximo total", async () => {
    const server = await startServer(() => {
      // nunca responde
    });
    servers.push(server);

    await expect(
      analyzeUrl(server.origin, {
        addressPolicy: loopbackOnly,
        allowedPorts: null,
        totalTimeoutMs: 300,
      }),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
  });

  it("rechaza destinos internos con la configuración por defecto", async () => {
    await expect(analyzeUrl("http://127.0.0.1")).rejects.toMatchObject({
      code: "BLOCKED_TARGET",
    });
    await expect(analyzeUrl("localhost")).rejects.toMatchObject({
      code: "BLOCKED_TARGET",
    });
  });
});
