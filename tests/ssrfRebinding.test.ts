import { afterEach, describe, expect, it } from "vitest";
import { analyzeUrl } from "@/lib/audit/analyze";
import { AuditError } from "@/lib/audit/errors";
import { isPublicAddress } from "@/lib/audit/ipGuard";
import {
  canonicalAddress,
  fetchHeadersSafely,
  type DnsLookup,
} from "@/lib/audit/safeRequest";
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

/**
 * DNS controlado por el "atacante": devuelve una respuesta distinta en cada
 * consulta, como haría un dominio con TTL 0 durante un ataque de rebinding.
 */
function scriptedDns(answers: string[][]) {
  const queries: string[] = [];

  const lookup: DnsLookup = (hostname, _options, callback) => {
    const answer = answers[Math.min(queries.length, answers.length - 1)];
    queries.push(hostname);
    callback(
      null,
      answer.map((address) => ({
        address,
        family: address.includes(":") ? 6 : 4,
      })),
    );
  };

  return { lookup, queries };
}

async function expectBlocked(promise: Promise<unknown>) {
  await expect(promise).rejects.toBeInstanceOf(AuditError);
  await expect(promise).rejects.toMatchObject({ code: "BLOCKED_TARGET" });
}

// En estos tests 127.0.0.1 hace de "IP pública permitida" y cualquier otra
// dirección de "IP interna", para no depender de internet.
const base = { addressPolicy: loopbackOnly, allowedPorts: null };

describe("DNS rebinding", () => {
  it("la IP validada es exactamente la IP a la que se conecta el socket", async () => {
    const server = await serve((_req, res) => res.end("ok"));
    const dns = scriptedDns([["127.0.0.1"]]);

    const result = await fetchHeadersSafely(
      `http://rebind.test:${server.port}/`,
      { ...base, dnsLookup: dns.lookup },
    );

    expect(result.status).toBe(200);
    expect(result.remoteAddress).toBe("127.0.0.1");
    // Una única resolución: no hay "validar" y luego "volver a resolver".
    expect(dns.queries).toEqual(["rebind.test"]);
  });

  it("no conecta si el DNS cambia a una IP interna en la conexión real", async () => {
    let hits = 0;
    const server = await serve((_req, res) => {
      hits += 1;
      res.end("secreto");
    });
    // Un validador previo habría visto 127.0.0.1; aquí solo hay una consulta
    // y es la que decide: si es interna, no se abre conexión.
    const dns = scriptedDns([["10.0.0.5"]]);

    await expectBlocked(
      fetchHeadersSafely(`http://rebind.test:${server.port}/`, {
        ...base,
        dnsLookup: dns.lookup,
      }),
    );
    expect(hits).toBe(0);
  });

  it("revalida en cada redirección aunque el nombre sea el mismo", async () => {
    const paths: string[] = [];
    const server = await serve((req, res) => {
      paths.push(req.url ?? "");
      if (req.url === "/") {
        res.writeHead(302, { location: "/interno" });
      }
      res.end();
    });
    // 1ª consulta (salto inicial): permitida. 2ª (tras redirigir): interna.
    const dns = scriptedDns([["127.0.0.1"], ["127.0.0.2"]]);

    await expectBlocked(
      fetchHeadersSafely(`http://rebind.test:${server.port}/`, {
        ...base,
        dnsLookup: dns.lookup,
      }),
    );
    expect(dns.queries).toHaveLength(2);
    expect(paths).toEqual(["/"]); // nunca llegó a pedir /interno
  });

  it("resuelve una vez por conexión y no reutiliza sockets entre saltos", async () => {
    const server = await serve((req, res) => {
      if (req.url === "/") res.writeHead(302, { location: "/a" });
      else if (req.url === "/a") res.writeHead(302, { location: "/b" });
      res.end();
    });
    const dns = scriptedDns([["127.0.0.1"]]);

    const result = await fetchHeadersSafely(
      `http://rebind.test:${server.port}/`,
      { ...base, dnsLookup: dns.lookup },
    );

    expect(result.redirects).toBe(2);
    expect(dns.queries).toHaveLength(3);
  });

  it("rechaza respuestas DNS que mezclan IPs públicas e internas", async () => {
    for (const answer of [
      ["93.184.216.34", "127.0.0.1"],
      ["127.0.0.1", "93.184.216.34"],
      ["93.184.216.34", "::1"],
      ["2606:4700:4700::1111", "fd00::1"],
      ["93.184.216.34", "::ffff:169.254.169.254"],
    ]) {
      const dns = scriptedDns([answer]);

      await expectBlocked(
        fetchHeadersSafely("http://mixto.test/", { dnsLookup: dns.lookup }),
      );
    }
  });

  it("rechaza una respuesta DNS vacía", async () => {
    const dns = scriptedDns([[]]);

    await expectBlocked(
      fetchHeadersSafely("http://vacio.test/", { dnsLookup: dns.lookup }),
    );
  });

  it("segunda barrera: corta si el socket acaba en una IP no aprobada", async () => {
    let hits = 0;
    const server = await serve((_req, res) => {
      hits += 1;
      res.end("secreto");
    });
    const dns = scriptedDns([["127.0.0.1"]]);

    // Simula que algo esquiva la validación del lookup: la política aprueba
    // la IP al resolver, pero la rechaza al comprobar el socket conectado.
    let checks = 0;
    const flipping = (address: string) => {
      checks += 1;
      return checks === 1 && address === "127.0.0.1";
    };

    await expectBlocked(
      fetchHeadersSafely(`http://rebind.test:${server.port}/`, {
        addressPolicy: flipping,
        allowedPorts: null,
        dnsLookup: dns.lookup,
      }),
    );
    expect(checks).toBeGreaterThan(1);
    // La conexión TCP se abre, pero la respuesta nunca se entrega.
    expect(hits).toBeLessThanOrEqual(1);
  });

  it("la comprobación HTTP→HTTPS también pasa por el lookup guardado", async () => {
    let hits = 0;
    const server = await serve((_req, res) => {
      hits += 1;
      res.end("ok");
    });
    // 1ª consulta: petición principal. 2ª: comprobación http:// → interna.
    const dns = scriptedDns([["127.0.0.1"], ["10.0.0.5"]]);

    const result = await analyzeUrl(`http://rebind.test:${server.port}/`, {
      ...base,
      dnsLookup: dns.lookup,
      httpPort: server.port,
    });

    expect(dns.queries).toHaveLength(2);
    expect(hits).toBe(1);
    expect(
      result.checks.find((check) => check.key === "http-redirect")?.status,
    ).toBe("warn");
  });
});

describe("SSRF · redirecciones", () => {
  it("bloquea redirecciones a un puerto no permitido", async () => {
    let hits = 0;
    const internal = await serve((_req, res) => {
      hits += 1;
      res.end();
    });
    const entry = await serve((_req, res) => {
      res.writeHead(302, { location: `http://127.0.0.1:${internal.port}/` });
      res.end();
    });

    await expectBlocked(
      fetchHeadersSafely(entry.origin, {
        addressPolicy: loopbackOnly,
        allowedPorts: [entry.port],
      }),
    );
    expect(hits).toBe(0);
  });

  it.each([
    ["credenciales embebidas", "http://admin:secreto@127.0.0.1/"],
    ["metadatos cloud", "http://169.254.169.254/latest/meta-data/"],
    ["IPv6 loopback", "http://[::1]/"],
    ["esquema gopher", "gopher://127.0.0.1:6379/_INFO"],
    ["ruta UNC/protocolo relativo", "//10.0.0.1/"],
  ])("bloquea una redirección con %s", async (_name, location) => {
    const entry = await serve((_req, res) => {
      res.writeHead(302, { location });
      res.end();
    });

    // Política por defecto + excepción solo para el servidor de entrada.
    await expectBlocked(
      fetchHeadersSafely(entry.origin, {
        addressPolicy: (address) =>
          address === "127.0.0.1" || isPublicAddress(address),
        allowedPorts: [entry.port],
      }),
    );
  });

  it("no sigue redirecciones en respuestas que no son 3xx", async () => {
    const server = await serve((_req, res) => {
      res.writeHead(200, { location: "http://169.254.169.254/" });
      res.end();
    });

    const result = await fetchHeadersSafely(server.origin, base);

    expect(result.status).toBe(200);
    expect(result.redirects).toBe(0);
  });
});

describe("SSRF · formas alternativas de escribir una IP interna", () => {
  it.each([
    "http://127.1/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://127.0.0.1./",
    "http://LOCALHOST/",
    "http://[::127.0.0.1]/",
    "http://[0:0:0:0:0:ffff:7f00:1]/",
    "http://[::ffff:a9fe:a9fe]/", // 169.254.169.254 mapeada
    "http://[64:ff9b::a9fe:a9fe]/", // NAT64
    "http://[2002:7f00:1::]/", // 6to4
    "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", // Teredo
    "http://[fe80::1]/",
    "http://[fd00:ec2::254]/", // metadatos AWS por IPv6
    "http://100.100.100.200/", // metadatos Alibaba (CGNAT)
    "http://192.0.0.192/", // metadatos Oracle
  ])("bloquea %s", async (url) => {
    await expectBlocked(fetchHeadersSafely(url));
  });
});

describe("canonicalAddress", () => {
  it("normaliza direcciones equivalentes a la misma forma", () => {
    expect(canonicalAddress("::ffff:127.0.0.1")).toBe("127.0.0.1");
    expect(canonicalAddress("2606:4700:0:0:0:0:0:1111")).toBe(
      "2606:4700::1111",
    );
    expect(canonicalAddress("2606:4700::1111")).toBe("2606:4700::1111");
    expect(canonicalAddress("FE80::1")).toBe("fe80::1");
    expect(canonicalAddress("8.8.8.8")).toBe("8.8.8.8");
  });
});
