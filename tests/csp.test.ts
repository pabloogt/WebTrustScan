import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildChecks, parseCsp } from "@/lib/audit/checks";
import {
  API_CONTENT_SECURITY_POLICY,
  buildContentSecurityPolicy,
  generateNonce,
} from "@/lib/csp";
import { config, proxy } from "@/proxy";

afterEach(() => {
  vi.unstubAllEnvs();
});

function directives(policy: string) {
  return parseCsp(policy)[0];
}

describe("buildContentSecurityPolicy (producción)", () => {
  const policy = buildContentSecurityPolicy({ nonce: "abc123", isDev: false });
  const parsed = directives(policy);

  it("no permite scripts ni estilos en línea sin nonce, ni eval", () => {
    expect(policy).not.toContain("'unsafe-inline'");
    expect(policy).not.toContain("'unsafe-eval'");
    expect(parsed.get("script-src")).toEqual([
      "'self'",
      "'nonce-abc123'",
      "'strict-dynamic'",
    ]);
    expect(parsed.get("style-src")).toEqual(["'self'", "'nonce-abc123'"]);
  });

  it("mantiene las restricciones que no dependen del nonce", () => {
    expect(parsed.get("default-src")).toEqual(["'self'"]);
    expect(parsed.get("object-src")).toEqual(["'none'"]);
    expect(parsed.get("base-uri")).toEqual(["'self'"]);
    expect(parsed.get("form-action")).toEqual(["'self'"]);
    expect(parsed.get("frame-ancestors")).toEqual(["'none'"]);
    expect(parsed.get("connect-src")).toEqual(["'self'"]);
  });

  it("no contiene comodines ni esquemas abiertos", () => {
    for (const [name, sources] of parsed) {
      if (name === "img-src") continue;
      expect(sources).not.toContain("*");
      expect(sources).not.toContain("https:");
      expect(sources).not.toContain("data:");
    }
  });

  it("WebTrustScan aprueba su propia política", () => {
    const checks = buildChecks({
      finalUrl: "https://webtrustscan.example/",
      headers: { "content-security-policy": policy },
      httpRedirect: "redirects",
    });
    const status = (key: string) =>
      checks.find((check) => check.key === key)?.status;

    expect(status("csp")).toBe("pass");
    expect(status("frame-protection")).toBe("pass");
  });

  it("la política anterior, con 'unsafe-inline', solo merecía un aviso", () => {
    const checks = buildChecks({
      finalUrl: "https://webtrustscan.example/",
      headers: {
        "content-security-policy":
          "default-src 'self'; script-src 'self' 'unsafe-inline'",
      },
      httpRedirect: "redirects",
    });

    expect(checks.find((check) => check.key === "csp")?.status).toBe("warn");
  });
});

describe("buildContentSecurityPolicy (desarrollo)", () => {
  const parsed = directives(
    buildContentSecurityPolicy({ nonce: "abc123", isDev: true }),
  );

  it("relaja solo lo que necesitan las herramientas de desarrollo", () => {
    expect(parsed.get("script-src")).toContain("'unsafe-eval'");
    expect(parsed.get("script-src")).not.toContain("'unsafe-inline'");
    expect(parsed.get("connect-src")).toEqual(["'self'", "ws:", "wss:"]);
    // Con nonce el navegador ignoraría 'unsafe-inline': no pueden ir juntos.
    expect(parsed.get("style-src")).toEqual(["'self'", "'unsafe-inline'"]);
  });
});

describe("generateNonce", () => {
  it("genera valores distintos, largos y válidos para una cabecera", () => {
    const nonces = new Set(Array.from({ length: 200 }, generateNonce));

    expect(nonces.size).toBe(200);
    for (const nonce of nonces) {
      expect(nonce).toMatch(/^[A-Za-z0-9+/=]{40,}$/);
    }
  });
});

describe("proxy", () => {
  const run = () => proxy(new NextRequest("http://localhost/"));
  const nonceOf = (policy: string | null) =>
    /'nonce-([^']+)'/.exec(policy ?? "")?.[1];

  it("añade a la respuesta una CSP con nonce y sin 'unsafe-inline'", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const policy = (await run()).headers.get("content-security-policy");

    expect(nonceOf(policy)).toBeTruthy();
    expect(policy).not.toContain("'unsafe-inline'");
    expect(policy).not.toContain("'unsafe-eval'");
  });

  it("usa un nonce distinto en cada petición", async () => {
    const first = nonceOf((await run()).headers.get("content-security-policy"));
    const second = nonceOf((await run()).headers.get("content-security-policy"));

    expect(first).not.toBe(second);
  });

  it("pasa a Next.js el mismo nonce que envía al navegador", async () => {
    const response = await run();
    const sent = nonceOf(response.headers.get("content-security-policy"));
    const forwarded = response.headers.get(
      "x-middleware-request-content-security-policy",
    );

    expect(nonceOf(forwarded)).toBe(sent);
    expect(response.headers.get("x-middleware-request-x-nonce")).toBe(sent);
  });

  it("no se aplica a la API ni a los estáticos", async () => {
    const source = new RegExp(`^${config.matcher[0].source}$`);

    expect(source.test("/")).toBe(true);
    expect(source.test("/cualquier/pagina")).toBe(true);
    expect(source.test("/api/analyze")).toBe(false);
    expect(source.test("/_next/static/chunk.js")).toBe(false);
    expect(source.test("/favicon.ico")).toBe(false);
  });
});

describe("CSP de la API", () => {
  it("no permite cargar ni enmarcar nada", async () => {
    const parsed = directives(API_CONTENT_SECURITY_POLICY);

    expect(parsed.get("default-src")).toEqual(["'none'"]);
    expect(parsed.get("frame-ancestors")).toEqual(["'none'"]);
  });
});
