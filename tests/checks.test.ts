import { describe, expect, it } from "vitest";
import {
  buildChecks,
  CHECK_WEIGHTS,
  parseCsp,
  parseHstsMaxAge,
  type CheckInput,
} from "@/lib/audit/checks";
import { calculateScore } from "@/lib/audit/score";

const HARDENED_HEADERS = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'nonce-abc123'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

function run(overrides: Partial<CheckInput> = {}) {
  const checks = buildChecks({
    finalUrl: "https://ejemplo.com/",
    headers: HARDENED_HEADERS,
    httpRedirect: "redirects",
    ...overrides,
  });

  const status = (key: string) =>
    checks.find((check) => check.key === key)?.status;

  return { checks, status, score: calculateScore(checks) };
}

function withHeader(name: string, value: string | undefined) {
  const headers: Record<string, string> = { ...HARDENED_HEADERS };

  if (value === undefined) {
    delete headers[name];
  } else {
    headers[name] = value;
  }

  return run({ headers });
}

describe("puntuación", () => {
  it("cada check generado tiene peso y cada peso tiene check", () => {
    const keys = run()
      .checks.map((check) => check.key)
      .sort();

    expect(keys).toEqual(Object.keys(CHECK_WEIGHTS).sort());
  });

  it("una web bien configurada obtiene 100 (antes el máximo era 89)", () => {
    const { checks, score } = run();

    expect(checks.every((check) => check.status === "pass")).toBe(true);
    expect(checks.every((check) => check.fix === null)).toBe(true);
    expect(score).toBe(100);
  });

  it("una web HTTP sin cabeceras obtiene una puntuación mínima", () => {
    const { score, status } = run({
      finalUrl: "http://ejemplo.com/",
      headers: {},
      httpRedirect: "no-redirect",
    });

    expect(status("https")).toBe("fail");
    expect(status("hsts")).toBe("fail");
    expect(score).toBeLessThan(10);
  });

  it("solo HTTPS + redirección, sin cabeceras, ya no llega a 'Aceptable'", () => {
    const { score } = run({ headers: {} });

    // Antes: 72 ("Aceptable"). Ahora las cabeceras ausentes no puntúan.
    expect(score).toBeLessThan(50);
  });

  it("los checks que no pasan siempre traen cómo arreglarlo", () => {
    const { checks } = run({
      finalUrl: "http://ejemplo.com/",
      headers: {},
      httpRedirect: "unknown",
    });

    for (const check of checks) {
      expect(check.status).not.toBe("pass");
      expect(check.fix).toBeTruthy();
    }
  });

  it("falla de forma visible si un check no tiene peso", () => {
    expect(() =>
      calculateScore([
        {
          key: "inventado",
          title: "",
          status: "pass",
          description: "",
          fix: null,
        },
      ]),
    ).toThrow(/no tiene peso/);
  });
});

describe("redirección HTTP → HTTPS", () => {
  it.each([
    ["redirects", "pass"],
    ["no-redirect", "fail"],
    ["unknown", "warn"],
  ] as const)("%s → %s", (httpRedirect, expected) => {
    expect(run({ httpRedirect }).status("http-redirect")).toBe(expected);
  });
});

describe("Strict-Transport-Security", () => {
  it.each([
    ["max-age=31536000; includeSubDomains; preload", "pass"],
    ["max-age=15552000", "pass"],
    ['max-age="31536000"', "pass"],
    ["includeSubDomains; MAX-AGE=63072000", "pass"],
    ["max-age=86400", "warn"],
    ["max-age=0", "fail"],
    ["includeSubDomains", "fail"],
    ["max-age=abc", "fail"],
    [undefined, "fail"],
  ] as const)("%s → %s", (value, expected) => {
    expect(withHeader("strict-transport-security", value).status("hsts")).toBe(
      expected,
    );
  });

  it("no cuenta sobre HTTP aunque la cabecera exista", () => {
    expect(run({ finalUrl: "http://ejemplo.com/" }).status("hsts")).toBe(
      "fail",
    );
  });

  it("parseHstsMaxAge", () => {
    expect(parseHstsMaxAge("max-age=100")).toBe(100);
    expect(parseHstsMaxAge("x-max-age=100")).toBeNull();
    expect(parseHstsMaxAge("")).toBeNull();
  });
});

describe("Content-Security-Policy", () => {
  it.each([
    ["default-src 'self'", "pass"],
    ["script-src 'self' https://cdn.ejemplo.com", "pass"],
    ["script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https:", "pass"],
    ["script-src 'sha256-abc=' 'unsafe-inline'", "pass"],
    ["default-src 'self' 'unsafe-inline'", "warn"],
    ["default-src *", "warn"],
    ["script-src https:", "warn"],
    ["upgrade-insecure-requests", "warn"],
    ["frame-ancestors 'self'", "warn"],
    // dos cabeceras: se aplican ambas, basta con que una sea estricta
    ["default-src *, script-src 'self'", "pass"],
    [undefined, "fail"],
  ] as const)("%s → %s", (value, expected) => {
    expect(withHeader("content-security-policy", value).status("csp")).toBe(
      expected,
    );
  });

  it("Report-Only sin política aplicada es solo un aviso", () => {
    const { status } = run({
      headers: {
        ...HARDENED_HEADERS,
        "content-security-policy": "",
        "content-security-policy-report-only": "default-src 'self'",
      },
    });

    expect(status("csp")).toBe("warn");
  });

  it("parseCsp ignora directivas repetidas y normaliza a minúsculas", () => {
    const [policy] = parseCsp(
      "Script-Src 'SELF'; script-src *;; img-src data:",
    );

    expect(policy.get("script-src")).toEqual(["'self'"]);
    expect(policy.get("img-src")).toEqual(["data:"]);
    expect(parseCsp(undefined)).toEqual([]);
    expect(parseCsp(" ; ")).toEqual([]);
  });
});

describe("protección frente a iframes", () => {
  function frame(headers: Record<string, string>) {
    return run({ headers }).status("frame-protection");
  }

  it.each([
    [{ "x-frame-options": "DENY" }, "pass"],
    [{ "x-frame-options": " sameorigin " }, "pass"],
    [{ "content-security-policy": "frame-ancestors 'self'" }, "pass"],
    [
      {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      },
      "pass",
    ],
    [{ "x-frame-options": "ALLOWALL" }, "warn"],
    [{ "x-frame-options": "ALLOW-FROM https://otra.com" }, "warn"],
    [{ "content-security-policy": "frame-ancestors *" }, "warn"],
    [{ "content-security-policy": "frame-ancestors https:" }, "warn"],
    [
      { "content-security-policy-report-only": "frame-ancestors 'none'" },
      "warn",
    ],
    [{ "content-security-policy": "default-src 'self'" }, "fail"],
    // "frame-ancestors" como texto dentro de otra directiva no cuenta
    [
      { "content-security-policy": "report-uri /csp?d=frame-ancestors" },
      "fail",
    ],
    [{}, "fail"],
  ] as const)("%j → %s", (headers, expected) => {
    expect(frame(headers)).toBe(expected);
  });

  it("X-Frame-Options válido compensa un frame-ancestors abierto", () => {
    expect(
      frame({
        "x-frame-options": "DENY",
        "content-security-policy": "frame-ancestors *",
      }),
    ).toBe("pass");
  });
});

describe("X-Content-Type-Options", () => {
  it.each([
    ["nosniff", "pass"],
    [" NoSniff ", "pass"],
    ["nosniff, nosniff", "pass"],
    ["sniff", "fail"],
    ["1", "fail"],
    [undefined, "fail"],
  ] as const)("%s → %s", (value, expected) => {
    expect(
      withHeader("x-content-type-options", value).status(
        "x-content-type-options",
      ),
    ).toBe(expected);
  });
});

describe("Referrer-Policy", () => {
  it.each([
    ["strict-origin-when-cross-origin", "pass"],
    ["no-referrer", "pass"],
    ["Same-Origin", "pass"],
    // el navegador usa el último valor que reconoce
    ["unsafe-url, strict-origin", "pass"],
    ["no-referrer, valor-futuro", "pass"],
    ["unsafe-url", "warn"],
    ["no-referrer-when-downgrade", "warn"],
    ["strict-origin, unsafe-url", "warn"],
    ["inventado", "fail"],
    [undefined, "warn"],
  ] as const)("%s → %s", (value, expected) => {
    expect(withHeader("referrer-policy", value).status("referrer-policy")).toBe(
      expected,
    );
  });
});

describe("Permissions-Policy", () => {
  it.each([
    ["camera=()", "pass"],
    ["  ", "fail"],
    [undefined, "fail"],
  ] as const)("%s → %s", (value, expected) => {
    expect(
      withHeader("permissions-policy", value).status("permissions-policy"),
    ).toBe(expected);
  });
});
