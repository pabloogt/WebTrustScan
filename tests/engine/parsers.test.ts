import { describe, expect, it } from "vitest";
import {
  describeCookie,
  isSessionLikeName,
  parseCookies,
  parseSetCookie,
} from "@/lib/engine/parse/cookies";
import {
  assessScripts,
  firstHeaderValue,
  frameAncestors,
  parseCsp,
  parseHstsMaxAge,
  upgradesInsecureRequests,
} from "@/lib/engine/parse/csp";
import { extractHtmlFacts, siteOf } from "@/lib/engine/parse/html";

const strength = (csp: string) => assessScripts(parseCsp(csp)).strength;

describe("CSP", () => {
  it.each([
    ["default-src 'self'", "strong"],
    ["script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'", "strong"],
    ["script-src 'self' 'sha256-abc' 'unsafe-inline'", "strong"],
    ["script-src 'self' 'unsafe-eval'", "eval-only"],
    ["script-src 'self' 'unsafe-inline'", "weak"],
    ["default-src *", "weak"],
    ["script-src https:", "weak"],
    ["script-src 'self' data:", "weak"],
    ["frame-ancestors 'self'", "unrestricted"],
    ["upgrade-insecure-requests", "unrestricted"],
  ])("%s → %s", (csp, expected) => {
    expect(strength(csp)).toBe(expected);
  });

  it("con varias políticas cuenta la más estricta", () => {
    expect(strength("script-src 'unsafe-inline' *, script-src 'self'")).toBe("strong");
  });

  it("ignora directivas repetidas, como hace el navegador", () => {
    expect(strength("script-src 'self'; script-src *")).toBe("strong");
  });

  it("evalúa frame-ancestors", () => {
    expect(frameAncestors(parseCsp("frame-ancestors 'none'"))).toBe("strict");
    expect(frameAncestors(parseCsp("frame-ancestors https://a.example"))).toBe("strict");
    expect(frameAncestors(parseCsp("frame-ancestors *"))).toBe("open");
    expect(frameAncestors(parseCsp("default-src 'self'"))).toBeNull();
    expect(frameAncestors(parseCsp("frame-ancestors *, frame-ancestors 'self'"))).toBe("strict");
  });

  it("detecta upgrade-insecure-requests", () => {
    expect(upgradesInsecureRequests(parseCsp("upgrade-insecure-requests"))).toBe(true);
    expect(upgradesInsecureRequests(parseCsp("default-src 'self'"))).toBe(false);
  });
});

describe("cabeceras de valor único", () => {
  it("usa el primer valor cuando la cabecera llega duplicada", () => {
    expect(firstHeaderValue("max-age=31536000, max-age=0")).toBe("max-age=31536000");
    expect(firstHeaderValue("nosniff, nosniff")).toBe("nosniff");
    expect(firstHeaderValue(undefined)).toBeUndefined();
    expect(firstHeaderValue("  ")).toBeUndefined();
  });

  it("parsea max-age de HSTS", () => {
    expect(parseHstsMaxAge("max-age=31536000; includeSubDomains")).toBe(31_536_000);
    expect(parseHstsMaxAge('includeSubDomains; max-age="600"')).toBe(600);
    expect(parseHstsMaxAge("max-age=0")).toBe(0);
    expect(parseHstsMaxAge("includeSubDomains")).toBeNull();
    expect(parseHstsMaxAge("max-age=abc")).toBeNull();
  });
});

describe("cookies", () => {
  it("parsea atributos sin conservar el valor", () => {
    const cookie = parseSetCookie(
      "sid=VALOR-SECRETO; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
    );

    expect(cookie).toEqual({
      name: "sid",
      secure: true,
      httpOnly: true,
      sameSite: "strict",
      domain: null,
      path: "/",
      sessionLifetime: false,
      sessionLike: true,
    });
    expect(JSON.stringify(cookie)).not.toContain("VALOR-SECRETO");
    expect(describeCookie(cookie!)).toBe("sid → Secure; HttpOnly; SameSite=strict");
  });

  it.each([
    ["PHPSESSID", true],
    ["JSESSIONID", true],
    ["connect.sid", true],
    ["__Host-session", true],
    ["auth_token", true],
    ["wordpress_logged_in_abc", true],
    ["XSRF-TOKEN", false],
    ["csrftoken", false],
    ["theme", false],
    ["_ga", false],
    ["cookie_consent", false],
  ])("¿%s parece de sesión? %s", (name, expected) => {
    expect(isSessionLikeName(name)).toBe(expected);
  });

  it("si una cookie se repite se queda con la última", () => {
    const cookies = parseCookies(["a=1", "b=2; Secure", "a=3; HttpOnly", "=sin-nombre"]);

    expect(cookies.map((cookie) => cookie.name)).toEqual(["a", "b"]);
    expect(cookies[0].httpOnly).toBe(true);
  });
});

describe("HTML", () => {
  const page = new URL("https://www.ejemplo.com/blog/");

  it("extrae recursos, formularios y CSP en <meta>", () => {
    const facts = extractHtmlFacts(
      `<html><head>
         <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
         <link rel="stylesheet" href="https://cdn.otro.net/a.css" integrity="sha384-x">
         <link rel="icon" href="http://ignorado.example/favicon.ico">
         <script src="/local.js"></script>
         <script>var s = '<img src="http://falso.example/x.png">';</script>
       </head><body>
         <img src=http://img.example/a.png alt="a > b">
         <iframe src='https://video.example/embed'></iframe>
         <form action="/buscar"><input type="text"></form>
         <FORM ACTION="http://www.ejemplo.com/login"><INPUT TYPE="PASSWORD"></FORM>
         <input type="password">
       </body></html>`,
      page,
    );

    expect(facts.metaCsp).toEqual(["default-src 'self'"]);
    expect(facts.resources.map((r) => [r.kind, r.host, r.insecure, r.hasIntegrity])).toEqual([
      ["style", "cdn.otro.net", false, true],
      ["script", "www.ejemplo.com", false, false],
      ["image", "img.example", true, false],
      ["frame", "video.example", false, false],
    ]);
    expect(facts.forms).toEqual([
      { action: "https://www.ejemplo.com/buscar", insecureAction: false, hasPassword: false },
      { action: "http://www.ejemplo.com/login", insecureAction: true, hasPassword: true },
    ]);
    expect(facts.loosePasswordInputs).toBe(1);
  });

  it("resuelve direcciones relativas respetando <base>", () => {
    const facts = extractHtmlFacts(
      '<base href="http://otra.example/dir/"><script src="app.js"></script>',
      page,
    );

    expect(facts.resources[0]).toMatchObject({
      url: "http://otra.example/dir/app.js",
      insecure: true,
    });
  });

  it("ignora direcciones que no son http(s) y HTML roto", () => {
    const facts = extractHtmlFacts(
      '<img src="data:image/png;base64,AAAA"><script src="javascript:void(0)"><img src="',
      page,
    );

    expect(facts.resources).toEqual([]);
  });

  it("aproxima el dominio registrable", () => {
    expect(siteOf("www.ejemplo.com")).toBe("ejemplo.com");
    expect(siteOf("a.b.ejemplo.com")).toBe("ejemplo.com");
    expect(siteOf("tienda.ejemplo.co.uk")).toBe("ejemplo.co.uk");
    expect(siteOf("www.ejemplo.com.es")).toBe("ejemplo.com.es");
    expect(siteOf("ejemplo.es")).toBe("ejemplo.es");
  });
});
