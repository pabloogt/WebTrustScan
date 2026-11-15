import { afterEach, describe, expect, it } from "vitest";
import { parseCookies } from "@/lib/engine/parse/cookies";
import { decodeEntities } from "@/lib/engine/parse/html";
import { classifyResource } from "@/lib/engine/parse/thirdParty";
import {
  GOOD_HEADERS,
  SIMPLE_PAGE,
  finding,
  respond,
  scan,
  startSite,
  type Site,
} from "../lab/harness";

/**
 * Casos de calibración derivados de dos análisis reales (15-11-2026):
 * www.amazon.es y termlifepicks.com. Reproducen en el laboratorio las
 * respuestas que provocaron falsos positivos o puntuaciones engañosas.
 */

const sites: Site[] = [];
const NOW = new Date("2026-11-15T12:00:00Z");

afterEach(async () => {
  await Promise.all(sites.splice(0).map((site) => site.close()));
});

async function site(spec: Parameters<typeof startSite>[0]) {
  const started = await startSite(spec);
  sites.push(started);
  return started;
}

/** Cabeceras Set-Cookie con la misma forma que las de www.amazon.es. */
const AMAZON_COOKIES = [
  "session-id=262-1234567-7654321; Domain=.amazon.es; Expires=Mon, 15-Nov-2027 16:40:41 GMT; Path=/; Secure",
  "session-id-time=2082787201l; Domain=.amazon.es; Expires=Mon, 15-Nov-2027 16:40:41 GMT; Path=/; Secure",
  "i18n-prefs=EUR; Domain=.amazon.es; Expires=Mon, 15-Nov-2027 16:40:41 GMT; Path=/",
  "lc-acbes=es_ES; Domain=.amazon.es; Expires=Mon, 15-Nov-2027 16:40:41 GMT; Path=/",
  // Borrados de cookies antiguas en otro dominio: no establecen nada.
  "session-id=-; path=/; domain=.www.amazon.es; expires=Sat, 15-Nov-2014 16:40:41 GMT",
  "session-token=-; path=/; domain=.www.amazon.es; expires=Sat, 15-Nov-2014 16:40:41 GMT",
  "at-acbes=-; path=/; domain=.www.amazon.es; expires=Sat, 15-Nov-2014 16:40:41 GMT",
  "sess-at-acbes=-; path=/; domain=.www.amazon.es; expires=Sat, 15-Nov-2014 16:40:41 GMT",
];

describe("calibración · cookies (caso Amazon)", () => {
  it("ignora los borrados de cookie y no mezcla cookies de dominios distintos", () => {
    const cookies = parseCookies(AMAZON_COOKIES, NOW);

    expect(cookies.map((cookie) => cookie.name)).toEqual([
      "session-id",
      "session-id-time",
      "i18n-prefs",
      "lc-acbes",
    ]);
    // Antes: el borrado posterior pisaba la cookie real y parecía sin Secure.
    expect(cookies[0]).toMatchObject({ secure: true, domain: "amazon.es" });
  });

  it("un nombre que suena a sesión no basta: el valor debe parecer un identificador", () => {
    const [id, time] = parseCookies(AMAZON_COOKIES, NOW);

    // "262-1234567-7654321" y "2082787201l" no son identificadores opacos.
    expect(id.sessionLike).toBe(false);
    expect(time.sessionLike).toBe(false);

    const [opaque, known, csrf] = parseCookies(
      [
        "auth_token=eyJhbGciOiJIUzI1NiJ9a8f3c2; Path=/",
        "PHPSESSID=abc; Path=/",
        "csrf_token=9f8e7d6c5b4a39281716a5b4c3d2e1f0; Path=/",
      ],
      NOW,
    );
    expect(opaque.sessionSignal).toBe("hint");
    expect(known.sessionSignal).toBe("known");
    expect(csrf.sessionSignal).toBeNull();
  });

  it("trata Max-Age=0 y el valor vacío como borrados", () => {
    expect(parseCookies(["a=1; Max-Age=0", "b=; Path=/", "c=2; Max-Age=60"], NOW)).toHaveLength(1);
  });

  it("informe: sin falsos «sin Secure» y con la confianza de cada detección", async () => {
    const amazon = await site({
      name: "amazon",
      handler: respond({ ...GOOD_HEADERS, "set-cookie": AMAZON_COOKIES }),
    });
    const report = await scan(amazon, undefined, { now: () => NOW });

    const secure = finding(report, "cookies.secure");
    expect(secure.status).toBe("warning");
    expect(secure.severity).toBe("low");
    // Solo aparecen las dos cookies que de verdad no llevan Secure.
    expect(secure.evidence.map((e) => e.value.split(" ")[0])).toEqual([
      "i18n-prefs",
      "lc-acbes",
    ]);
    expect(finding(report, "cookies.httponly").status).toBe("not_applicable");
    expect(finding(report, "cookies.samesite").status).toBe("pass");
  });

  it("una cookie con nombre sugerente y valor opaco se señala con confianza baja", async () => {
    const shop = await site({
      name: "shop",
      handler: respond({
        ...GOOD_HEADERS,
        "set-cookie": ["user_token=a1b2c3d4e5f6a7b8c9d0e1f2; Path=/; Secure"],
      }),
    });
    const httpOnly = finding(await scan(shop), "cookies.httponly");

    expect(httpOnly.status).toBe("fail");
    expect(httpOnly.confidence).toBe("low");
    expect(httpOnly.description).toMatch(/no puede confirmarlo/);
  });
});

describe("calibración · CSP (caso Amazon)", () => {
  it("una CSP que solo actualiza peticiones no controla scripts, y se explica", async () => {
    const amazon = await site({
      name: "amazon-csp",
      handler: respond({
        ...GOOD_HEADERS,
        "content-security-policy":
          "upgrade-insecure-requests;report-uri https://metrics.example/",
        "content-security-policy-report-only":
          "default-src 'self' https: 'unsafe-inline';report-uri https://metrics.example/",
      }),
    });
    const csp = finding(await scan(amazon), "headers.csp");

    expect(csp.status).toBe("warning");
    expect(csp.severity).toBe("medium");
    expect(csp.credit).toBe(0.25);
    expect(csp.description).toMatch(/"upgrade-insecure-requests", "report-uri"/);
    expect(csp.description).toMatch(/Report-Only/);
  });

  it("la ausencia de CSP es severidad media y no se presenta como vulnerabilidad", async () => {
    const bare = await site({
      name: "bare",
      handler: respond({ "content-type": "text/html" }),
    });
    const csp = finding(await scan(bare), "headers.csp");

    expect(csp.status).toBe("fail");
    expect(csp.severity).toBe("medium");
    expect(csp.description).toMatch(/No es una vulnerabilidad por sí misma/);
  });
});

describe("calibración · SRI", () => {
  it.each([
    ["https://m.media-amazon.com/images/I/11J1WJh9jNL.js", "www.amazon.es", "first-party"],
    ["https://github.githubassets.com/assets/app-0a1b2c3d4e.js", "github.com", "first-party"],
    ["https://static.ejemplo.com/app.js", "www.ejemplo.com", "first-party"],
    ["https://www.googletagmanager.com/gtag/js?id=GT-XXXX", "termlifepicks.com", "dynamic"],
    ["https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js", "termlifepicks.com", "dynamic"],
    ["https://fonts.googleapis.com/css2?family=Inter", "ejemplo.com", "dynamic"],
    ["https://js.stripe.com/v3/", "ejemplo.com", "dynamic"],
    ["https://cdn.otro.net/widget.js", "ejemplo.com", "dynamic"],
    ["https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js", "ejemplo.com", "pinned"],
    ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", "ejemplo.com", "pinned"],
    ["https://code.jquery.com/jquery-3.7.1.min.js", "ejemplo.com", "pinned"],
    ["https://cdn.otro.net/build/app.9f8e7d6c5b.js", "ejemplo.com", "pinned"],
    // Marca demasiado corta para deducir parentesco.
    ["https://cdn.abcd-x.net/a.js", "abc.com", "dynamic"],
  ])("%s en %s → %s", (url, host, expected) => {
    expect(classifyResource(url, host)).toBe(expected);
  });

  it("scripts de analítica y publicidad no se penalizan (caso TermLifePicks)", async () => {
    const blog = await site({
      name: "blog",
      handler: respond(
        GOOD_HEADERS,
        SIMPLE_PAGE.replace(
          "</body>",
          '<script async src="https://www.googletagmanager.com/gtag/js?id=GT-XXXX"></script><script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1&#038;host=ca-host-pub-2"></script></body>',
        ),
      ),
    });
    const report = await scan(blog);
    const sri = finding(report, "content.sri");

    expect(sri.status).toBe("info");
    expect(sri.credit).toBeNull();
    expect(sri.description).toMatch(/SRI no se puede aplicar/);
    // Las URL aparecen como evidencia y con las entidades HTML decodificadas.
    expect(sri.evidence.map((e) => e.value)).toEqual([
      "https://www.googletagmanager.com/gtag/js?id=GT-XXXX",
      "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1&host=ca-host-pub-2",
    ]);
    expect(report.web.score).toBe(100);
  });

  it("una librería con versión fija sin integrity sí se señala, con su URL", async () => {
    const shop = await site({
      name: "pinned",
      handler: respond(
        GOOD_HEADERS,
        SIMPLE_PAGE.replace(
          "</body>",
          '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"></script><script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha384-x" crossorigin="anonymous"></script></body>',
        ),
      ),
    });
    const sri = finding(await scan(shop), "content.sri");

    expect(sri.status).toBe("warning");
    expect(sri.credit).toBe(0.5);
    expect(sri.evidence[0]).toEqual({
      label: "Sin integrity",
      value: "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js",
    });
  });

  it("decodifica entidades HTML sin alterar el resto", () => {
    expect(decodeEntities("a=1&amp;b=2&#038;c=3&#x26;d=4")).toBe("a=1&b=2&c=3&d=4");
    expect(decodeEntities("&desconocida; &#0; 100%")).toBe("&desconocida; &#0; 100%");
  });
});

describe("calibración · correo y DNS", () => {
  const zone = (dmarc: string) => ({
    mx: { "lab.test": ["mx.lab.test"] },
    txt: { "lab.test": ["v=spf1 include:_spf.lab.test ~all"], "_dmarc.lab.test": [dmarc] },
  });

  it("DMARC p=none sin informes vale menos que con informes, y se explica", async () => {
    const target = await site({ name: "mail", handler: respond(GOOD_HEADERS) });

    const silent = finding(await scan(target, zone("v=DMARC1; p=none;")), "email.dmarc");
    expect(silent.credit).toBe(0.25);
    expect(silent.description).toMatch(/no protege ni informa/);

    const monitoring = finding(
      await scan(target, zone("v=DMARC1; p=none; rua=mailto:d@lab.test")),
      "email.dmarc",
    );
    expect(monitoring.credit).toBe(0.4);
    expect(monitoring.description).toMatch(/primera fase normal/);
  });

  it("la ausencia de CAA es informativa y no puntúa", async () => {
    const target = await site({ name: "caa", handler: respond(GOOD_HEADERS) });
    const report = await scan(target, zone("v=DMARC1; p=reject"));
    const caa = finding(report, "dns.caa");

    expect(caa.status).toBe("info");
    expect(caa.weight).toBe(0);
    expect(caa.description).toMatch(/opcional/);
    expect(report.dnsEmail.score).toBe(100);
  });

  it("con un solo control evaluado no se publica una nota de correo", async () => {
    const target = await site({ name: "one", handler: respond(GOOD_HEADERS) });
    // Sin MX ni SPF: SPF es informativo y solo DMARC puntúa.
    const report = await scan(target, {
      txt: { "_dmarc.lab.test": ["v=DMARC1; p=none"] },
    });

    expect(report.dnsEmail.evaluated).toBe(1);
    expect(report.dnsEmail.score).toBeNull();
    expect(report.dnsEmail.withheld).toBe("controls");
    expect(report.dnsEmail.summary).toMatch(/demasiado pocos/);
  });
});

describe("calibración · puntuaciones con pocos controles", () => {
  it("una categoría con uno o dos controles no muestra porcentaje", async () => {
    const target = await site({ name: "cats", handler: respond(GOOD_HEADERS) });
    const { categories } = (await scan(target)).web;
    const by = Object.fromEntries(categories.map((c) => [c.category, c]));

    expect(by.transport).toMatchObject({ score: 100, scored: 6, passed: 6 });
    expect(by.cors).toMatchObject({ score: null, scored: 1, passed: 1 });
    expect(by.disclosure).toMatchObject({ score: null, scored: 1, passed: 1 });
    expect(by.cookies).toMatchObject({ score: null, scored: 0, notApplicable: 3 });
  });

  it("TLS 1.0/1.1 aceptado: severidad baja, evidencia reproducible y sin exagerar", async () => {
    const legacy = await site({
      name: "legacy",
      tls: { minVersion: "TLSv1", ciphers: "DEFAULT:@SECLEVEL=0" },
      handler: respond(GOOD_HEADERS),
    });
    const tls = finding(await scan(legacy), "transport.legacy-tls");

    expect(tls.status).toBe("fail");
    expect(tls.severity).toBe("low");
    expect(tls.confidence).toBe("high");
    expect(tls.description).toMatch(/clientes antiguos/);
    expect(tls.evidence.some((e) => e.value.startsWith("openssl s_client"))).toBe(true);
  });
});
