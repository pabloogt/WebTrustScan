import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import type { AuditReport } from "@/lib/engine/types";
import {
  GOOD_HEADERS,
  SIMPLE_PAGE,
  closedPort,
  finding,
  respond,
  scan,
  scanLegacy,
  startSite,
  type LegacyOutcome,
  type Site,
  type SiteSpec,
  type Zone,
} from "./harness";

/**
 * Laboratorio de escenarios. Cada caso levanta un sitio simulado, lo analiza
 * con el motor 1.x (congelado en lib/audit) y con el Engine 2.0, y comprueba
 * el comportamiento esperado del nuevo. Con LAB_REPORT=1 escribe la tabla
 * comparativa en tests/lab/results.json (base de TESTING_REPORT.md).
 */

type Row = {
  id: string;
  title: string;
  legacy: string;
  score: number | null;
  grade: string | null;
  coverage: number;
  confidence: string;
  cap: number | null;
  condition: string;
  open: string[];
  unverified: string[];
};

const rows: Row[] = [];
const sites: Site[] = [];

afterEach(async () => {
  await Promise.all(sites.splice(0).map((site) => site.close()));
});

afterAll(() => {
  if (process.env.LAB_REPORT === "1") {
    fs.writeFileSync(
      path.join(__dirname, "results.json"),
      `${JSON.stringify(rows, null, 2)}\n`,
    );
  }
});

function legacyText(outcome: LegacyOutcome): string {
  return outcome.kind === "score"
    ? String(outcome.score)
    : `error ${outcome.code}`;
}

async function runScenario(
  id: string,
  title: string,
  spec: Omit<SiteSpec, "name">,
  zone?: Zone,
): Promise<{ report: AuditReport; legacy: LegacyOutcome }> {
  const site = await startSite({ name: id, ...spec });
  sites.push(site);

  const legacy = await scanLegacy(site);
  const report = await scan(site, zone);

  rows.push({
    id,
    title,
    legacy: legacyText(legacy),
    score: report.web.score,
    grade: report.web.grade,
    coverage: report.web.coverage,
    confidence: report.web.confidence,
    cap: report.web.cap?.value ?? null,
    condition: report.target.condition,
    open: report.findings
      .filter(
        (entry) =>
          entry.report === "web" &&
          (entry.status === "fail" || entry.status === "warning"),
      )
      .map((entry) => `${entry.id}:${entry.status}`),
    unverified: report.findings
      .filter(
        (entry) =>
          entry.report === "web" &&
          (entry.status === "not_tested" || entry.status === "error"),
      )
      .map((entry) => entry.id),
  });

  return { report, legacy };
}

const status = (report: AuditReport, id: string) => finding(report, id).status;

const legacyScore = (outcome: LegacyOutcome) =>
  outcome.kind === "score" ? outcome.score : null;

describe("laboratorio · sitios bien y mal configurados", () => {
  it("01 · web correctamente configurada → A, cobertura total", async () => {
    const { report } = await runScenario(
      "s01-good",
      "Web correctamente configurada",
      {
        handler: respond({
          ...GOOD_HEADERS,
          "set-cookie": ["session=x; Secure; HttpOnly; SameSite=Lax; Path=/"],
        }),
      },
    );

    expect(report.web.score).toBe(100);
    expect(report.web.grade).toBe("A");
    expect(report.web.coverage).toBe(100);
    expect(report.web.confidence).toBe("high");
    expect(report.web.cap).toBeNull();
    expect(report.target.condition).toBe("ok");
  });

  it("02 · HTTPS correcto sin ninguna cabecera → D, no «aceptable»", async () => {
    const { report } = await runScenario(
      "s02-no-headers",
      "HTTPS con cabeceras deficientes",
      { handler: respond({ "content-type": "text/html" }) },
    );

    expect(status(report, "transport.https")).toBe("pass");
    expect(status(report, "transport.certificate")).toBe("pass");
    expect(status(report, "headers.csp")).toBe("fail");
    expect(status(report, "transport.hsts")).toBe("fail");
    // Referrer-Policy ausente: el navegador ya aplica un valor seguro.
    expect(status(report, "headers.referrer-policy")).toBe("info");
    expect(report.web.grade).toBe("D");
    expect(report.web.coverage).toBe(100);
  });

  it("03 · certificado caducado → informe con tope 30 (antes: error sin informe)", async () => {
    const { report, legacy } = await runScenario(
      "s03-expired",
      "Certificado caducado (resto perfecto)",
      { cert: "expired", handler: respond(GOOD_HEADERS) },
    );

    expect(legacy).toEqual({ kind: "error", code: "TLS_ERROR" });

    const certificate = finding(report, "transport.certificate");
    expect(certificate.status).toBe("fail");
    expect(certificate.severity).toBe("critical");
    expect(certificate.description).toMatch(/caducado/);
    expect(certificate.evidence.some((e) => e.label === "Válido hasta")).toBe(true);
    expect(report.web.score).toBe(30);
    expect(report.web.cap?.checkId).toBe("transport.certificate");
    expect(report.web.rawScore).toBeGreaterThan(80);
  });

  it("03b · certificado de otro dominio y autofirmado → fallo crítico", async () => {
    const wrong = await runScenario("s03b-wronghost", "Certificado de otro dominio", {
      cert: "wronghost",
      handler: respond(GOOD_HEADERS),
    });
    expect(finding(wrong.report, "transport.certificate").description).toMatch(
      /no corresponde a este dominio/,
    );
    expect(wrong.report.web.score).toBe(30);

    const self = await runScenario("s03c-selfsigned", "Certificado autofirmado", {
      cert: "selfsigned",
      handler: respond(GOOD_HEADERS),
    });
    expect(status(self.report, "transport.certificate")).toBe("fail");
    expect(self.report.web.score).toBe(30);
  });

  it("04 · CSP incorrecta: débil, solo Report-Only y sin control de scripts", async () => {
    const weak = await runScenario("s04-csp-weak", "CSP con unsafe-inline y comodín", {
      handler: respond({
        ...GOOD_HEADERS,
        "content-security-policy":
          "default-src *; script-src 'self' 'unsafe-inline' https:; frame-ancestors 'self'",
      }),
    });
    const weakCsp = finding(weak.report, "headers.csp");
    expect(weakCsp.status).toBe("warning");
    expect(weakCsp.credit).toBe(0.5);
    // La misma cabecera protege frente a clickjacking: no hay doble castigo.
    expect(status(weak.report, "headers.clickjacking")).toBe("pass");

    const reportOnly = await runScenario("s04b-csp-ro", "CSP solo en Report-Only", {
      handler: respond({
        ...GOOD_HEADERS,
        "content-security-policy": "",
        "content-security-policy-report-only":
          "default-src 'self'; frame-ancestors 'none'",
      }),
    });
    expect(finding(reportOnly.report, "headers.csp").credit).toBe(0.2);
    expect(status(reportOnly.report, "headers.clickjacking")).toBe("warning");

    const framesOnly = await runScenario(
      "s04c-csp-frames",
      "CSP que solo declara frame-ancestors",
      {
        handler: respond({
          ...GOOD_HEADERS,
          "content-security-policy": "frame-ancestors 'self'",
        }),
      },
    );
    expect(finding(framesOnly.report, "headers.csp").credit).toBe(0.25);
    expect(status(framesOnly.report, "headers.clickjacking")).toBe("pass");
  });

  it("04d · CSP declarada en <meta> (hosting estático) cuenta como CSP", async () => {
    const { report, legacy } = await runScenario(
      "s04d-csp-meta",
      "CSP en etiqueta <meta> (hosting estático)",
      {
        handler: respond(
          { ...GOOD_HEADERS, "content-security-policy": "" },
          SIMPLE_PAGE.replace(
            "<head>",
            "<head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; object-src 'none'\">",
          ),
        ),
      },
    );

    expect(legacy.kind === "score" && legacy.statuses.csp).toBe("fail");
    expect(status(report, "headers.csp")).toBe("pass");
    // frame-ancestors no funciona en <meta>: clickjacking sigue sin cubrir.
    expect(status(report, "headers.clickjacking")).toBe("fail");
  });

  it("05 · HSTS inseguro: max-age=0 y max-age corto", async () => {
    const zero = await runScenario("s05-hsts-zero", "HSTS con max-age=0", {
      handler: respond({ ...GOOD_HEADERS, "strict-transport-security": "max-age=0" }),
    });
    expect(status(zero.report, "transport.hsts")).toBe("fail");
    expect(finding(zero.report, "transport.hsts").description).toMatch(/OLVIDAR/);

    const short = await runScenario("s05b-hsts-short", "HSTS de 1 día", {
      handler: respond({
        ...GOOD_HEADERS,
        "strict-transport-security": "max-age=86400",
      }),
    });
    expect(finding(short.report, "transport.hsts").credit).toBe(0.5);
  });

  it("05c · cabeceras duplicadas por CDN + origen no son un fallo", async () => {
    const { report, legacy } = await runScenario(
      "s05c-duplicated",
      "Cabeceras duplicadas (CDN + origen)",
      {
        handler: respond({
          ...GOOD_HEADERS,
          "content-security-policy": "default-src 'self'",
          "strict-transport-security": ["max-age=31536000", "max-age=31536000"],
          "x-frame-options": ["SAMEORIGIN", "SAMEORIGIN"],
          "x-content-type-options": ["nosniff", "nosniff"],
        }),
      },
    );

    // Anomalía del motor 1.x: daba HSTS por inválido y XFO por no reconocido.
    expect(legacy.kind === "score" && legacy.statuses.hsts).toBe("fail");
    expect(legacy.kind === "score" && legacy.statuses["frame-protection"]).toBe("warn");

    expect(status(report, "transport.hsts")).toBe("pass");
    expect(status(report, "headers.clickjacking")).toBe("pass");
    expect(status(report, "headers.nosniff")).toBe("pass");
    expect(report.web.score).toBe(100);
  });

  it("06 · cookies de sesión mal configuradas", async () => {
    const { report } = await runScenario("s06-cookies", "Cookies mal configuradas", {
      handler: respond({
        ...GOOD_HEADERS,
        "set-cookie": ["PHPSESSID=secreto123; Path=/", "theme=dark; Path=/"],
      }),
    });

    const secure = finding(report, "cookies.secure");
    expect(secure.status).toBe("fail");
    expect(status(report, "cookies.httponly")).toBe("fail");
    expect(status(report, "cookies.samesite")).toBe("warning");
    // La clasificación «de sesión» es heurística: confianza media.
    expect(finding(report, "cookies.httponly").confidence).toBe("medium");
    // El valor de la cookie nunca aparece en el informe.
    expect(JSON.stringify(report)).not.toContain("secreto123");
    expect(report.web.grade).toBe("B");
  });

  it("07 · CORS permisivo con credenciales → fallo; público sin credenciales → correcto", async () => {
    const reflect = await runScenario(
      "s07-cors-reflect",
      "CORS: refleja el origen con credenciales",
      {
        handler: (req, res) => {
          res.writeHead(200, {
            ...GOOD_HEADERS,
            ...(req.headers.origin
              ? {
                  "access-control-allow-origin": req.headers.origin,
                  "access-control-allow-credentials": "true",
                }
              : {}),
          });
          res.end(SIMPLE_PAGE);
        },
      },
    );
    const cors = finding(reflect.report, "cors.policy");
    expect(cors.status).toBe("fail");
    expect(cors.severity).toBe("high");
    expect(cors.description).toMatch(/depende/);
    // Un fallo de severidad alta impide la nota A aunque el resto sea perfecto.
    expect(reflect.report.web.score).toBe(89);
    expect(reflect.report.web.grade).toBe("B");

    const open = await runScenario("s07b-cors-public", "CORS: * sin credenciales", {
      handler: respond({ ...GOOD_HEADERS, "access-control-allow-origin": "*" }),
    });
    expect(status(open.report, "cors.policy")).toBe("pass");
    expect(open.report.web.score).toBe(100);
  });

  it("08 · web estática sin cookies ni formularios no pierde puntos por ello", async () => {
    const { report } = await runScenario(
      "s08-static",
      "Web estática sin cookies ni formularios",
      { handler: respond(GOOD_HEADERS) },
    );

    for (const id of ["cookies.secure", "cookies.httponly", "cookies.samesite"]) {
      expect(status(report, id)).toBe("not_applicable");
    }
    expect(status(report, "content.insecure-forms")).toBe("not_applicable");
    expect(status(report, "content.sri")).toBe("not_applicable");
    expect(report.web.score).toBe(100);
    expect(report.web.coverage).toBe(100);
  });

  it("09 · API que responde 401/403 en JSON no se juzga como una página", async () => {
    const api401 = await runScenario("s09-api-401", "API JSON con 401", {
      handler: respond(
        {
          "content-type": "application/json",
          "www-authenticate": "Bearer",
          "strict-transport-security": "max-age=31536000",
          "x-content-type-options": "nosniff",
        },
        '{"error":"unauthorized"}',
        401,
      ),
    });

    expect(api401.report.target.condition).toBe("auth-required");
    for (const id of [
      "headers.csp",
      "headers.clickjacking",
      "headers.permissions-policy",
      "headers.referrer-policy",
      "content.mixed-content",
    ]) {
      expect(status(api401.report, id)).toBe("not_applicable");
    }
    expect(status(api401.report, "headers.nosniff")).toBe("pass");
    expect(api401.report.web.score).toBe(100);
    // El motor 1.x la puntuaba como una web sin cabeceras.
    expect(legacyScore(api401.legacy)).toBeLessThan(70);

    const api403 = await runScenario("s09b-api-403", "API JSON con 403 sin nosniff", {
      handler: respond({ "content-type": "application/json" }, "{}", 403),
    });
    const nosniff = finding(api403.report, "headers.nosniff");
    expect(nosniff.status).toBe("fail");
    // Página de error de la aplicación: se evalúa, con confianza reducida.
    expect(nosniff.confidence).toBe("medium");
    expect(api403.report.notices.join(" ")).toMatch(/autenticación/);
  });

  it("10 · bloqueo de CDN/WAF → sin puntuación, no una mala nota", async () => {
    const { report, legacy } = await runScenario(
      "s10-cdn-block",
      "CDN/WAF bloquea al analizador (403 challenge)",
      {
        handler: respond(
          {
            "content-type": "text/html",
            server: "cloudflare",
            "cf-ray": "8a1b2c3d4e5f-MAD",
            "cf-mitigated": "challenge",
          },
          "<html><title>Just a moment...</title></html>",
          403,
        ),
      },
    );

    // El motor 1.x puntuaba la página de bloqueo como si fuera el sitio.
    expect(legacyScore(legacy)).toBeLessThan(50);

    expect(report.target.condition).toBe("blocked");
    expect(report.target.edge).toBe("Cloudflare");
    expect(status(report, "headers.csp")).toBe("not_tested");
    expect(status(report, "transport.hsts")).toBe("not_tested");
    expect(status(report, "transport.certificate")).toBe("pass");
    expect(report.web.counts.status.fail).toBe(0);
    expect(report.web.coverage).toBeLessThan(50);
    expect(report.web.score).toBeNull();
    expect(report.web.summary).toMatch(/No es suficiente/);
    expect(report.notices[0]).toMatch(/bloqueado al analizador/);
  });

  it("10b · sitio normal detrás de una CDN → se evalúa y se avisa del intermediario", async () => {
    const { report } = await runScenario("s10b-cdn-ok", "Sitio servido por CDN", {
      handler: respond({
        ...GOOD_HEADERS,
        server: "cloudflare",
        "cf-ray": "8a1b2c3d4e5f-MAD",
      }),
    });

    expect(report.target.edge).toBe("Cloudflare");
    // "server: cloudflare" no revela versiones: no es un hallazgo.
    expect(status(report, "disclosure.banner")).toBe("pass");
    expect(report.web.score).toBe(100);
    expect(report.notices.join(" ")).toMatch(/Cloudflare/);
  });

  it("11 · respuesta 429 → los controles de respuesta quedan sin comprobar", async () => {
    const { report, legacy } = await runScenario("s11-429", "Respuesta 429", {
      handler: respond({ "retry-after": "30" }, "Too Many Requests", 429),
    });

    expect(legacyScore(legacy)).toBeLessThan(50);
    expect(report.target.condition).toBe("rate-limited");
    expect(report.web.counts.status.fail).toBe(0);
    expect(report.web.score).toBeNull();
    expect(status(report, "headers.nosniff")).toBe("not_tested");
  });

  it("12 · redirecciones múltiples: se evalúa el destino y se registra la cadena", async () => {
    const { report } = await runScenario("s12-redirects", "Redirecciones múltiples", {
      handler: (req, res) => {
        const next: Record<string, string> = {
          "/": "/a",
          "/a": "/b",
          "/b": "/inicio",
        };
        const target = next[req.url ?? ""];

        if (target) {
          res.writeHead(302, { location: target });
          res.end();
          return;
        }

        respond(GOOD_HEADERS)(req, res);
      },
    });

    expect(report.target.redirects).toHaveLength(4);
    expect(report.target.url).toMatch(/\/inicio$/);
    expect(report.web.score).toBe(100);
    expect(report.notices.join(" ")).toMatch(/3 redirecciones/);
  });

  it("14 · frame-ancestors sin X-Frame-Options es protección suficiente", async () => {
    const { report } = await runScenario(
      "s14-frame-ancestors",
      "frame-ancestors correcto, sin X-Frame-Options",
      { handler: respond(GOOD_HEADERS) },
    );

    const clickjacking = finding(report, "headers.clickjacking");
    expect(clickjacking.status).toBe("pass");
    expect(clickjacking.description).toMatch(/X-Frame-Options no es necesario/);
  });

  it("15 · errores temporales (503, puerto 80 colgado) no penalizan", async () => {
    const down = await runScenario("s15-503", "Error temporal 503", {
      handler: respond({ "content-type": "text/html" }, "Service Unavailable", 503),
    });
    expect(legacyScore(down.legacy)).toBeLessThan(50);
    expect(down.report.target.condition).toBe("server-error");
    expect(down.report.web.counts.status.fail).toBe(0);
    expect(down.report.web.score).toBeNull();

    const hang = await runScenario(
      "s15b-http-hang",
      "Versión http:// que no responde (timeout)",
      { handler: respond(GOOD_HEADERS), http: "hang" },
    );
    // El motor 1.x restaba la mitad del peso por una comprobación incompleta.
    expect(legacyScore(hang.legacy)).toBeLessThan(100);
    const redirect = finding(hang.report, "transport.http-redirect");
    expect(redirect.status).toBe("not_tested");
    expect(hang.report.web.score).toBe(100);
    expect(hang.report.web.coverage).toBeLessThan(100);
    expect(hang.report.web.provisional).toBe(false);
  });

  it("16 · puerto 80 cerrado es correcto, no «a revisar»", async () => {
    const { report, legacy } = await runScenario(
      "s16-http-closed",
      "Puerto HTTP cerrado (solo HTTPS)",
      { handler: respond(GOOD_HEADERS), http: "closed" },
    );

    expect(legacy.kind === "score" && legacy.statuses["http-redirect"]).toBe("warn");
    expect(status(report, "transport.http-redirect")).toBe("pass");
    expect(report.web.score).toBe(100);
  });

  it("17 · web sin HTTPS → informe con tope 35 y una sola causa raíz", async () => {
    const { report, legacy } = await runScenario("s17-http-only", "Web solo HTTP", {
      cert: false,
      handler: respond({
        ...GOOD_HEADERS,
        "set-cookie": ["session=x; HttpOnly; SameSite=Lax"],
      }),
    });

    // Motor 1.x: 3 castigos (https, hsts, redirección) por la misma causa.
    expect(legacy.kind === "score" && legacy.statuses.hsts).toBe("fail");

    expect(status(report, "transport.https")).toBe("fail");
    for (const id of [
      "transport.certificate",
      "transport.tls-version",
      "transport.legacy-tls",
      "transport.http-redirect",
      "transport.hsts",
      "cookies.secure",
    ]) {
      expect(status(report, id)).toBe("not_applicable");
    }
    expect(report.web.score).toBe(35);
    expect(report.web.grade).toBe("F");
    expect(report.web.cap?.checkId).toBe("transport.https");
    expect(report.web.counts.severity.critical).toBe(1);
  });

  it("17b · https:// no responde pero http:// sí → informe, no error de conexión", async () => {
    const site = await startSite({
      name: "s17b-https-closed",
      cert: false,
      handler: respond(GOOD_HEADERS),
    });
    sites.push(site);

    // Lo que ocurre cuando alguien escribe "midominio.com" y el 443 está cerrado.
    const url = `https://${site.host}:${await closedPort()}/`;
    const legacy = await scanLegacy({ ...site, url });
    const report = await scan({ ...site, url });

    rows.push({
      id: "s17b-https-closed",
      title: "https:// cerrado, http:// disponible",
      legacy: legacy.kind === "score" ? String(legacy.score) : `error ${legacy.code}`,
      score: report.web.score,
      grade: report.web.grade,
      coverage: report.web.coverage,
      confidence: report.web.confidence,
      cap: report.web.cap?.value ?? null,
      condition: report.target.condition,
      open: ["transport.https:fail"],
      unverified: [],
    });

    expect(legacy).toEqual({ kind: "error", code: "UNREACHABLE" });

    const https = finding(report, "transport.https");
    expect(https.status).toBe("fail");
    expect(https.description).toMatch(/no responde/);
    expect(https.evidence.some((e) => e.value.includes("ECONNREFUSED"))).toBe(true);
    expect(report.target.url).toMatch(/^http:/);
    expect(report.web.score).toBe(35);
    expect(report.notices.join(" ")).toMatch(/se ha analizado la versión http/);
  });

  it("18 · contenido mixto y formulario con contraseña enviado por HTTP", async () => {
    const { report } = await runScenario(
      "s18-content",
      "Contenido mixto y formulario inseguro",
      {
        handler: respond(
          GOOD_HEADERS,
          `<!doctype html><html><body><p>${"Texto de relleno. ".repeat(20)}</p>
           <script src="http://cdn.example.org/lib.js"></script>
           <script src="https://cdn.example.org/lib@2.1.0/otra.js"></script>
           <!-- <script src="http://comentado.example/x.js"></script> -->
           <form action="http://s18-content.lab.test/login" method="post">
             <input type="text" name="user"><input type="password" name="pass">
           </form></body></html>`,
        ),
      },
    );

    const mixed = finding(report, "content.mixed-content");
    expect(mixed.status).toBe("fail");
    expect(mixed.evidence).toHaveLength(1); // el script comentado no cuenta

    const forms = finding(report, "content.insecure-forms");
    expect(forms.status).toBe("fail");
    expect(forms.severity).toBe("high");

    const sri = finding(report, "content.sri");
    expect(sri.status).toBe("warning");
    expect(sri.confidence).toBe("medium");
  });

  it("19 · banners con versión → hallazgo leve, nunca «vulnerable»", async () => {
    const { report } = await runScenario("s19-banner", "Versiones de software expuestas", {
      handler: respond({
        ...GOOD_HEADERS,
        server: "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
      }),
    });

    const banner = finding(report, "disclosure.banner");
    expect(banner.status).toBe("fail");
    expect(banner.severity).toBe("low");
    expect(banner.description).toMatch(/No es una vulnerabilidad en sí/);
    expect(report.web.score).toBeGreaterThanOrEqual(97);
  });

  it("20 · servidor que acepta TLS 1.0", async () => {
    const { report } = await runScenario("s20-legacy-tls", "Servidor que acepta TLS 1.0/1.1", {
      tls: { minVersion: "TLSv1", ciphers: "DEFAULT:@SECLEVEL=0" },
      handler: respond(GOOD_HEADERS),
    });

    expect(status(report, "transport.tls-version")).toBe("pass");
    expect(status(report, "transport.legacy-tls")).toBe("fail");
  });
});

describe("laboratorio · problemas DNS y del propio análisis", () => {
  it("13 · dominio inexistente → error claro, sin informe ni puntuación", async () => {
    const site = await startSite({ name: "s13", handler: respond(GOOD_HEADERS) });
    sites.push(site);

    await expect(
      scan({ ...site, url: "https://no-existe.invalid/" }),
    ).rejects.toMatchObject({ code: "UNREACHABLE", reason: "ENOTFOUND" });
  });

  it("13b · el resolvedor DNS falla → ERROR, no fallo del dominio", async () => {
    const site = await startSite({ name: "s13b", handler: respond(GOOD_HEADERS) });
    sites.push(site);

    const report = await scan(site, { failing: true });

    for (const id of ["email.spf", "email.dmarc", "dns.caa"]) {
      expect(status(report, id)).toBe("error");
    }
    expect(report.dnsEmail.score).toBeNull();
    expect(report.dnsEmail.coverage).toBe(0);
    // El informe web no se ve afectado.
    expect(report.web.score).toBe(100);
  });

  it("13c · DNS y correo se puntúan aparte de la seguridad web", async () => {
    const good = await startSite({ name: "s13c", handler: respond(GOOD_HEADERS) });
    sites.push(good);

    const strong = await scan(good, {
      mx: { "lab.test": ["mx.lab.test"] },
      txt: {
        "lab.test": ["v=spf1 include:_spf.lab.test -all", "otra-verificacion=1"],
        "_dmarc.lab.test": ["v=DMARC1; p=reject; rua=mailto:dmarc@lab.test"],
      },
      caa: { "lab.test": ['issue "letsencrypt.org"'] },
    });
    expect(strong.dnsEmail.score).toBe(100);
    expect(strong.web.score).toBe(100);

    const weak = await scan(good, {
      mx: { "lab.test": ["mx.lab.test"] },
      txt: {
        "lab.test": ["v=spf1 +all"],
        "_dmarc.lab.test": ["v=DMARC1; p=none"],
      },
    });
    expect(status(weak, "email.spf")).toBe("fail");
    expect(finding(weak, "email.dmarc").credit).toBe(0.25);
    // CAA ausente es informativo: no puntúa.
    expect(status(weak, "dns.caa")).toBe("info");
    expect(weak.dnsEmail.grade).toBe("F");
    // Un correo mal configurado no baja la nota de seguridad web.
    expect(weak.web.score).toBe(100);
  });
});
