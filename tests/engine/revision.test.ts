import { afterEach, describe, expect, it } from "vitest";
import { safeTlsProbe, type TlsProbeResult } from "@/lib/audit/safeRequest";
import { transportChecks } from "@/lib/engine/checks/transport";
import type { ScanContext, TlsVersion } from "@/lib/engine/context";
import {
  COVERAGE_LABEL,
  MAIL_SCOPE_NOTE,
  SCORE_NOTES,
  categoryResult,
} from "@/lib/engine/format";
import { parseCookies } from "@/lib/engine/parse/cookies";
import { classifyResource, sameBrand } from "@/lib/engine/parse/thirdParty";
import {
  GOOD_HEADERS,
  LAB_CA,
  SIMPLE_PAGE,
  closedPort,
  finding,
  labLookup,
  loopbackOnly,
  respond,
  scan,
  startSite,
  type Site,
} from "../lab/harness";

/**
 * Revisión técnica del 15-11-2026 (fase de consolidación): precisión de la
 * evidencia TLS, textos de SPF/DMARC/HSTS/CSP, transparencia de las cifras y
 * revisión de las heurísticas para no cambiar falsos positivos por negativos.
 */

const sites: Site[] = [];
const NOW = new Date("2026-11-15T12:00:00Z");
const LEGACY = { ciphers: "DEFAULT:@SECLEVEL=0" };

afterEach(async () => {
  await Promise.all(sites.splice(0).map((site) => site.close()));
});

async function site(spec: Parameters<typeof startSite>[0]) {
  const started = await startSite(spec);
  sites.push(started);
  return started;
}

const evidenceOf = (report: Awaited<ReturnType<typeof scan>>, id: string) =>
  Object.fromEntries(finding(report, id).evidence.map((e) => [e.label, e.value]));

describe("TLS · una prueba por versión", () => {
  it("servidor actual: 1.0 y 1.1 rechazados de forma explícita, 1.2 y 1.3 aceptados", async () => {
    const modern = await site({ name: "tls-modern", handler: respond(GOOD_HEADERS) });
    const report = await scan(modern);
    const legacy = finding(report, "transport.legacy-tls");
    const evidence = evidenceOf(report, "transport.legacy-tls");

    expect(legacy.status).toBe("pass");
    expect(legacy.confidence).toBe("high");
    expect(legacy.description).toMatch(/responde que no admite esas versiones/);
    expect(evidence["Saludo solo con TLS 1.0"]).toMatch(/^rechazado/);
    expect(evidence["Saludo solo con TLS 1.1"]).toMatch(/^rechazado/);
    expect(evidence["Saludo solo con TLS 1.2"]).toMatch(/^aceptado/);
    expect(evidence["Saludo solo con TLS 1.3"]).toMatch(/^aceptado/);
    expect(evidence["Conexión normal (cliente actual)"]).toMatch(/^negocia TLSv1\.3/);
  });

  it("servidor que acepta 1.0 y 1.1: se muestran ambas y se distingue de lo que negocia un navegador", async () => {
    const old = await site({
      name: "tls-old",
      tls: { minVersion: "TLSv1", ...LEGACY },
      handler: respond(GOOD_HEADERS),
    });
    const report = await scan(old);
    const legacy = finding(report, "transport.legacy-tls");
    const evidence = evidenceOf(report, "transport.legacy-tls");

    expect(legacy.status).toBe("fail");
    expect(legacy.severity).toBe("low");
    expect(legacy.description).toMatch(/acepta conexiones con TLS 1\.0 y TLS 1\.1/);
    expect(legacy.description).toMatch(/navegadores actuales, que con este servidor negocian TLSv1\.3/);
    // Ya no se afirma que el saludo esté «limitado a TLS 1.0–1.1».
    expect(legacy.description).not.toMatch(/limitado a/);
    expect(evidence["Saludo solo con TLS 1.0"]).toMatch(/^aceptado/);
    expect(evidence["Saludo solo con TLS 1.1"]).toMatch(/^aceptado/);
    // Un comando de reproducción por cada versión aceptada.
    expect(evidence["Cómo reproducirlo (TLS 1.0)"]).toMatch(/-tls1 /);
    expect(evidence["Cómo reproducirlo (TLS 1.1)"]).toMatch(/-tls1_1 /);
    // El control de versión negociada es independiente y sigue correcto.
    expect(finding(report, "transport.tls-version").status).toBe("pass");
  });

  it("servidor que acepta 1.1 pero no 1.0: solo se afirma lo demostrado", async () => {
    const partial = await site({
      name: "tls-11",
      tls: { minVersion: "TLSv1.1", ...LEGACY },
      handler: respond(GOOD_HEADERS),
    });
    const legacy = finding(await scan(partial), "transport.legacy-tls");

    expect(legacy.status).toBe("fail");
    expect(legacy.description).toMatch(/acepta conexiones con TLS 1\.1, una versión retirada/);
    expect(legacy.description).toMatch(/TLS 1\.0 no se ha aceptado/);
    expect(legacy.evidence.some((e) => e.label === "Cómo reproducirlo (TLS 1.0)")).toBe(false);
  });

  it("servidor sin TLS 1.3: correcto, con una nota", async () => {
    const tls12 = await site({
      name: "tls-12",
      tls: { maxVersion: "TLSv1.2" },
      handler: respond(GOOD_HEADERS),
    });
    const report = await scan(tls12);
    const version = finding(report, "transport.tls-version");

    expect(version.status).toBe("pass");
    expect(version.description).toMatch(/se establece con TLSv1\.2/);
    expect(version.description).toMatch(/no ofrece TLS 1\.3/);
    expect(evidenceOf(report, "transport.tls-version")["Saludo solo con TLS 1.3"]).toMatch(/^rechazado/);
    expect(report.web.score).toBe(100);
  });

  it("un fallo del cliente o de la red NO se interpreta como rechazo del servidor", async () => {
    const options = { addressPolicy: loopbackOnly, allowedPorts: null, dnsLookup: labLookup, tlsCa: LAB_CA };
    const version = { minVersion: "TLSv1", maxVersion: "TLSv1" } as const;

    // Puerto cerrado: no hay servidor TLS al que preguntar.
    const closed = await safeTlsProbe(`https://x.lab.test:${await closedPort()}`, version, options);
    expect(closed).toEqual({ outcome: "error", reason: "ECONNREFUSED" });

    // Dominio que no resuelve.
    const unresolved = await safeTlsProbe("https://no-existe.invalid", version, { dnsLookup: labLookup });
    expect(unresolved.outcome).toBe("error");

    // Servidor que acepta la conexión y nunca responde al saludo.
    const silent = await site({ name: "tls-silent", cert: false, handler: respond(), http: "hang" });
    const timedOut = await safeTlsProbe(`https://${silent.host}:${silent.httpPort}`, version, {
      ...options,
      requestTimeoutMs: 300,
    });
    expect(timedOut.outcome).toBe("error");

    // Un servicio que no habla TLS (HTTP plano) tampoco es un «rechazo».
    const plain = await site({ name: "tls-plain", cert: false, handler: respond() });
    const notTls = await safeTlsProbe(`https://${plain.host}:${plain.httpPort}`, version, options);
    expect(notTls.outcome).toBe("error");
  });

  it("si una versión antigua no se pudo probar, el control queda «no comprobado»", () => {
    const check = transportChecks.find((entry) => entry.id === "transport.legacy-tls")!;
    const context = (versions: Partial<Record<TlsVersion, TlsProbeResult>>) =>
      ({
        isHttps: true,
        finalUrl: new URL("https://ejemplo.com/"),
        primary: { tls: { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256" } },
        tlsVersions: {
          TLSv1: { outcome: "rejected", reason: "PROTOCOL_VERSION", explicit: true },
          "TLSv1.1": { outcome: "rejected", reason: "PROTOCOL_VERSION", explicit: true },
          "TLSv1.2": { outcome: "accepted", protocol: "TLSv1.2" },
          "TLSv1.3": { outcome: "accepted", protocol: "TLSv1.3" },
          ...versions,
        },
      }) as unknown as ScanContext;

    const untestable = check.run(
      context({ TLSv1: { outcome: "error", reason: "UNSUPPORTED_RUNTIME" } }),
    );
    expect(untestable.status).toBe("not_tested");
    expect(untestable.description).toMatch(/No se ha podido realizar una prueba válida de TLS 1\.0/);

    // Pero si la otra SÍ se aceptó, eso sigue siendo un hallazgo.
    const mixed = check.run(
      context({
        TLSv1: { outcome: "error", reason: "TIMEOUT" },
        "TLSv1.1": { outcome: "accepted", protocol: "TLSv1.1" },
      }),
    );
    expect(mixed.status).toBe("fail");
    expect(mixed.description).toMatch(/TLS 1\.0 no se ha podido comprobar/);

    // Corte sin alerta explícita: coherente con rechazo, confianza media.
    const implicit = check.run(
      context({ TLSv1: { outcome: "rejected", reason: "ECONNRESET", explicit: false } }),
    );
    expect(implicit.status).toBe("pass");
    expect(implicit.confidence).toBe("medium");
    expect(implicit.description).toMatch(/sin indicar el motivo/);
  });
});

describe("SPF y DMARC · textos precisos", () => {
  const zone = (spf: string, dmarc: string) => ({
    mx: { "lab.test": ["mx.lab.test"] },
    txt: { "lab.test": [spf], "_dmarc.lab.test": [dmarc] },
  });
  const mail = async (spf: string, dmarc: string) => {
    const target = await site({ name: "mail", handler: respond(GOOD_HEADERS) });
    return scan(target, zone(spf, dmarc));
  };

  it("~all es softfail y -all es fail: no se describen como equivalentes", async () => {
    const soft = finding(await mail("v=spf1 include:x ~all", "v=DMARC1; p=reject"), "email.spf");
    const hard = finding(await mail("v=spf1 include:x -all", "v=DMARC1; p=reject"), "email.spf");

    expect(soft.status).toBe("pass");
    expect(soft.description).toMatch(/"~all" \(softfail\)/);
    expect(soft.description).toMatch(/pide aceptarlo y tratarlo como sospechoso, no rechazarlo/);
    expect(soft.description).not.toMatch(/\(fail\)/);

    expect(hard.status).toBe("pass");
    expect(hard.description).toMatch(/"-all" \(fail\)/);
    expect(hard.description).toMatch(/pide a los receptores que lo rechacen/);
    expect(hard.description).not.toMatch(/softfail/);
  });

  it("p=none sin rua: no afirma que los mensajes suplantados se entreguen", async () => {
    const dmarc = finding(await mail("v=spf1 ~all", "v=DMARC1; p=none;"), "email.dmarc");

    expect(dmarc.status).toBe("warning");
    expect(dmarc.severity).toBe("low");
    expect(dmarc.credit).toBe(0.25);
    expect(dmarc.description).toMatch(/no pide a los receptores que pongan en cuarentena ni rechacen/);
    expect(dmarc.description).toMatch(/cada receptor sigue aplicando sus propios filtros antispam/);
    expect(dmarc.description).toMatch(/no especifica ninguna dirección a la que enviar los informes agregados/);
    expect(dmarc.description).not.toMatch(/se siguen entregando|se entregan y/);
  });

  it("p=none con rua: fase de supervisión, sin la advertencia de rua", async () => {
    const dmarc = finding(
      await mail("v=spf1 ~all", "v=DMARC1; p=none; rua=mailto:d@lab.test"),
      "email.dmarc",
    );

    expect(dmarc.credit).toBe(0.4);
    expect(dmarc.description).toMatch(/primera fase normal/);
    expect(dmarc.description).not.toMatch(/no especifica ninguna dirección/);
  });

  it("quarantine y reject describen lo que se pide, no lo que ocurrirá", async () => {
    const reject = finding(await mail("v=spf1 -all", "v=DMARC1; p=reject"), "email.dmarc");
    const quarantine = finding(await mail("v=spf1 -all", "v=DMARC1; p=quarantine"), "email.dmarc");

    expect(reject.description).toMatch(/pide a los receptores que rechacen/);
    expect(quarantine.description).toMatch(/pide a los receptores que traten como sospechosos/);
  });

  it("CAA ausente sigue siendo informativo y sin peso", async () => {
    const caa = finding(await mail("v=spf1 -all", "v=DMARC1; p=reject"), "dns.caa");

    expect(caa.status).toBe("info");
    expect(caa.weight).toBe(0);
  });

  it("el alcance limitado del informe de correo está declarado", () => {
    expect(MAIL_SCOPE_NOTE).toMatch(/Evaluación limitada/);
    expect(MAIL_SCOPE_NOTE).toMatch(/No comprueba DKIM/);
    expect(MAIL_SCOPE_NOTE).toMatch(/No es una auditoría completa/);
  });
});

describe("HSTS · recomendación progresiva", () => {
  const hsts = async (value?: string) => {
    const headers: Record<string, string | string[]> = { ...GOOD_HEADERS };
    if (value === undefined) delete headers["strict-transport-security"];
    else headers["strict-transport-security"] = value;

    const target = await site({ name: "hsts", handler: respond(headers) });
    return finding(await scan(target), "transport.hsts");
  };

  it("sin HSTS: no recomienda includeSubDomains ni preload como primer paso", async () => {
    const missing = await hsts();

    expect(missing.status).toBe("fail");
    // La cabecera propuesta para empezar no lleva includeSubDomains.
    expect(missing.remediation).toMatch(/"Strict-Transport-Security: max-age=86400"/);
    expect(missing.remediation).toMatch(/solo después de verificar que todos los subdominios/);
    expect(missing.remediation).toMatch(/dejará de abrir por HTTP cualquier subdominio/);
    expect(missing.remediation).toMatch(/"preload" es todavía más difícil de revertir y no es necesario/);
    expect(missing.remediation).not.toMatch(/max-age=\d+; includeSubDomains/);
  });

  it("HSTS válido sin includeSubDomains es correcto y no se presenta como defecto", async () => {
    const plain = await hsts("max-age=31536000");

    expect(plain.status).toBe("pass");
    expect(plain.remediation).toBeNull();
    expect(plain.description).toMatch(/es opcional y solo conviene añadir si todos los subdominios funcionan por HTTPS/);
  });

  it("max-age corto: recomienda subir la duración, sin includeSubDomains", async () => {
    const short = await hsts("max-age=86400");

    expect(short.status).toBe("warning");
    expect(short.remediation).not.toMatch(/includeSubDomains/);
  });
});

describe("CSP · recomendaciones adaptadas al sitio", () => {
  const WORDPRESS = SIMPLE_PAGE.replace(
    "</body>",
    '<link rel="stylesheet" href="/wp-content/themes/tema/style.css"><script src="/wp-includes/js/jquery/jquery.min.js"></script><script async src="https://www.googletagmanager.com/gtag/js?id=GT-X"></script><script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script></body>',
  );

  it("sin CSP en un WordPress con GTM y AdSense: Report-Only primero y terceros nombrados", async () => {
    const headers = { ...GOOD_HEADERS, "content-security-policy": "" };
    const target = await site({ name: "wp", handler: respond(headers, WORDPRESS) });
    const csp = finding(await scan(target), "headers.csp");

    expect(csp.status).toBe("fail");
    expect(csp.severity).toBe("medium");
    expect(csp.remediation).toMatch(/No apliques una política restrictiva de golpe/);
    expect(csp.remediation).toMatch(/"Content-Security-Policy-Report-Only"/);
    expect(csp.remediation).toMatch(/googletagmanager\.com/);
    expect(csp.remediation).toMatch(/googlesyndication\.com/);
    expect(csp.remediation).toMatch(/parece WordPress/);
    expect(csp.remediation).toMatch(/plugins/);
    // Ya no se propone una política concreta lista para copiar.
    expect(csp.remediation).not.toMatch(/default-src 'self'; object-src/);
  });

  it("sitio sin terceros ni WordPress: recomendación genérica, sin menciones inventadas", async () => {
    const headers = { ...GOOD_HEADERS, "content-security-policy": "" };
    const target = await site({ name: "plain", handler: respond(headers) });
    const csp = finding(await scan(target), "headers.csp");

    expect(csp.remediation).toMatch(/Report-Only/);
    expect(csp.remediation).not.toMatch(/WordPress|se cargan recursos de/);
  });

  it("solo Report-Only: se dice que no hay ninguna CSP aplicada", async () => {
    const target = await site({
      name: "ro",
      handler: respond({
        ...GOOD_HEADERS,
        "content-security-policy": "",
        "content-security-policy-report-only": "default-src 'self'",
      }),
    });
    const csp = finding(await scan(target), "headers.csp");

    expect(csp.status).toBe("warning");
    expect(csp.credit).toBe(0.2);
    expect(csp.description).toMatch(/No hay ninguna CSP aplicada/);
    expect(csp.remediation).toMatch(/Es el primer paso correcto/);
  });

  it("CSP aplicada y Report-Only a la vez: cuenta la aplicada", async () => {
    const target = await site({
      name: "both",
      handler: respond({
        ...GOOD_HEADERS,
        "content-security-policy-report-only": "default-src *",
      }),
    });

    expect(finding(await scan(target), "headers.csp").status).toBe("pass");
  });
});

describe("heurísticas · ni falsos positivos ni falsos negativos", () => {
  it("un identificador solo numérico o solo hexadecimal también cuenta como indicio", () => {
    const [numeric, hex, short] = parseCookies(
      [
        "session-id=262-1234567-7654321; Path=/; Secure",
        "auth=0123456789abcdef0123456789abcdef; Path=/",
        "session-id-time=2082787201l; Path=/",
      ],
      NOW,
    );

    expect(numeric.sessionSignal).toBe("hint");
    expect(hex.sessionSignal).toBe("hint");
    // Un valor corto no puede ser un identificador de sesión.
    expect(short.sessionSignal).toBeNull();
  });

  it("Max-Age tiene prioridad sobre Expires al decidir si es un borrado", () => {
    const past = "Sat, 15-Nov-2014 16:40:41 GMT";
    const names = (headers: string[]) =>
      parseCookies(headers, NOW).map((cookie) => cookie.name);

    // Expires pasado pero Max-Age positivo: la cookie SÍ se establece.
    expect(names([`a=valor; Expires=${past}; Max-Age=3600`])).toEqual(["a"]);
    // Expires futuro pero Max-Age=0: es un borrado.
    expect(names(["b=valor; Expires=Mon, 15-Nov-2027 16:40:41 GMT; Max-Age=0"])).toEqual([]);
    // Max-Age no numérico se ignora y decide Expires.
    expect(names([`c=valor; Max-Age=abc; Expires=${past}`])).toEqual([]);
    // Fecha ilegible: no se asume que sea un borrado.
    expect(names(["d=valor; Expires=no-es-una-fecha"])).toEqual(["d"]);
  });

  it("la marca debe coincidir como palabra, no como subcadena", () => {
    expect(sameBrand("m.media-amazon.com", "www.amazon.es")).toBe(true);
    expect(sameBrand("github.githubassets.com", "github.com")).toBe(true);
    expect(sameBrand("static.ejemplo.net", "ejemplo.com")).toBe(true);
    // Antes «shopify» se daba por propio de «shop.com».
    expect(sameBrand("cdn.shopify.com", "shop.com")).toBe(false);
    expect(sameBrand("cdn.amazonaws.com", "amazon.es")).toBe(false);
    expect(sameBrand("notamazon.com", "amazon.es")).toBe(false);
    expect(classifyResource("https://cdn.shopify.com/s/files/1/app.js", "shop.com")).toBe("unknown");
  });

  it("un tercero sin versión visible no se da por «dinámico»: se dice que no se sabe", async () => {
    const target = await site({
      name: "unknown",
      handler: respond(
        GOOD_HEADERS,
        SIMPLE_PAGE.replace("</body>", '<script src="https://cdn.proveedor.net/widget.js"></script></body>'),
      ),
    });
    const sri = finding(await scan(target), "content.sri");

    expect(sri.status).toBe("info");
    expect(sri.confidence).toBe("medium");
    expect(sri.description).toMatch(/no se puede saber desde fuera si su contenido es fijo/);
    expect(sri.description).not.toMatch(/SRI no se puede aplicar a ese tipo/);
    expect(sri.remediation).toMatch(/URL versionada/);
    expect(sri.evidence[0].label).toMatch(/sin versión visible/);
  });

  it("los recursos tratados como propios por la marca se declaran como indicio", async () => {
    const target = await site({
      name: "marca",
      handler: respond(
        GOOD_HEADERS,
        SIMPLE_PAGE.replace("</body>", '<script src="https://cdn.media-marca.lab-assets.example/app.js"></script><script src="https://x.marca-static.net/a.js"></script></body>'),
      ),
    });
    // El sitio del laboratorio es marca.lab.test: su marca es «lab».
    const sri = finding(await scan(target), "content.sri");

    // «lab» tiene menos de 4 letras: no se deduce parentesco por nombre.
    expect(sri.status).toBe("info");
    expect(sri.description).not.toMatch(/se han tratado como propios/);
  });

  it("un 403 corriente con texto genérico no se toma por un bloqueo de WAF", async () => {
    const target = await site({
      name: "forbidden",
      handler: respond({ "content-type": "text/html" }, "<h1>Request unsuccessful</h1>", 403),
    });
    const report = await scan(target);

    expect(report.target.condition).toBe("auth-required");
    // Se evalúa (con confianza reducida) en lugar de quedar «no comprobado».
    expect(finding(report, "headers.nosniff").status).toBe("fail");
  });
});

describe("transparencia de las cifras", () => {
  it("recuento y puntuación ponderada se muestran como cosas distintas", async () => {
    // Solo Permissions-Policy de las cuatro protecciones del navegador.
    const target = await site({
      name: "pesos",
      handler: respond({
        "content-type": "text/html",
        "permissions-policy": "camera=()",
      }),
    });
    const headers = (await scan(target)).web.categories.find(
      (category) => category.category === "headers",
    )!;

    // 1 de 4 controles (25 %), pero el que pasa pesa 2 de 22: 9/100.
    expect(headers).toMatchObject({ passed: 1, scored: 4, score: 9 });
    expect(categoryResult(headers)).toBe("1 de 4 correctos · puntuación ponderada 9/100");
  });

  it("la puntuación es peso conseguido entre peso evaluado", async () => {
    const target = await site({
      name: "formula",
      handler: respond({ ...GOOD_HEADERS, "x-content-type-options": "" }),
    });
    const report = await scan(target);
    const scored = report.findings.filter(
      (f) => f.report === "web" && f.weight > 0 && ["pass", "warning", "fail"].includes(f.status),
    );
    const total = scored.reduce((sum, f) => sum + f.weight, 0);
    const earned = scored.reduce((sum, f) => sum + f.weight * (f.credit ?? 0), 0);

    expect(report.web.score).toBe(Math.round((earned / total) * 100));
    expect(report.web.evaluated).toBe(scored.length);
    expect(report.web.coverage).toBe(100);
  });

  it("la cobertura se explica como cobertura del catálogo, no como auditoría completa", () => {
    const notes = SCORE_NOTES.join(" ");

    expect(COVERAGE_LABEL).toBe("Cobertura del catálogo aplicable");
    expect(notes).toMatch(/No es el porcentaje de controles superados/);
    expect(notes).toMatch(/no significa que se haya auditado toda la seguridad del dominio/);
    expect(notes).toMatch(/Confianza:/);
    expect(notes).toMatch(/no se pudieron comprobar tampoco restan/);
  });
});
