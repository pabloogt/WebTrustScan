import fs from "node:fs";
import { PDFDocument } from "pdf-lib";
import { afterEach, describe, expect, it } from "vitest";
import { buildReportPdf, pdfFileName, toPdfText } from "@/lib/report/pdf";
import {
  GOOD_HEADERS,
  SIMPLE_PAGE,
  respond,
  scan,
  startSite,
  type Site,
} from "../lab/harness";

const sites: Site[] = [];

afterEach(async () => {
  await Promise.all(sites.splice(0).map((site) => site.close()));
});

async function sampleReport() {
  const site = await startSite({
    name: "cliente",
    handler: respond(
      {
        ...GOOD_HEADERS,
        "content-security-policy": "default-src 'self' 'unsafe-inline' https:",
        "strict-transport-security": "max-age=86400",
        server: "nginx/1.18.0",
        "set-cookie": ["PHPSESSID=abc; Path=/", "theme=dark; Secure"],
        // Texto del sitio analizado que acaba en la evidencia del informe.
        "x-powered-by": "PHP/8.1 (café ÿ)",
      },
      SIMPLE_PAGE.replace(
        "</body>",
        `<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/${"x".repeat(300)}.js"></script></body>`,
      ),
    ),
    http: "hang",
  });
  sites.push(site);

  return scan(site, {
    mx: { "lab.test": ["mx.lab.test"] },
    txt: { "lab.test": ["v=spf1 ~all"], "_dmarc.lab.test": ["v=DMARC1; p=none"] },
  });
}

describe("informe PDF", () => {
  it("genera un PDF válido, paginado y con metadatos", async () => {
    const report = await sampleReport();
    const bytes = await buildReportPdf(report);

    expect(Buffer.from(bytes.subarray(0, 5)).toString("latin1")).toBe("%PDF-");

    const doc = await PDFDocument.load(bytes);
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(3);
    expect(doc.getTitle()).toBe("Informe de seguridad · cliente.lab.test");
    expect(doc.getAuthor()).toBe("WebTrustScan");
    expect(bytes.length).toBeGreaterThan(5_000);
    expect(bytes.length).toBeLessThan(400_000);

    if (process.env.PDF_OUT) fs.writeFileSync(process.env.PDF_OUT, bytes);
  });

  it("admite marca blanca", async () => {
    const report = await sampleReport();
    const bytes = await buildReportPdf(report, {
      name: "Agencia Ejemplo",
      tagline: "Informe preparado para su cliente",
    });

    expect((await PDFDocument.load(bytes)).getAuthor()).toBe("Agencia Ejemplo");
  });

  it("no falla con un informe sin puntuación (análisis bloqueado)", async () => {
    const site = await startSite({
      name: "bloqueado",
      handler: respond({ "cf-mitigated": "challenge" }, "Just a moment...", 403),
    });
    sites.push(site);

    const report = await scan(site);
    expect(report.web.score).toBeNull();

    const doc = await PDFDocument.load(await buildReportPdf(report));
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(2);
  });

  it("sustituye los caracteres que la fuente no puede representar", () => {
    expect(toPdfText("Año → 100 % ≥ «bien» – €")).toBe("Año -> 100 % >= «bien» – €");
    expect(toPdfText("emoji \u{1F600} 日本 \u0007 fin\nlínea")).toBe("emoji ? ?? ? fin línea");
  });

  it("el nombre de fichero no incluye caracteres peligrosos", async () => {
    const report = await sampleReport();

    expect(
      pdfFileName({ ...report, target: { ...report.target, host: "a/b\\c..d e" } }),
    ).toMatch(/^webtrustscan-a_b_c\.\.d_e-\d{4}-\d{2}-\d{2}\.pdf$/);
  });
});
