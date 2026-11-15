import {
  PDFDocument,
  StandardFonts,
  rgb,
  type PDFFont,
  type PDFPage,
  type RGB,
} from "pdf-lib";
import { CATEGORY_LABELS, REPORT_LABELS } from "../engine/catalog";
import {
  COVERAGE_LABEL,
  MAIL_SCOPE_NOTE,
  SCORE_NOTES,
  categoryResult,
  controlCounts,
} from "../engine/format";
import type {
  AuditReport,
  CheckStatus,
  Confidence,
  Finding,
  ReportId,
  ReportScore,
  Severity,
} from "../engine/types";

/**
 * Genera el informe en PDF. Funciona igual en el navegador (descarga
 * directa, sin enviar el informe a ningún servidor) y en Node (para
 * informes programados más adelante).
 */

export type PdfBrand = {
  /** Nombre que aparece en la cabecera y el pie. */
  name: string;
  /** Línea bajo el nombre (p. ej. el nombre de la agencia). */
  tagline?: string;
};

const DEFAULT_BRAND: PdfBrand = { name: "WebTrustScan" };

const PAGE = { width: 595.28, height: 841.89 };
const MARGIN = 48;
const CONTENT_WIDTH = PAGE.width - MARGIN * 2;
const FOOTER_SPACE = 40;

const hex = (value: string): RGB => {
  const n = parseInt(value.slice(1), 16);
  return rgb(((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255);
};

const COLOR = {
  ink: hex("#0f172a"),
  text: hex("#1e293b"),
  muted: hex("#64748b"),
  line: hex("#e2e8f0"),
  panel: hex("#f8fafc"),
  navy: hex("#0b1220"),
  white: hex("#ffffff"),
  accent: hex("#38bdf8"),
};

const GRADE_COLOR: Record<string, RGB> = {
  A: hex("#059669"),
  B: hex("#65a30d"),
  C: hex("#d97706"),
  D: hex("#ea580c"),
  F: hex("#dc2626"),
};

const SEVERITY_COLOR: Record<Severity, RGB> = {
  critical: hex("#b91c1c"),
  high: hex("#c2410c"),
  medium: hex("#b45309"),
  low: hex("#475569"),
  info: hex("#475569"),
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Informativa",
};

const STATUS_LABEL: Record<CheckStatus, string> = {
  pass: "Correcto",
  fail: "Fallo",
  warning: "Mejorable",
  info: "Informativo",
  not_applicable: "No aplica",
  not_tested: "No comprobado",
  error: "Error del análisis",
};

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "alta",
  medium: "media (indicio)",
  low: "baja (indicio débil)",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Caracteres de Windows-1252 fuera de Latin-1 que la fuente sí tiene. */
const CP1252_EXTRA = "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ";

/**
 * Las fuentes estándar de PDF solo cubren Windows-1252. El texto procede en
 * parte del sitio analizado, así que cualquier otro carácter se sustituye.
 */
export function toPdfText(value: string): string {
  let out = "";

  for (const char of value
    .replace(/→/g, "->")
    .replace(/≥/g, ">=")
    .replace(/≤/g, "<=")
    .replace(/[\r\n\t]+/g, " ")) {
    const code = char.codePointAt(0) ?? 0;

    if ((code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff)) {
      out += char;
    } else if (CP1252_EXTRA.includes(char)) {
      out += char;
    } else {
      out += "?";
    }
  }

  return out;
}

type Fonts = { regular: PDFFont; bold: PDFFont; mono: PDFFont };

type TextOptions = {
  font?: PDFFont;
  size?: number;
  color?: RGB;
  indent?: number;
  width?: number;
  lineGap?: number;
  /** No partir el párrafo entre dos páginas (si cabe en una). */
  together?: boolean;
};

class Writer {
  page!: PDFPage;
  y = 0;

  constructor(
    private readonly doc: PDFDocument,
    readonly fonts: Fonts,
  ) {
    this.newPage();
  }

  newPage(): void {
    this.page = this.doc.addPage([PAGE.width, PAGE.height]);
    this.y = PAGE.height - MARGIN;
  }

  /** Salta de página si no caben `height` puntos. */
  ensure(height: number): void {
    if (this.y - height < MARGIN + FOOTER_SPACE) this.newPage();
  }

  space(height: number): void {
    this.y -= height;
  }

  /** Parte un texto en líneas que caben en `width`. */
  wrap(text: string, font: PDFFont, size: number, width: number): string[] {
    const lines: string[] = [];
    let line = "";

    const fits = (candidate: string) =>
      font.widthOfTextAtSize(candidate, size) <= width;

    for (const word of toPdfText(text).split(" ")) {
      if (!word) continue;

      const candidate = line ? `${line} ${word}` : word;

      if (fits(candidate)) {
        line = candidate;
        continue;
      }

      if (line) lines.push(line);
      line = word;

      // Una URL o un token más largo que la línea se corta por caracteres.
      while (!fits(line)) {
        let cut = line.length - 1;
        while (cut > 1 && !fits(line.slice(0, cut))) cut -= 1;
        lines.push(line.slice(0, cut));
        line = line.slice(cut);
      }
    }

    if (line) lines.push(line);

    return lines;
  }

  text(value: string, options: TextOptions = {}): void {
    const font = options.font ?? this.fonts.regular;
    const size = options.size ?? 10;
    const indent = options.indent ?? 0;
    const width = options.width ?? CONTENT_WIDTH - indent;
    const leading = size + (options.lineGap ?? 4);

    const lines = this.wrap(value, font, size, width);

    if (options.together && lines.length * leading < 400) {
      this.ensure(lines.length * leading);
    }

    for (const line of lines) {
      this.ensure(leading);
      this.y -= leading;
      this.page.drawText(line, {
        x: MARGIN + indent,
        y: this.y + (options.lineGap ?? 4) / 2,
        size,
        font,
        color: options.color ?? COLOR.text,
      });
    }
  }

  rule(): void {
    this.ensure(10);
    this.y -= 6;
    this.page.drawLine({
      start: { x: MARGIN, y: this.y },
      end: { x: PAGE.width - MARGIN, y: this.y },
      thickness: 0.7,
      color: COLOR.line,
    });
    this.y -= 6;
  }

  heading(value: string): void {
    // Un título nunca se queda solo al pie: reserva sitio para su contenido.
    this.ensure(120);
    this.y -= 14;
    this.text(value, { font: this.fonts.bold, size: 14, color: COLOR.ink });
    this.rule();
  }
}

function drawLogo(page: PDFPage, x: number, y: number, scale: number): void {
  // Escudo con marca de verificación.
  page.drawSvgPath(
    "M12 1.5 L21 5 V11.5 C21 17 17 21 12 23 C7 21 3 17 3 11.5 V5 Z",
    { x, y, scale, color: COLOR.accent },
  );
  page.drawSvgPath("M7.5 12 L10.8 15.3 L16.8 8.6", {
    x,
    y,
    scale,
    borderColor: COLOR.navy,
    borderWidth: 2.2,
  });
}

function cover(writer: Writer, report: AuditReport, brand: PdfBrand): void {
  const { page, fonts } = writer;
  const bandHeight = 150;

  page.drawRectangle({
    x: 0,
    y: PAGE.height - bandHeight,
    width: PAGE.width,
    height: bandHeight,
    color: COLOR.navy,
  });

  drawLogo(page, MARGIN, PAGE.height - 34, 1.25);
  page.drawText(toPdfText(brand.name), {
    x: MARGIN + 38,
    y: PAGE.height - 56,
    size: 17,
    font: fonts.bold,
    color: COLOR.white,
  });
  if (brand.tagline) {
    page.drawText(toPdfText(brand.tagline), {
      x: MARGIN + 38,
      y: PAGE.height - 70,
      size: 9,
      font: fonts.regular,
      color: hex("#94a3b8"),
    });
  }

  const label = "INFORME DE CONFIGURACIÓN DE SEGURIDAD";
  page.drawText(label, {
    x: PAGE.width - MARGIN - fonts.regular.widthOfTextAtSize(label, 8),
    y: PAGE.height - 52,
    size: 8,
    font: fonts.regular,
    color: hex("#94a3b8"),
  });

  const host = toPdfText(report.target.host);
  const hostSize = fonts.bold.widthOfTextAtSize(host, 24) > CONTENT_WIDTH ? 15 : 24;
  page.drawText(host, {
    x: MARGIN,
    y: PAGE.height - 112,
    size: hostSize,
    font: fonts.bold,
    color: COLOR.white,
  });

  const date = new Date(report.scannedAt).toLocaleString("es-ES", {
    dateStyle: "long",
    timeStyle: "short",
    timeZone: "Europe/Madrid",
  });
  page.drawText(toPdfText(`Análisis del ${date} (hora peninsular)`), {
    x: MARGIN,
    y: PAGE.height - 132,
    size: 9.5,
    font: fonts.regular,
    color: hex("#cbd5e1"),
  });

  writer.y = PAGE.height - bandHeight - 14;
}

function scoreCard(
  writer: Writer,
  title: string,
  score: ReportScore,
  x: number,
  width: number,
  top: number,
): void {
  const { page, fonts } = writer;
  const height = 118;

  page.drawRectangle({
    x,
    y: top - height,
    width,
    height,
    color: COLOR.panel,
    borderColor: COLOR.line,
    borderWidth: 0.8,
  });

  page.drawText(toPdfText(title.toUpperCase()), {
    x: x + 14,
    y: top - 20,
    size: 8,
    font: fonts.bold,
    color: COLOR.muted,
  });

  const color = score.grade ? GRADE_COLOR[score.grade] : COLOR.muted;

  if (score.score !== null && score.grade) {
    const value = String(score.score);
    page.drawText(value, {
      x: x + 14,
      y: top - 62,
      size: 36,
      font: fonts.bold,
      color,
    });
    page.drawText("/ 100", {
      x: x + 18 + fonts.bold.widthOfTextAtSize(value, 36),
      y: top - 62,
      size: 11,
      font: fonts.regular,
      color: COLOR.muted,
    });
    page.drawText(
      toPdfText(`Nota ${score.grade}${score.provisional ? " (provisional)" : ""}`),
      { x: x + 14, y: top - 80, size: 11, font: fonts.bold, color },
    );
  } else {
    page.drawText("Sin puntuación", {
      x: x + 14,
      y: top - 56,
      size: 18,
      font: fonts.bold,
      color: COLOR.muted,
    });
    page.drawText(
      toPdfText(
        score.withheld === "controls"
          ? "Demasiado pocos controles evaluados"
          : "Cobertura insuficiente",
      ),
      { x: x + 14, y: top - 76, size: 9, font: fonts.regular, color: COLOR.muted },
    );
  }

  const facts = [
    `${COVERAGE_LABEL}: ${score.coverage}% · Confianza ${CONFIDENCE_LABEL[score.confidence].split(" ")[0]}`,
    controlCounts(score),
  ];

  facts.forEach((fact, index) => {
    page.drawText(toPdfText(fact), {
      x: x + 14,
      y: top - 97 - index * 11,
      size: 7.5,
      font: fonts.regular,
      color: COLOR.text,
    });
  });
}

function categoryTable(writer: Writer, report: AuditReport): void {
  const { fonts } = writer;
  const rows = [...report.web.categories, ...report.dnsEmail.categories];

  writer.heading("Resultado por categoría");

  for (const row of rows) {
    writer.ensure(16);
    writer.y -= 15;

    const result = categoryResult(row);

    writer.page.drawText(toPdfText(row.label), {
      x: MARGIN,
      y: writer.y,
      size: 9.5,
      font: fonts.regular,
      color: COLOR.text,
    });
    writer.page.drawText(toPdfText(result), {
      x: MARGIN + 250,
      y: writer.y,
      size: 9.5,
      font: fonts.bold,
      color: row.scored > 0 && row.passed < row.scored ? hex("#b45309") : COLOR.text,
    });
  }

  writer.space(4);
  writer.text(
    "La puntuación ponderada solo se da en las categorías con tres o más controles evaluados. No es el porcentaje de controles correctos: depende del peso de cada control.",
    { size: 8, color: COLOR.muted },
  );

  writer.heading("Cómo leer estas cifras");
  for (const note of SCORE_NOTES) {
    writer.text(`• ${note}`, { size: 8.5, color: COLOR.text, together: true });
    writer.space(2);
  }
}

function findingBlock(writer: Writer, finding: Finding, detailed: boolean): void {
  const { fonts } = writer;
  const open = finding.status === "fail" || finding.status === "warning";

  writer.ensure(detailed ? 70 : 34);
  writer.space(6);
  writer.text(finding.title, { font: fonts.bold, size: 11, color: COLOR.ink });

  const meta = [
    STATUS_LABEL[finding.status],
    open ? `Severidad ${SEVERITY_LABEL[finding.severity].toLowerCase()}` : null,
    open || finding.confidence !== "high"
      ? `Confianza ${CONFIDENCE_LABEL[finding.confidence]}`
      : null,
    CATEGORY_LABELS[finding.category],
  ]
    .filter(Boolean)
    .join("  ·  ");

  writer.text(meta, {
    size: 8.5,
    font: fonts.bold,
    color: open ? SEVERITY_COLOR[finding.severity] : COLOR.muted,
  });
  writer.space(2);
  writer.text(finding.description, { size: 9.5 });

  if (finding.remediation) {
    writer.space(3);
    writer.text(open ? "Cómo solucionarlo" : "Recomendación", {
      size: 8,
      font: fonts.bold,
      color: COLOR.muted,
    });
    writer.text(finding.remediation, { size: 9.5 });
  }

  if (detailed && finding.evidence.length > 0) {
    writer.space(3);
    writer.text("Evidencia", { size: 8, font: fonts.bold, color: COLOR.muted });

    for (const item of finding.evidence.slice(0, 8)) {
      // La etiqueta y su valor no se separan en un salto de página.
      const valueLines = writer.wrap(
        item.value.slice(0, 600),
        fonts.mono,
        8,
        CONTENT_WIDTH - 16,
      ).length;
      writer.ensure(12 + Math.min(valueLines, 12) * 11);
      writer.text(`${item.label}:`, { size: 8, color: COLOR.muted, indent: 8 });
      writer.text(item.value.slice(0, 600), {
        size: 8,
        font: fonts.mono,
        indent: 16,
        lineGap: 3,
      });
    }
  }

  writer.space(4);
  writer.rule();
}

function compactList(writer: Writer, findings: Finding[]): void {
  for (const finding of findings) {
    // Título y descripción de un control no se separan entre páginas.
    writer.ensure(
      18 + writer.wrap(finding.description, writer.fonts.regular, 8.5, CONTENT_WIDTH).length * 12.5,
    );
    writer.text(`${finding.title}  —  ${STATUS_LABEL[finding.status]}`, {
      size: 9.5,
      font: writer.fonts.bold,
      color: COLOR.ink,
    });
    writer.text(finding.description, { size: 8.5, color: COLOR.muted });

    // En controles informativos o no comprobados la evidencia aporta el
    // detalle (p. ej. las URL de los scripts de terceros).
    if (finding.status !== "pass" && finding.status !== "not_applicable") {
      for (const item of finding.evidence
        .filter((entry) => entry.value !== "(no enviada)")
        .slice(0, 4)) {
        writer.text(`${item.label}: ${item.value.slice(0, 300)}`, {
          size: 7.5,
          font: writer.fonts.mono,
          indent: 10,
          lineGap: 3,
          color: COLOR.muted,
        });
      }
    }

    writer.space(3);
  }
}

function reportSection(writer: Writer, report: AuditReport, id: ReportId): void {
  const own = report.findings.filter((finding) => finding.report === id);
  const score = id === "web" ? report.web : report.dnsEmail;
  const open = own
    .filter((f) => f.status === "fail" || f.status === "warning")
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        b.weight - a.weight,
    );
  const unverified = own.filter(
    (f) => f.status === "not_tested" || f.status === "error",
  );
  const passed = own.filter((f) => f.status === "pass");
  const neutral = own.filter(
    (f) => f.status === "info" || f.status === "not_applicable",
  );

  writer.heading(`${REPORT_LABELS[id]} · hallazgos (${open.length})`);

  if (id === "dns-email") {
    writer.text(MAIL_SCOPE_NOTE, {
      size: 9,
      font: writer.fonts.bold,
      color: hex("#92400e"),
    });
    writer.space(4);
  }
  writer.text(score.summary, { size: 9.5, color: COLOR.muted });
  writer.space(4);

  if (open.length === 0) {
    writer.text("No se ha detectado ningún problema en los controles evaluados.", {
      size: 10,
    });
  }
  for (const finding of open) findingBlock(writer, finding, true);

  if (unverified.length > 0) {
    writer.heading(`${REPORT_LABELS[id]} · no se pudo comprobar (${unverified.length})`);
    writer.text(
      "Estos controles no restan puntos: reducen la cobertura. No indican un problema de la web.",
      { size: 8.5, color: COLOR.muted },
    );
    writer.space(4);
    compactList(writer, unverified);
  }

  if (passed.length > 0) {
    writer.heading(`${REPORT_LABELS[id]} · controles correctos (${passed.length})`);
    compactList(writer, passed);
  }

  if (neutral.length > 0) {
    writer.heading(`${REPORT_LABELS[id]} · no aplica o informativo (${neutral.length})`);
    writer.text("No afectan a la puntuación.", { size: 8.5, color: COLOR.muted });
    writer.space(4);
    compactList(writer, neutral);
  }
}

export async function buildReportPdf(
  report: AuditReport,
  brand: PdfBrand = DEFAULT_BRAND,
): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const fonts: Fonts = {
    regular: await doc.embedFont(StandardFonts.Helvetica),
    bold: await doc.embedFont(StandardFonts.HelveticaBold),
    mono: await doc.embedFont(StandardFonts.Courier),
  };

  doc.setTitle(toPdfText(`Informe de seguridad · ${report.target.host}`));
  doc.setAuthor(toPdfText(brand.name));
  doc.setSubject("Auditoría externa de configuración de seguridad web");
  doc.setCreator(`WebTrustScan Engine ${report.engineVersion}`);
  doc.setCreationDate(new Date(report.scannedAt));

  const writer = new Writer(doc, fonts);

  cover(writer, report, brand);

  // Tarjetas de puntuación, una por informe.
  const gap = 14;
  const cardWidth = (CONTENT_WIDTH - gap) / 2;
  const top = writer.y;
  scoreCard(writer, REPORT_LABELS.web, report.web, MARGIN, cardWidth, top);
  scoreCard(
    writer,
    REPORT_LABELS["dns-email"],
    report.dnsEmail,
    MARGIN + cardWidth + gap,
    cardWidth,
    top,
  );
  writer.y = top - 118 - 12;

  writer.text(`URL analizada: ${report.target.url}`, { size: 9 });
  writer.text(
    `Respuesta: HTTP ${report.target.httpStatus}${report.target.edge ? ` · servida a través de ${report.target.edge}` : ""} · Motor ${report.engineVersion}`,
    { size: 9, color: COLOR.muted },
  );

  if (report.notices.length > 0) {
    writer.space(8);
    writer.text("Avisos sobre este análisis", {
      size: 9,
      font: fonts.bold,
      color: COLOR.ink,
    });
    for (const notice of report.notices) {
      writer.text(`• ${notice}`, { size: 9, indent: 6 });
    }
  }

  categoryTable(writer, report);
  reportSection(writer, report, "web");
  reportSection(writer, report, "dns-email");

  writer.heading("Alcance y límites");
  writer.text(
    "Este informe evalúa la configuración de seguridad observable desde fuera, sin autenticarse y con un máximo de cinco peticiones inocuas más un saludo TLS por versión de protocolo. No es una prueba de intrusión ni una certificación: no analiza el código, la lógica de la aplicación, las zonas con inicio de sesión ni el contenido que la web genera con JavaScript. Una puntuación alta indica una buena configuración en los controles comprobados, no la ausencia de vulnerabilidades. Una cobertura del 100 % significa que se han evaluado todos los controles aplicables de este catálogo, no que se haya auditado toda la seguridad del dominio. Los hallazgos con confianza media o baja son indicios que conviene verificar.",
    { size: 9, color: COLOR.muted },
  );

  // Pie de página, cuando ya se conoce el total.
  const pages = doc.getPages();
  pages.forEach((page, index) => {
    const left = toPdfText(`${brand.name} · ${report.target.host}`);
    const right = `Página ${index + 1} de ${pages.length}`;

    page.drawLine({
      start: { x: MARGIN, y: MARGIN + 14 },
      end: { x: PAGE.width - MARGIN, y: MARGIN + 14 },
      thickness: 0.6,
      color: COLOR.line,
    });
    page.drawText(left, {
      x: MARGIN,
      y: MARGIN,
      size: 8,
      font: fonts.regular,
      color: COLOR.muted,
    });
    page.drawText(right, {
      x: PAGE.width - MARGIN - fonts.regular.widthOfTextAtSize(right, 8),
      y: MARGIN,
      size: 8,
      font: fonts.regular,
      color: COLOR.muted,
    });
  });

  return doc.save();
}

export function pdfFileName(report: AuditReport): string {
  const host = report.target.host.replace(/[^a-z0-9.-]/gi, "_");
  return `webtrustscan-${host}-${report.scannedAt.slice(0, 10)}.pdf`;
}
