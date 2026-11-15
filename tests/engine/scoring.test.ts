import { describe, expect, it } from "vitest";
import { CATALOG, getDefinition, type CheckId } from "@/lib/engine/catalog";
import { ALL_CHECKS } from "@/lib/engine/run";
import {
  HIGH_SEVERITY_CAP,
  assertCompleteFindings,
  gradeFor,
  scoreReport,
} from "@/lib/engine/scoring";
import type { CheckStatus, Confidence, Finding } from "@/lib/engine/types";

type Override = {
  status: CheckStatus;
  credit?: number;
  confidence?: Confidence;
  severity?: Finding["severity"];
};

/** Construye un informe web completo: todo PASS salvo lo indicado. */
function findings(overrides: Partial<Record<CheckId, Override>> = {}): Finding[] {
  return CATALOG.map((definition) => {
    const override = overrides[definition.id] ?? { status: "pass" as const };
    const scored = ["pass", "warning", "fail"].includes(override.status);

    return {
      id: definition.id,
      report: definition.report,
      category: definition.category,
      title: definition.title,
      status: override.status,
      severity:
        override.severity ??
        (override.status === "fail" ? definition.severity : "info"),
      confidence: override.confidence ?? "high",
      credit: !scored
        ? null
        : override.status === "pass"
          ? 1
          : override.status === "fail"
            ? 0
            : (override.credit ?? 0.5),
      weight: definition.weight,
      description: `resultado de ${definition.id}`,
      remediation: null,
      evidence: [],
      references: [],
      method: definition.method,
    };
  });
}

const web = (overrides?: Partial<Record<CheckId, Override>>) =>
  scoreReport("web", findings(overrides));

describe("catálogo", () => {
  it("cada check del catálogo tiene exactamente una implementación", () => {
    const implemented = ALL_CHECKS.map((check) => check.id).sort();
    const declared = CATALOG.map((definition) => definition.id).sort();

    expect(implemented).toEqual(declared);
    expect(new Set(implemented).size).toBe(implemented.length);
  });

  it("los checks informativos no pesan y los demás sí", () => {
    for (const definition of CATALOG) {
      expect(definition.weight > 0).toBe(definition.severity !== "info");
    }
  });

  it("detecta resultados que faltan o están duplicados", () => {
    const complete = findings();

    expect(() => assertCompleteFindings(complete)).not.toThrow();
    expect(() => assertCompleteFindings(complete.slice(1))).toThrow(/no ha producido/);
    expect(() => assertCompleteFindings([...complete, complete[0]])).toThrow(/duplicados/);
  });
});

describe("puntuación", () => {
  it("todo correcto → 100, A, cobertura 100 y confianza alta", () => {
    expect(web()).toMatchObject({
      score: 100,
      grade: "A",
      coverage: 100,
      confidence: "high",
      provisional: false,
      cap: null,
    });
  });

  it("NOT_APPLICABLE e INFO ni suman ni restan", () => {
    const result = web({
      "cookies.secure": { status: "not_applicable" },
      "cookies.httponly": { status: "not_applicable" },
      "cookies.samesite": { status: "not_applicable" },
      "content.insecure-forms": { status: "not_applicable" },
      "headers.referrer-policy": { status: "info" },
    });

    expect(result.score).toBe(100);
    expect(result.coverage).toBe(100);
  });

  it("NOT_TESTED y ERROR nunca restan puntos: reducen la cobertura", () => {
    const result = web({
      "transport.http-redirect": { status: "not_tested" },
      "cors.policy": { status: "error" },
    });

    expect(result.score).toBe(100);
    expect(result.counts.status.fail).toBe(0);
    expect(result.coverage).toBeLessThan(100);
    expect(result.coverage).toBeGreaterThan(85);
  });

  it("con cobertura insuficiente no se publica puntuación", () => {
    const untested: Partial<Record<CheckId, Override>> = {};

    for (const definition of CATALOG) {
      if (definition.category !== "transport") {
        untested[definition.id] = { status: "not_tested" };
      }
    }

    const result = web(untested);

    expect(result.coverage).toBeLessThan(50);
    expect(result.score).toBeNull();
    expect(result.grade).toBeNull();
    expect(result.rawScore).toBe(100);
    expect(result.confidence).toBe("low");
  });

  it("cobertura parcial → puntuación provisional", () => {
    const result = web({
      "headers.csp": { status: "not_tested" },
      "transport.hsts": { status: "not_tested" },
    });

    expect(result.score).toBe(100);
    expect(result.provisional).toBe(true);
  });

  it("un WARNING pierde solo la parte no conseguida del peso", () => {
    const failed = web({ "headers.csp": { status: "fail", severity: "medium" } });
    const partial = web({ "headers.csp": { status: "warning", credit: 0.5 } });

    expect(100 - (partial.rawScore as number)).toBeCloseTo(
      (100 - (failed.rawScore as number)) / 2,
      0,
    );
  });

  it("una conclusión con poca confianza penaliza menos", () => {
    const high = web({ "cookies.httponly": { status: "fail", confidence: "high" } });
    const medium = web({ "cookies.httponly": { status: "fail", confidence: "medium" } });
    const low = web({ "cookies.httponly": { status: "fail", confidence: "low" } });

    expect(high.rawScore as number).toBeLessThan(medium.rawScore as number);
    expect(medium.rawScore as number).toBeLessThan(low.rawScore as number);
  });

  it("los fallos críticos limitan la nota aunque el resto sea perfecto", () => {
    const noHttps = web({ "transport.https": { status: "fail" } });
    const badCert = web({ "transport.certificate": { status: "fail" } });
    const both = web({
      "transport.https": { status: "fail" },
      "transport.certificate": { status: "fail" },
    });

    expect(noHttps.score).toBe(getDefinition("transport.https").capOnFail);
    expect(noHttps.grade).toBe("F");
    expect(badCert.score).toBe(getDefinition("transport.certificate").capOnFail);
    // Con varios topes se aplica el más bajo.
    expect(both.cap?.checkId).toBe("transport.certificate");
  });

  it("el tope solo se declara si realmente rebaja la puntuación", () => {
    const overrides: Partial<Record<CheckId, Override>> = {
      "transport.https": { status: "fail" },
    };

    for (const definition of CATALOG) {
      if (definition.report === "web" && definition.id !== "transport.https") {
        overrides[definition.id] = { status: "fail", severity: "low" };
      }
    }

    const result = web(overrides);

    expect(result.score).toBe(0);
    expect(result.cap).toBeNull();
  });

  it("un fallo de severidad alta y confianza alta impide la nota A", () => {
    const confirmed = web({ "cors.policy": { status: "fail" } });
    const doubtful = web({ "cors.policy": { status: "fail", confidence: "medium" } });

    expect(confirmed.score).toBe(HIGH_SEVERITY_CAP);
    expect(confirmed.grade).toBe("B");
    expect(doubtful.grade).toBe("A");
  });

  it("cada informe solo cuenta sus propios hallazgos", () => {
    const all = findings({
      "email.spf": { status: "fail" },
      "email.dmarc": { status: "fail" },
      "dns.caa": { status: "fail" },
    });

    expect(scoreReport("web", all).score).toBe(100);
    expect(scoreReport("dns-email", all).score).toBe(0);
  });

  it("da puntuación por categoría, o null si nada puntúa en ella", () => {
    const result = web({
      "cookies.secure": { status: "not_applicable" },
      "cookies.httponly": { status: "not_applicable" },
      "cookies.samesite": { status: "not_applicable" },
      "headers.csp": { status: "fail", severity: "medium" },
    });
    const byId = Object.fromEntries(
      result.categories.map((category) => [category.category, category.score]),
    );

    expect(byId.cookies).toBeNull();
    expect(byId.transport).toBe(100);
    expect(byId.headers).toBeLessThan(100);
  });

  it("cuenta los hallazgos abiertos por severidad", () => {
    const result = web({
      "transport.https": { status: "fail" },
      "headers.nosniff": { status: "fail" },
      "headers.csp": { status: "warning", severity: "medium" },
    });

    expect(result.counts.severity).toMatchObject({ critical: 1, low: 1, medium: 1 });
  });

  it.each([
    [100, "A"],
    [90, "A"],
    [89, "B"],
    [75, "B"],
    [74, "C"],
    [60, "C"],
    [59, "D"],
    [40, "D"],
    [39, "F"],
    [0, "F"],
  ])("la nota de %i es %s", (score, grade) => {
    expect(gradeFor(score)).toBe(grade);
  });
});
