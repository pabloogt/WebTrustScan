import { describe, expect, it } from "vitest";
import { AuditError } from "@/lib/audit/errors";
import { normalizeUrl } from "@/lib/normalizeUrl";

describe("normalizeUrl", () => {
  it("añade https:// cuando falta el esquema", () => {
    expect(normalizeUrl("ejemplo.com")).toBe("https://ejemplo.com/");
    expect(normalizeUrl("  ejemplo.com/ruta?a=1  ")).toBe(
      "https://ejemplo.com/ruta?a=1",
    );
  });

  it("respeta http:// y https:// explícitos", () => {
    expect(normalizeUrl("http://ejemplo.com")).toBe("http://ejemplo.com/");
    expect(normalizeUrl("HTTPS://Ejemplo.com")).toBe("https://ejemplo.com/");
  });

  it.each([
    ["vacía", "   "],
    ["esquema file", "file:///etc/passwd"],
    ["esquema ftp", "ftp://ejemplo.com"],
    ["esquema gopher", "gopher://ejemplo.com"],
    ["javascript", "javascript://alert(1)"],
    ["credenciales", "https://user:pass@ejemplo.com"],
    ["espacios", "no es una url"],
    ["demasiado larga", `ejemplo.com/${"a".repeat(3000)}`],
  ])("rechaza una URL %s", (_name, input) => {
    expect(() => normalizeUrl(input)).toThrow(AuditError);
  });

  it("marca los rechazos como INVALID_URL (HTTP 400)", () => {
    try {
      normalizeUrl("ftp://ejemplo.com");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AuditError);
      expect((error as AuditError).code).toBe("INVALID_URL");
      expect((error as AuditError).httpStatus).toBe(400);
    }
  });
});
