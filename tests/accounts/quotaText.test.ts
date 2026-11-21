import { describe, expect, it } from "vitest";
import { formatLocalDateTime, releaseText, usageSummary } from "@/components/account/quotaText";
import { formatUtc } from "@/lib/accounts/analyze";

/**
 * Textos de consumo que ve el usuario. El servidor responde en UTC; el
 * panel convierte a la zona horaria del navegador (aquí se fija para que
 * la prueba no dependa de la del equipo).
 */

describe("textos de la cuota semanal", () => {
  it("resume el consumo de la ventana", () => {
    expect(usageSummary(3, 5, 7)).toBe("3 de 5 análisis utilizados en los últimos 7 días");
  });

  it("muestra la liberación en la hora local del usuario, indicando la zona", () => {
    const iso = "2026-11-24T17:05:00.000Z";

    expect(formatLocalDateTime(iso, "Europe/Madrid")).toMatch(/24 de noviembre de 2026.*18:05.*CET/);
    expect(formatLocalDateTime(iso, "America/Mexico_City")).toMatch(/24 de noviembre de 2026.*11:05/);
    expect(formatLocalDateTime(iso, "UTC")).toMatch(/17:05.*UTC/);
    // Cerca de medianoche la fecha local puede ser otra.
    expect(formatLocalDateTime("2026-11-24T23:30:00Z", "Europe/Madrid")).toMatch(/25 de noviembre/);
  });

  it("con usos libres indica cuándo se libera el siguiente; sin ninguno, cuándo vuelve a haberlo", () => {
    expect(
      releaseText({ remaining: 2, nextReleaseAt: "2026-11-24T17:05:00Z", availableAt: null }, "UTC"),
    ).toMatch(/^El próximo uso se libera el 24 de noviembre de 2026.*17:05/);
    expect(
      releaseText(
        { remaining: 0, nextReleaseAt: "2026-11-20T08:00:00Z", availableAt: "2026-11-22T09:00:00Z" },
        "UTC",
      ),
    ).toMatch(/^Podrás hacer otro análisis a partir del 22 de noviembre de 2026.*09:00/);
    expect(releaseText({ remaining: 5, nextReleaseAt: null, availableAt: null })).toBeNull();
  });

  it("los mensajes del servidor llevan la hora en UTC, explícita", () => {
    expect(formatUtc("2026-11-24T17:05:00.000Z")).toBe("24/11/2026 17:05 UTC");
    expect(formatUtc("2026-11-24T23:30:00+01:00")).toBe("24/11/2026 22:30 UTC");
  });
});
