import { AuditError } from "./audit/errors";

const MAX_URL_LENGTH = 2048;
const SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Convierte lo que escribe el usuario en una URL http(s) válida.
 * Añade https:// si falta el esquema y rechaza cualquier otro esquema,
 * credenciales embebidas y entradas que no sean una URL.
 */
export function normalizeUrl(input: string): string {
  const trimmed = input.trim();

  if (!trimmed) {
    throw new AuditError("INVALID_URL", "La URL está vacía.");
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    throw new AuditError("INVALID_URL", "La URL es demasiado larga.");
  }

  const candidate = SCHEME_PATTERN.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let parsed: URL;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new AuditError(
      "INVALID_URL",
      "La URL no parece válida. Prueba algo como ejemplo.com",
    );
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new AuditError(
      "INVALID_URL",
      "Solo se pueden analizar direcciones http:// o https://.",
    );
  }

  if (parsed.username || parsed.password) {
    throw new AuditError(
      "INVALID_URL",
      "La URL no puede incluir usuario ni contraseña.",
    );
  }

  if (!parsed.hostname) {
    throw new AuditError(
      "INVALID_URL",
      "La URL no parece válida. Prueba algo como ejemplo.com",
    );
  }

  return parsed.href;
}
