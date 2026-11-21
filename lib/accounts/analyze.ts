import { createHmac, timingSafeEqual } from "node:crypto";
import { AuditError } from "../audit/errors";
import { isPublicAddress } from "../audit/ipGuard";
import { assertAllowedTarget } from "../audit/safeRequest";
import type { AuditReport } from "../engine/types";
import { acquireSlot, checkLimit, clientKey, enforceLimit, pseudonym } from "../limits";
import { normalizeUrl } from "../normalizeUrl";
import { ANONYMOUS, QUOTA_WINDOW_DAYS, RATE_LIMITS, entitlementsFor } from "../plans";
import { AccountError } from "./http";
import type { AccountDeps, SessionUser } from "./ports";

/**
 * Control de consumo alrededor del motor de análisis. El motor es el mismo
 * para todos: los planes cambian CUÁNTO se puede analizar, nunca las
 * protecciones (SSRF, tiempos, tamaños), que viven dentro del motor.
 */

type HeaderReader = { get(name: string): string | null };
type Run = (url: string) => Promise<AuditReport>;

/** Tiempo máximo de un análisis más margen: caducidad de una plaza. */
const SLOT_TTL_SECONDS = 45;

/**
 * Valida la dirección ANTES de consumir nada: una URL mal escrita o un
 * destino claramente no permitido (IP interna, puerto distinto de 80/443)
 * no gasta cuota ni límite diario.
 */
export function validateTarget(rawUrl: string): string {
  const url = normalizeUrl(rawUrl);

  assertAllowedTarget(new URL(url), isPublicAddress, [80, 443]);

  return url;
}

export type QuotaInfo = {
  plan: string;
  used: number;
  limit: number;
  remaining: number;
  /** Días de la ventana móvil. */
  windowDays: number;
  /** Cuándo se libera el uso más antiguo que cuenta (ISO 8601, UTC). */
  nextReleaseAt: string | null;
  auditId: string | null;
};

/** Fecha y hora en UTC para mensajes del servidor: «24/11/2026 18:05 UTC». */
export function formatUtc(iso: string): string {
  const date = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(date.getUTCDate())}/${pad(date.getUTCMonth() + 1)}/${date.getUTCFullYear()} ${pad(
    date.getUTCHours(),
  )}:${pad(date.getUTCMinutes())} UTC`;
}

/** Visitante sin cuenta: límite diario por IP y un análisis a la vez. */
export async function analyzeForVisitor(
  headers: HeaderReader,
  url: string,
  run: Run,
): Promise<{ report: AuditReport }> {
  const key = clientKey(headers);
  const release = await acquireSlot("anon-audit", key, ANONYMOUS.maxConcurrentAudits, SLOT_TTL_SECONDS);

  if (!release) {
    throw new AccountError(429, "Ya tienes un análisis en curso. Espera a que termine.", {
      code: "concurrent",
    });
  }

  try {
    // Se cuenta al aceptar el análisis, termine bien o mal: si no, repetir
    // contra un destino que falla sería gratis.
    const day = await checkLimit("anon-day", key, {
      max: ANONYMOUS.auditsPerDay,
      windowSeconds: 86_400,
    });

    if (!day.allowed) {
      throw new AccountError(
        429,
        `Has alcanzado el límite de ${ANONYMOUS.auditsPerDay} análisis diarios sin cuenta. Vuelve a intentarlo mañana.`,
        { code: "anonymous_limit", retryAfterSeconds: day.retryAfterSeconds },
      );
    }

    return { report: await run(url) };
  } finally {
    await release();
  }
}

/** Usuario con sesión: cuota del plan, reservada de forma atómica. */
export async function analyzeForUser(
  deps: AccountDeps,
  user: SessionUser,
  url: string,
  requestId: string,
  run: Run,
): Promise<{ report: AuditReport; quota: QuotaInfo | null }> {
  await enforceLimit("user-audits", user.id, RATE_LIMITS.auditsByUser);

  const reservation = await deps.quota.reserve(user.id, requestId, pseudonym("email", user.email));

  switch (reservation.outcome) {
    case "quota_exceeded":
      throw new AccountError(
        429,
        `Has usado los ${reservation.limit} análisis de tu plan en los últimos ${QUOTA_WINDOW_DAYS} días.` +
          (reservation.availableAt
            ? ` Tendrás uno disponible de nuevo el ${formatUtc(reservation.availableAt)}.`
            : ""),
        {
          code: "quota_exceeded",
          used: reservation.used,
          limit: reservation.limit,
          windowDays: QUOTA_WINDOW_DAYS,
          availableAt: reservation.availableAt,
        },
      );
    case "too_many_concurrent":
      throw new AccountError(429, "Tienes demasiados análisis en curso. Espera a que termine alguno.", {
        code: "concurrent",
      });
    case "no_workspace":
      throw new AccountError(503, "Tu cuenta todavía se está preparando. Vuelve a intentarlo en un momento.");
    case "duplicate": {
      // Reintento de una petición ya vista: no se ejecuta ni se cobra otra vez.
      if (reservation.status === "completed" && reservation.auditId) {
        const report = await deps.quota.reportOf(reservation.auditId);
        if (report) return { report, quota: null };
      }
      throw new AccountError(
        409,
        reservation.status === "reserved"
          ? "Ese análisis ya está en curso."
          : "Esa petición ya se procesó. Inicia un análisis nuevo.",
        { code: "duplicate" },
      );
    }
    default:
  }

  let report: AuditReport;

  try {
    report = await run(url);
  } catch (error) {
    // El destino no respondió o no era analizable: el trabajo se hizo, cuenta.
    // Cualquier otro error es nuestro: se devuelve el análisis a la cuota.
    await deps.quota
      .finish(reservation.usageId, error instanceof AuditError ? "failed" : "released")
      .catch(() => undefined);
    throw error;
  }

  let auditId: string;

  try {
    auditId = await deps.quota.complete(
      reservation.usageId,
      new URL(report.target.url).hostname,
      report,
      entitlementsFor(reservation.plan).historySize,
    );
  } catch (error) {
    await deps.quota.finish(reservation.usageId, "released").catch(() => undefined);
    throw error;
  }

  return {
    report,
    quota: {
      plan: reservation.plan,
      used: reservation.used,
      limit: reservation.limit,
      remaining: Math.max(0, reservation.limit - reservation.used),
      windowDays: QUOTA_WINDOW_DAYS,
      nextReleaseAt: reservation.nextReleaseAt,
      auditId,
    },
  };
}

/* ---------- pase de recuperación de contraseña ---------- */

const TICKET_SECONDS = 15 * 60;

function sign(userId: string, expires: number): string {
  // Reutiliza la clave de servidor; el prefijo separa este uso de los demás.
  return createHmac("sha256", pseudonym("email", "recovery-ticket-key"))
    .update(`${userId}:${expires}`)
    .digest("hex");
}

/**
 * Pase que acredita que la sesión viene de un enlace de recuperación recién
 * usado. Permite fijar una contraseña nueva sin conocer la anterior durante
 * 15 minutos. Va firmado: quien robe una sesión no puede fabricárselo.
 */
export function createRecoveryTicket(userId: string, now = Date.now()): string {
  const expires = Math.floor(now / 1000) + TICKET_SECONDS;
  return `${expires}.${sign(userId, expires)}`;
}

export function verifyRecoveryTicket(
  ticket: string | undefined,
  userId: string,
  now = Date.now(),
): boolean {
  const [rawExpires, signature] = (ticket ?? "").split(".");
  const expires = Number(rawExpires);

  if (!signature || !Number.isInteger(expires) || expires * 1000 < now) return false;

  const expected = Buffer.from(sign(userId, expires));
  const actual = Buffer.from(signature);

  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export const RECOVERY_COOKIE = "wts_recovery";
export const RECOVERY_COOKIE_SECONDS = TICKET_SECONDS;
