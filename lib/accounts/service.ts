import { clientKey, enforceLimit, pseudonym } from "../limits";
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  RATE_LIMITS,
  entitlementsFor,
} from "../plans";
import { appBaseUrl } from "./config";
import { AccountError } from "./http";
import type { AccountDeps, AuthResult, SessionUser } from "./ports";

/**
 * Lógica de cuentas. No sabe nada de Supabase: trabaja contra los puertos.
 *
 * Regla de no enumeración: registro y recuperación responden SIEMPRE lo
 * mismo, exista o no la cuenta. El acceso usa un único mensaje para
 * «contraseña incorrecta», «cuenta inexistente» y «correo sin confirmar».
 */

type HeaderReader = { get(name: string): string | null };

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function parseEmail(value: unknown): string {
  const email = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (!EMAIL.test(email) || email.length > 254) {
    throw new AccountError(400, "Introduce una dirección de correo válida.");
  }

  return email;
}

export function parsePassword(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < PASSWORD_MIN_LENGTH ||
    value.length > PASSWORD_MAX_LENGTH
  ) {
    throw new AccountError(
      400,
      `La contraseña debe tener entre ${PASSWORD_MIN_LENGTH} y ${PASSWORD_MAX_LENGTH} caracteres.`,
    );
  }

  return value;
}

const confirmUrl = (next: string) =>
  `${appBaseUrl()}/auth/confirm?next=${encodeURIComponent(next)}`;

/** Convierte un fallo del proveedor en un error para el usuario. */
function assertOk(result: AuthResult, context: "password" | "generic" = "generic"): void {
  if (result.ok) return;

  switch (result.reason) {
    case "weak_password":
      throw new AccountError(400, "Esa contraseña es demasiado débil o aparece en filtraciones conocidas. Elige otra.");
    case "same_password":
      throw new AccountError(400, "La contraseña nueva debe ser distinta de la actual.");
    case "rate_limited":
      throw new AccountError(429, "Demasiados intentos. Espera unos minutos y vuelve a probar.");
    case "reauth_required":
      throw new AccountError(
        401,
        "Por seguridad, esta operación necesita un inicio de sesión reciente. Cierra sesión, vuelve a entrar y repítela.",
      );
    case "invalid_link":
      throw new AccountError(400, "El enlace no es válido o ha caducado. Solicita uno nuevo.");
    case "invalid_credentials":
      throw new AccountError(
        context === "password" ? 400 : 401,
        context === "password" ? "La contraseña actual no es correcta." : "Correo o contraseña incorrectos.",
      );
    default:
      throw new AccountError(503, "El servicio de cuentas no está disponible. Inténtalo más tarde.");
  }
}

const GENERIC_REGISTER =
  "Si la dirección es válida, te hemos enviado un correo con un enlace para confirmar la cuenta.";
const GENERIC_RECOVERY =
  "Si existe una cuenta con esa dirección, te hemos enviado un correo para restablecer la contraseña.";

export async function register(
  deps: AccountDeps,
  headers: HeaderReader,
  body: Record<string, unknown>,
): Promise<{ message: string }> {
  const ip = clientKey(headers);
  await enforceLimit("register", ip, RATE_LIMITS.register);

  const email = parseEmail(body.email);
  const password = parsePassword(body.password);
  const result = await deps.auth.signUp(email, password, confirmUrl("/panel"));

  // Una contraseña débil no revela nada sobre la cuenta: se puede decir.
  if (!result.ok && result.reason === "weak_password") assertOk(result);
  if (!result.ok && result.reason === "unavailable") assertOk(result);

  await deps.quota
    .logSecurityEvent({ userId: null, type: "register_requested", ipHash: ip })
    .catch(() => undefined);

  // Misma respuesta si la cuenta ya existía o si el proveedor limitó el envío.
  return { message: GENERIC_REGISTER };
}

export async function login(
  deps: AccountDeps,
  headers: HeaderReader,
  body: Record<string, unknown>,
): Promise<SessionUser> {
  const ip = clientKey(headers);
  await enforceLimit("login-ip", ip, RATE_LIMITS.loginByIp);

  const invalid = new AccountError(401, "Correo o contraseña incorrectos.");

  if (typeof body.email !== "string" || typeof body.password !== "string") throw invalid;

  const email = body.email.trim().toLowerCase();

  if (!EMAIL.test(email) || body.password.length > PASSWORD_MAX_LENGTH) throw invalid;

  // Límite por cuenta: frena la fuerza bruta distribuida entre muchas IP.
  await enforceLimit("login-email", pseudonym("email", email), RATE_LIMITS.loginByEmail);

  const result = await deps.auth.signIn(email, body.password);

  if (!result.ok) {
    await deps.quota
      .logSecurityEvent({ userId: null, type: "login_failed", ipHash: ip })
      .catch(() => undefined);
    if (result.reason === "invalid_credentials") throw invalid;
    assertOk(result);
  }

  const user = await deps.auth.getUser();

  // Sesión sin correo confirmado: no se admite.
  if (!user) {
    await deps.auth.signOut("local");
    throw invalid;
  }

  return user;
}

export async function requestRecovery(
  deps: AccountDeps,
  headers: HeaderReader,
  body: Record<string, unknown>,
): Promise<{ message: string }> {
  const ip = clientKey(headers);
  await enforceLimit("recovery-ip", ip, RATE_LIMITS.recoveryByIp);

  const email = parseEmail(body.email);
  const perAccount = await enforceLimit(
    "recovery-email",
    pseudonym("email", email),
    RATE_LIMITS.recoveryByEmail,
  ).catch(() => null);

  // Superado el límite por cuenta no se envía nada, pero se responde igual:
  // la respuesta no puede servir para saber si la cuenta existe.
  if (perAccount) {
    await deps.auth.requestPasswordReset(email, confirmUrl("/cuenta/nueva-contrasena"));
    await deps.quota
      .logSecurityEvent({ userId: null, type: "recovery_requested", ipHash: ip })
      .catch(() => undefined);
  }

  return { message: GENERIC_RECOVERY };
}

/** Contraseña nueva. Con `currentPassword` desde ajustes; sin ella tras un enlace de recuperación. */
export async function changePassword(
  deps: AccountDeps,
  user: SessionUser,
  headers: HeaderReader,
  body: Record<string, unknown>,
  options: { requireCurrent: boolean },
): Promise<void> {
  await enforceLimit("account-change", user.id, RATE_LIMITS.accountChanges);

  const password = parsePassword(body.password);

  if (options.requireCurrent) {
    const current = typeof body.currentPassword === "string" ? body.currentPassword : "";

    if (!current || !(await deps.auth.verifyPassword(user.email, current))) {
      throw new AccountError(400, "La contraseña actual no es correcta.");
    }
  }

  assertOk(await deps.auth.updatePassword(password), "password");

  // Quien tuviera una sesión con la contraseña anterior la pierde.
  await deps.auth.signOut("others");
  await deps.quota
    .logSecurityEvent({ userId: user.id, type: "password_changed", ipHash: clientKey(headers) })
    .catch(() => undefined);
}

export async function changeEmail(
  deps: AccountDeps,
  user: SessionUser,
  headers: HeaderReader,
  body: Record<string, unknown>,
): Promise<{ message: string }> {
  await enforceLimit("account-change", user.id, RATE_LIMITS.accountChanges);

  const email = parseEmail(body.email);
  const current = typeof body.currentPassword === "string" ? body.currentPassword : "";

  if (!current || !(await deps.auth.verifyPassword(user.email, current))) {
    throw new AccountError(400, "La contraseña actual no es correcta.");
  }
  if (email === user.email) {
    throw new AccountError(400, "Esa ya es tu dirección de correo.");
  }

  const result = await deps.auth.updateEmail(email, confirmUrl("/panel"));

  if (!result.ok && result.reason !== "rate_limited") assertOk(result);

  await deps.quota
    .logSecurityEvent({ userId: user.id, type: "email_change_requested", ipHash: clientKey(headers) })
    .catch(() => undefined);

  // No se dice si la dirección nueva ya pertenece a otra cuenta.
  return {
    message:
      "Te hemos enviado un correo de confirmación. El cambio no se aplica hasta que lo confirmes.",
  };
}

export async function deleteAccount(
  deps: AccountDeps,
  user: SessionUser,
  headers: HeaderReader,
  body: Record<string, unknown>,
): Promise<void> {
  await enforceLimit("account-change", user.id, RATE_LIMITS.accountChanges);

  const password = typeof body.password === "string" ? body.password : "";

  if (!password || !(await deps.auth.verifyPassword(user.email, password))) {
    throw new AccountError(400, "La contraseña no es correcta.");
  }
  if (body.confirm !== "ELIMINAR") {
    throw new AccountError(400, 'Escribe "ELIMINAR" para confirmar.');
  }

  // Antes de borrar: el consumo del periodo se conserva bajo un HMAC del
  // correo, para que volver a registrarse no reinicie la cuota.
  await deps.quota.recordDeletion(user.id, pseudonym("email", user.email));
  assertOk(await deps.auth.deleteUser(user.id));

  await deps.quota
    .logSecurityEvent({ userId: null, type: "account_deleted", ipHash: clientKey(headers) })
    .catch(() => undefined);
  await deps.auth.signOut("local").catch(() => undefined);
}

export type AccountOverview = {
  user: { email: string; pendingEmail: string | null };
  profile: { displayName: string | null; createdAt: string | null };
  plan: { id: string; label: string; monthlyAudits: number; historySize: number };
  usage: { used: number; remaining: number; periodStart: string; periodEnd: string };
};

export async function overview(deps: AccountDeps, user: SessionUser): Promise<AccountOverview> {
  await enforceLimit("account-read", user.id, RATE_LIMITS.accountReads);

  const [profile, usage] = await Promise.all([
    deps.data.getProfile(user.id),
    deps.quota.usage(user.id, pseudonym("email", user.email)),
  ]);

  if (!usage) {
    throw new AccountError(503, "Tu cuenta todavía se está preparando. Vuelve a intentarlo en un momento.");
  }

  // El plan sale de la base de datos; lo que permite, de la configuración central.
  const plan = entitlementsFor(usage.plan);

  return {
    user: { email: user.email, pendingEmail: user.pendingEmail },
    profile: {
      displayName: profile?.displayName ?? null,
      createdAt: profile?.createdAt ?? null,
    },
    plan: {
      id: plan.plan,
      label: plan.label,
      monthlyAudits: plan.monthlyAudits,
      historySize: plan.historySize,
    },
    usage: {
      used: usage.used,
      remaining: Math.max(0, plan.monthlyAudits - usage.used),
      periodStart: usage.periodStart,
      periodEnd: usage.periodEnd,
    },
  };
}

export async function updateProfile(
  deps: AccountDeps,
  user: SessionUser,
  body: Record<string, unknown>,
): Promise<void> {
  await enforceLimit("account-change", user.id, RATE_LIMITS.accountChanges);

  const raw = typeof body.displayName === "string" ? body.displayName.trim() : "";

  if (raw.length > 80) {
    throw new AccountError(400, "El nombre no puede tener más de 80 caracteres.");
  }
  // Sin caracteres de control: el nombre se mostrará en pantalla e informes.
  if (/[\u0000-\u001f\u007f]/.test(raw)) {
    throw new AccountError(400, "El nombre contiene caracteres no permitidos.");
  }

  await deps.data.updateDisplayName(user.id, raw || null);
}
