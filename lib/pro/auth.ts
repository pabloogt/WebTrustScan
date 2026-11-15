import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt,
  timingSafeEqual,
} from "node:crypto";
import { isUniqueViolation, type Db } from "./db";
import { ProError } from "./errors";
import type { Plan, Role } from "./plans";

/**
 * Autenticación con correo y contraseña, y sesiones en base de datos.
 *
 * - Contraseñas: scrypt con sal aleatoria por usuario (parámetros OWASP).
 * - Sesiones: token aleatorio de 256 bits; en la base de datos solo se guarda
 *   su SHA-256, así que una fuga de la tabla no permite suplantar a nadie.
 * - No depende de ningún servicio externo.
 */

const SCRYPT = { N: 2 ** 15, r: 8, p: 3, keyLength: 32 };
const SESSION_DAYS = 30;
export const SESSION_MAX_AGE_SECONDS = SESSION_DAYS * 86_400;

export const PASSWORD_MIN_LENGTH = 10;
const PASSWORD_MAX_LENGTH = 200;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function derive(password: string, salt: Buffer, params = SCRYPT): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password.normalize("NFKC"),
      salt,
      params.keyLength,
      { N: params.N, r: params.r, p: params.p, maxmem: 128 * 1024 * 1024 },
      (error, key) => (error ? reject(error) : resolve(key)),
    );
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt);

  return [
    "scrypt",
    SCRYPT.N,
    SCRYPT.r,
    SCRYPT.p,
    salt.toString("base64"),
    key.toString("base64"),
  ].join("$");
}

export async function verifyPassword(
  password: string,
  stored: string,
): Promise<boolean> {
  const [scheme, n, r, p, salt, hash] = stored.split("$");

  if (scheme !== "scrypt" || !salt || !hash) return false;

  const expected = Buffer.from(hash, "base64");
  const actual = await derive(password, Buffer.from(salt, "base64"), {
    N: Number(n),
    r: Number(r),
    p: Number(p),
    keyLength: expected.length,
  });

  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Hash con el que comparar cuando el usuario no existe (tiempo constante). */
let dummyHash: Promise<string> | null = null;

const hashToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");

export function normalizeEmail(value: unknown): string {
  const email = typeof value === "string" ? value.trim().toLowerCase() : "";

  if (!EMAIL.test(email) || email.length > 254) {
    throw new ProError(400, "Introduce una dirección de correo válida.");
  }

  return email;
}

function assertPassword(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < PASSWORD_MIN_LENGTH ||
    value.length > PASSWORD_MAX_LENGTH
  ) {
    throw new ProError(
      400,
      `La contraseña debe tener entre ${PASSWORD_MIN_LENGTH} y ${PASSWORD_MAX_LENGTH} caracteres.`,
    );
  }

  return value;
}

export type SessionContext = {
  user: { id: string; email: string };
  organization: { id: string; name: string; plan: Plan };
  role: Role;
};

/** Crea el usuario, su organización y la pertenencia como propietario. */
export async function registerUser(
  db: Db,
  input: { email: unknown; password: unknown; organizationName?: unknown },
): Promise<{ userId: string; organizationId: string }> {
  const email = normalizeEmail(input.email);
  const passwordHash = await hashPassword(assertPassword(input.password));
  const name =
    typeof input.organizationName === "string" && input.organizationName.trim()
      ? input.organizationName.trim().slice(0, 80)
      : `Organización de ${email.split("@")[0]}`.slice(0, 80);
  const userId = randomUUID();
  const organizationId = randomUUID();

  try {
    await db.transaction(async (tx) => {
      await tx.query(
        "insert into users (id, email, password_hash) values ($1, $2, $3)",
        [userId, email, passwordHash],
      );
      await tx.query("insert into organizations (id, name) values ($1, $2)", [
        organizationId,
        name,
      ]);
      await tx.query(
        "insert into memberships (user_id, organization_id, role) values ($1, $2, 'owner')",
        [userId, organizationId],
      );
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new ProError(409, "Ya existe una cuenta con ese correo.");
    }
    throw error;
  }

  return { userId, organizationId };
}

/**
 * Comprueba las credenciales. Devuelve el id del usuario o null. Tarda lo
 * mismo exista o no el usuario, y el error que se muestra es siempre el
 * mismo, para no revelar qué correos están registrados.
 */
export async function authenticate(
  db: Db,
  emailInput: unknown,
  password: unknown,
): Promise<string | null> {
  if (typeof emailInput !== "string" || typeof password !== "string") return null;
  if (password.length > PASSWORD_MAX_LENGTH) return null;

  const [user] = await db.query<{ id: string; password_hash: string }>(
    "select id, password_hash from users where lower(email) = $1",
    [emailInput.trim().toLowerCase()],
  );

  if (!user) {
    dummyHash ??= hashPassword("contraseña-de-relleno");
    await verifyPassword(password, await dummyHash);
    return null;
  }

  return (await verifyPassword(password, user.password_hash)) ? user.id : null;
}

/** Abre una sesión y devuelve el token (solo se entrega aquí, una vez). */
export async function createSession(
  db: Db,
  userId: string,
  now: Date = new Date(),
): Promise<string> {
  const token = randomBytes(32).toString("base64url");

  await db.query(
    "insert into sessions (token_hash, user_id, expires_at) values ($1, $2, $3)",
    [
      hashToken(token),
      userId,
      new Date(now.getTime() + SESSION_MAX_AGE_SECONDS * 1000).toISOString(),
    ],
  );
  // Limpieza oportunista de sesiones caducadas de este usuario.
  await db.query("delete from sessions where user_id = $1 and expires_at <= $2", [
    userId,
    now.toISOString(),
  ]);

  return token;
}

/** Resuelve un token de sesión a usuario + organización + rol, o null. */
export async function getSession(
  db: Db,
  token: string | undefined | null,
  now: Date = new Date(),
): Promise<SessionContext | null> {
  if (!token || token.length > 200) return null;

  const [row] = await db.query<{
    user_id: string;
    email: string;
    organization_id: string;
    name: string;
    plan: Plan;
    role: Role;
  }>(
    `select u.id as user_id, u.email, o.id as organization_id, o.name, o.plan, m.role
       from sessions s
       join users u on u.id = s.user_id
       join memberships m on m.user_id = u.id
       join organizations o on o.id = m.organization_id
      where s.token_hash = $1 and s.expires_at > $2
      order by m.created_at asc
      limit 1`,
    [hashToken(token), now.toISOString()],
  );

  return row
    ? {
        user: { id: row.user_id, email: row.email },
        organization: { id: row.organization_id, name: row.name, plan: row.plan },
        role: row.role,
      }
    : null;
}

export async function destroySession(db: Db, token: string): Promise<void> {
  await db.query("delete from sessions where token_hash = $1", [hashToken(token)]);
}

/** Cierra todas las sesiones de un usuario (p. ej. al cambiar la contraseña). */
export async function destroyAllSessions(db: Db, userId: string): Promise<void> {
  await db.query("delete from sessions where user_id = $1", [userId]);
}
