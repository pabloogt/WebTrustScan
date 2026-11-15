import { isIP } from "node:net";

export type ClientIdentity = {
  /** Clave para el limitador. Nunca contiene texto libre del cliente. */
  key: string;
  /** De dónde sale: cabecera de plataforma, proxy propio de confianza o ninguna. */
  source: "vercel" | "trusted-proxy" | "untrusted";
};

/** Clave compartida cuando no hay ninguna IP en la que se pueda confiar. */
export const SHARED_CLIENT_KEY = "anon";

type HeaderReader = { get(name: string): string | null };

type Env = Record<string, string | undefined>;

/**
 * Normaliza una IP para usarla como clave. En IPv6 se agrupa por /64, porque
 * un mismo cliente suele controlar el /64 entero y podría rotar direcciones.
 */
export function normalizeIpKey(candidate: string): string | null {
  let ip = candidate.trim();

  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);

  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) ip = mapped[1];

  const family = isIP(ip);

  if (family === 4) return ip;

  if (family === 6) {
    try {
      const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
      const [head, tail = ""] = canonical.split("::");
      const headGroups = head ? head.split(":") : [];
      const tailGroups = tail ? tail.split(":") : [];
      const missing = 8 - headGroups.length - tailGroups.length;
      const groups = canonical.includes("::")
        ? [...headGroups, ...Array<string>(missing).fill("0"), ...tailGroups]
        : headGroups;

      return `${groups.slice(0, 4).join(":")}::/64`;
    } catch {
      return null;
    }
  }

  return null;
}

function firstValid(value: string | null): string | null {
  if (!value) return null;

  return normalizeIpKey(value.split(",")[0] ?? "");
}

/**
 * Identifica al cliente para el límite de peticiones SIN fiarse de cabeceras
 * que el propio cliente pueda escribir:
 *
 * - En Vercel (`VERCEL=1`) la plataforma sobrescribe las cabeceras de IP, así
 *   que se usan las suyas.
 * - Con proxy propio, `TRUSTED_PROXY_HOPS=N` indica cuántos proxies de
 *   confianza hay delante; se toma la IP que añadió el más externo de ellos
 *   (contando desde la derecha de X-Forwarded-For), nunca la de la izquierda.
 * - En cualquier otro caso no se confía en nada y todos los clientes comparten
 *   una única clave: el límite sigue protegiendo, aunque sea común.
 */
export function getClientIdentity(
  headers: HeaderReader,
  env: Env = process.env,
): ClientIdentity {
  if (env.VERCEL === "1") {
    const ip =
      firstValid(headers.get("x-vercel-forwarded-for")) ??
      firstValid(headers.get("x-real-ip")) ??
      firstValid(headers.get("x-forwarded-for"));

    if (ip) return { key: ip, source: "vercel" };
  }

  const hops = Number.parseInt(env.TRUSTED_PROXY_HOPS ?? "", 10);

  if (Number.isInteger(hops) && hops > 0) {
    const chain = (headers.get("x-forwarded-for") ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    const candidate = chain[chain.length - hops];
    const ip = candidate ? normalizeIpKey(candidate) : null;

    if (ip) return { key: ip, source: "trusted-proxy" };
  }

  return { key: SHARED_CLIENT_KEY, source: "untrusted" };
}
