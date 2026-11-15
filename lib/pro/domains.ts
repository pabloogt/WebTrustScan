import { randomBytes, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { AuditError } from "../audit/errors";
import { safeFetch } from "../audit/safeRequest";
import { createSystemDnsClient, type DnsClient } from "../engine/dnsClient";
import { normalizeUrl } from "../normalizeUrl";
import type { SessionContext } from "./auth";
import { isUniqueViolation, isUuid, type Db } from "./db";
import { ProError, notFound } from "./errors";
import { PLAN_LIMITS, hasRole } from "./plans";

export type Domain = {
  id: string;
  hostname: string;
  verified: boolean;
  verifiedMethod: string | null;
  createdAt: string;
  /** Instrucciones de verificación (solo se entregan a la organización dueña). */
  verification: { dnsName: string; dnsValue: string; fileUrl: string; token: string };
  latestAudit: {
    id: string;
    webScore: number | null;
    webGrade: string | null;
    createdAt: string;
  } | null;
};

type DomainRow = {
  id: string;
  hostname: string;
  verification_token: string;
  verified_at: Date | string | null;
  verified_method: string | null;
  created_at: Date | string;
  audit_id?: string | null;
  web_score?: number | null;
  web_grade?: string | null;
  audit_created_at?: Date | string | null;
};

const iso = (value: Date | string) => new Date(value).toISOString();

export const VERIFY_DNS_LABEL = "_webtrustscan";
export const VERIFY_PREFIX = "webtrustscan-verify=";
export const VERIFY_FILE_PATH = "/.well-known/webtrustscan-verify.txt";

function toDomain(row: DomainRow): Domain {
  return {
    id: row.id,
    hostname: row.hostname,
    verified: row.verified_at !== null,
    verifiedMethod: row.verified_method,
    createdAt: iso(row.created_at),
    verification: {
      dnsName: `${VERIFY_DNS_LABEL}.${row.hostname}`,
      dnsValue: `${VERIFY_PREFIX}${row.verification_token}`,
      fileUrl: `https://${row.hostname}${VERIFY_FILE_PATH}`,
      token: row.verification_token,
    },
    latestAudit: row.audit_id
      ? {
          id: row.audit_id,
          webScore: row.web_score ?? null,
          webGrade: row.web_grade ?? null,
          createdAt: iso(row.audit_created_at as Date | string),
        }
      : null,
  };
}

/** Convierte lo que escribe el usuario en un nombre de host público. */
export function normalizeHostname(input: unknown): string {
  if (typeof input !== "string") {
    throw new ProError(400, "Indica el dominio que quieres añadir.");
  }

  let hostname: string;

  try {
    hostname = new URL(normalizeUrl(input)).hostname.toLowerCase().replace(/\.$/, "");
  } catch (error) {
    throw new ProError(
      400,
      error instanceof AuditError ? error.message : "El dominio no es válido.",
    );
  }

  const bare = hostname.replace(/^\[|\]$/g, "");

  if (isIP(bare) || !hostname.includes(".") || hostname.length > 253) {
    throw new ProError(
      400,
      "Añade un nombre de dominio (por ejemplo, midominio.com), no una dirección IP.",
    );
  }

  return hostname;
}

const SELECT_WITH_LATEST = `
  select d.*, a.id as audit_id, a.web_score, a.web_grade, a.created_at as audit_created_at
    from domains d
    left join lateral (
      select id, web_score, web_grade, created_at
        from audits
       where domain_id = d.id and organization_id = d.organization_id
       order by created_at desc
       limit 1
    ) a on true`;

export async function listDomains(db: Db, organizationId: string): Promise<Domain[]> {
  const rows = await db.query<DomainRow>(
    `${SELECT_WITH_LATEST} where d.organization_id = $1 order by d.created_at asc`,
    [organizationId],
  );

  return rows.map(toDomain);
}

/** Devuelve el dominio SOLO si pertenece a la organización indicada. */
export async function getDomain(
  db: Db,
  organizationId: string,
  domainId: unknown,
): Promise<Domain> {
  if (!isUuid(domainId)) throw notFound("El dominio");

  const [row] = await db.query<DomainRow>(
    `${SELECT_WITH_LATEST} where d.id = $1 and d.organization_id = $2`,
    [domainId, organizationId],
  );

  if (!row) throw notFound("El dominio");

  return toDomain(row);
}

export async function addDomain(
  db: Db,
  session: SessionContext,
  input: unknown,
): Promise<Domain> {
  if (!hasRole(session.role, "member")) {
    throw new ProError(403, "Tu rol no permite añadir dominios.");
  }

  const hostname = normalizeHostname(input);
  const { id: organizationId, plan } = session.organization;
  const limit = PLAN_LIMITS[plan].domains;
  const id = randomUUID();

  try {
    // El recuento y la inserción van en la misma transacción para que dos
    // peticiones simultáneas no superen el límite del plan.
    await db.transaction(async (tx) => {
      const [{ count }] = await tx.query<{ count: number }>(
        "select count(*)::int as count from domains where organization_id = $1",
        [organizationId],
      );

      if (count >= limit) {
        throw new ProError(
          403,
          `Tu plan permite guardar ${limit} ${limit === 1 ? "dominio" : "dominios"}.`,
        );
      }

      await tx.query(
        "insert into domains (id, organization_id, hostname, verification_token) values ($1, $2, $3, $4)",
        [id, organizationId, hostname, randomBytes(20).toString("hex")],
      );
      await tx.query(
        "insert into activity_log (id, organization_id, user_id, action, target) values ($1, $2, $3, 'domain.add', $4)",
        [randomUUID(), organizationId, session.user.id, hostname],
      );
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new ProError(409, "Ese dominio ya está en tu organización.");
    }
    throw error;
  }

  return getDomain(db, organizationId, id);
}

export async function deleteDomain(
  db: Db,
  session: SessionContext,
  domainId: unknown,
): Promise<void> {
  if (!hasRole(session.role, "admin")) {
    throw new ProError(403, "Tu rol no permite eliminar dominios.");
  }

  const domain = await getDomain(db, session.organization.id, domainId);

  await db.query("delete from domains where id = $1 and organization_id = $2", [
    domain.id,
    session.organization.id,
  ]);
  await db.query(
    "insert into activity_log (id, organization_id, user_id, action, target) values ($1, $2, $3, 'domain.delete', $4)",
    [randomUUID(), session.organization.id, session.user.id, domain.hostname],
  );
}

export type VerificationDeps = {
  dnsClient?: DnsClient;
  /** Descarga el fichero de verificación. Inyectable en tests. */
  fetchFile?: (url: string) => Promise<string | null>;
};

/**
 * Descarga el fichero de verificación por la capa segura: es una URL
 * derivada de un dato del usuario, así que aplica la misma protección SSRF
 * que el analizador. No sigue redirecciones: el fichero debe estar en el
 * propio dominio.
 */
async function fetchVerificationFile(url: string): Promise<string | null> {
  try {
    const response = await safeFetch(url, {
      maxRedirects: 0,
      maxBodyBytes: 1024,
      requestTimeoutMs: 6_000,
    });

    return response.status === 200 ? response.body : null;
  } catch {
    return null;
  }
}

/**
 * Comprueba la propiedad del dominio por registro TXT o por fichero. El
 * token es secreto de la organización: otra organización que añada el mismo
 * dominio recibe un token distinto y no puede verificarlo con el ajeno.
 */
export async function verifyDomain(
  db: Db,
  session: SessionContext,
  domainId: unknown,
  deps: VerificationDeps = {},
): Promise<{ verified: boolean; method: "dns" | "file" | null; domain: Domain }> {
  if (!hasRole(session.role, "member")) {
    throw new ProError(403, "Tu rol no permite verificar dominios.");
  }

  const domain = await getDomain(db, session.organization.id, domainId);
  const expected = domain.verification.dnsValue;
  let method: "dns" | "file" | null = null;

  try {
    const records = await (deps.dnsClient ?? createSystemDnsClient()).resolveTxt(
      domain.verification.dnsName,
    );
    if (records.some((record) => record.trim() === expected)) method = "dns";
  } catch {
    // Un fallo del resolvedor no impide probar el otro método.
  }

  if (!method) {
    const body = await (deps.fetchFile ?? fetchVerificationFile)(
      domain.verification.fileUrl,
    );
    if (body?.split(/\r?\n/).some((line) => line.trim() === expected)) {
      method = "file";
    }
  }

  // Si la prueba ha desaparecido, el dominio deja de estar verificado.
  await db.query(
    `update domains
        set verified_at = case when $3::text is null then null else coalesce(verified_at, now()) end,
            verified_method = $3
      where id = $1 and organization_id = $2`,
    [domain.id, session.organization.id, method],
  );

  if (method && !domain.verified) {
    await db.query(
      "insert into activity_log (id, organization_id, user_id, action, target) values ($1, $2, $3, 'domain.verify', $4)",
      [randomUUID(), session.organization.id, session.user.id, domain.hostname],
    );
  }

  return {
    verified: method !== null,
    method,
    domain: await getDomain(db, session.organization.id, domain.id),
  };
}
