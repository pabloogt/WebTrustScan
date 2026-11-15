import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import type { Probe } from "./context";

/**
 * Consultas DNS que necesita el motor. Van al resolvedor del sistema, nunca
 * al sitio analizado, así que no abren conexiones hacia el destino.
 * Es inyectable para poder simular zonas DNS en el laboratorio.
 */
export type DnsClient = {
  resolveTxt(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<string[]>;
  resolveCaa(name: string): Promise<string[]>;
};

export type DnsFacts = {
  /** Dominio analizado (host sin "www."). */
  domain: string;
  /** Dominio que se considera emisor de correo (el primero con MX). */
  mailDomain: string;
  mx: Probe<string[]>;
  spf: Probe<string[]>;
  dmarc: Probe<{ name: string; records: string[]; inherited: boolean }>;
  caa: Probe<{ name: string | null; records: string[] }>;
};

/** "No existe" es una respuesta válida (lista vacía), no un error. */
const EMPTY_CODES = new Set(["ENODATA", "ENOTFOUND", "ENONAME", "NXDOMAIN"]);

async function orEmpty<T>(query: Promise<T[]>): Promise<T[]> {
  try {
    return await query;
  } catch (error) {
    if (EMPTY_CODES.has((error as NodeJS.ErrnoException).code ?? "")) return [];
    throw error;
  }
}

export function createSystemDnsClient(timeoutMs = 3_000): DnsClient {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });

  return {
    resolveTxt: async (name) =>
      (await orEmpty(resolver.resolveTxt(name))).map((chunks) => chunks.join("")),
    resolveMx: async (name) =>
      (await orEmpty(resolver.resolveMx(name)))
        // RFC 7505: un MX "." declara que el dominio no acepta correo.
        .filter((record) => record.exchange && record.exchange !== ".")
        .map((record) => record.exchange),
    resolveCaa: async (name) =>
      (await orEmpty(resolver.resolveCaa(name))).map((record) => {
        const entry = record as unknown as Record<string, unknown>;
        const tag = ["issue", "issuewild", "iodef"].find((key) => key in entry);

        return tag ? `${tag} "${String(entry[tag])}"` : JSON.stringify(record);
      }),
  };
}

async function probe<T>(query: () => Promise<T>): Promise<Probe<T>> {
  try {
    return { ok: true, value: await query() };
  } catch (error) {
    return {
      ok: false,
      code: "DNS_ERROR",
      reason: (error as NodeJS.ErrnoException).code ?? "UNKNOWN",
    };
  }
}

/** El dominio y sus padres, hasta quedarse en dos niveles. */
export function domainCandidates(domain: string): string[] {
  const labels = domain.split(".");
  const candidates: string[] = [];

  for (let start = 0; start <= Math.max(0, labels.length - 2); start += 1) {
    candidates.push(labels.slice(start).join("."));
  }

  return candidates.slice(0, 4);
}

export async function collectDnsFacts(
  host: string,
  client: DnsClient,
): Promise<DnsFacts | null> {
  if (isIP(host) || !host.includes(".")) return null;

  const domain = host.toLowerCase().replace(/^www\./, "");
  const candidates = domainCandidates(domain);

  let mailDomain = domain;
  const mx = await probe(async () => {
    for (const candidate of candidates) {
      const records = await client.resolveMx(candidate);

      if (records.length > 0) {
        mailDomain = candidate;
        return records;
      }
    }

    return [];
  });

  const [spf, dmarc, caa] = await Promise.all([
    probe(async () =>
      (await client.resolveTxt(mailDomain)).filter((record) =>
        /^v=spf1(\s|$)/i.test(record.trim()),
      ),
    ),
    probe(async () => {
      for (const candidate of candidates) {
        const name = `_dmarc.${candidate}`;
        const records = (await client.resolveTxt(name)).filter((record) =>
          /^v=DMARC1\s*(;|$)/i.test(record.trim()),
        );

        if (records.length > 0) {
          return { name, records, inherited: candidate !== domain };
        }
      }

      return { name: `_dmarc.${domain}`, records: [], inherited: false };
    }),
    probe(async () => {
      // RFC 8659: si el dominio no tiene CAA se hereda el del padre.
      for (const candidate of candidates) {
        const records = await client.resolveCaa(candidate);
        if (records.length > 0) return { name: candidate, records };
      }

      return { name: null, records: [] };
    }),
  ]);

  return { domain, mailDomain, mx, spf, dmarc, caa };
}
