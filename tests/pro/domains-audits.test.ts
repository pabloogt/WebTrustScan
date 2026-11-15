import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { runAudit } from "@/lib/engine/run";
import type { AuditReport } from "@/lib/engine/types";
import {
  compareAudits,
  getAudit,
  listAudits,
  runDomainAudit,
} from "@/lib/pro/audits";
import { compareReports } from "@/lib/pro/compare";
import type { Db } from "@/lib/pro/db";
import {
  addDomain,
  deleteDomain,
  getDomain,
  listDomains,
  normalizeHostname,
  verifyDomain,
} from "@/lib/pro/domains";
import {
  GOOD_HEADERS,
  labOptions,
  respond,
  startSite,
  zoneClient,
  type Site,
} from "../lab/harness";
import { createAccount, createTestDb, type Account } from "./helpers";

let db: Db;
let free: Account;
let pro: Account;
let viewer: Account;
const sites: Site[] = [];

beforeAll(async () => {
  db = await createTestDb();
  free = await createAccount(db, "free@ejemplo.com");
  pro = await createAccount(db, "pro@ejemplo.com", { plan: "pro" });
  viewer = await createAccount(db, "lector@ejemplo.com", { role: "viewer" });
});

afterAll(() => db.close());

afterEach(async () => {
  await Promise.all(sites.splice(0).map((site) => site.close()));
});

/** Sitio de laboratorio + función que lo audita, para inyectar en el servicio. */
async function labSite(name: string, headers = GOOD_HEADERS) {
  const site = await startSite({ name, handler: respond(headers) });
  sites.push(site);

  return {
    site,
    run: (): Promise<AuditReport> => runAudit(site.url, labOptions(site)),
  };
}

describe("dominios", () => {
  it.each([
    ["Ejemplo.COM", "ejemplo.com"],
    ["https://www.ejemplo.com/ruta?x=1", "www.ejemplo.com"],
    ["  tienda.ejemplo.es.  ", "tienda.ejemplo.es"],
  ])("normaliza %s → %s", (input, expected) => {
    expect(normalizeHostname(input)).toBe(expected);
  });

  it.each(["127.0.0.1", "http://[::1]/", "localhost", "", "ftp://x.com", 42, "a b.com"])(
    "rechaza %s",
    (input) => {
      expect(() => normalizeHostname(input)).toThrow();
    },
  );

  it("añade un dominio con un token de verificación propio y secreto", async () => {
    const domain = await addDomain(db, pro.session, "ejemplo.com");

    expect(domain).toMatchObject({
      hostname: "ejemplo.com",
      verified: false,
      latestAudit: null,
      verification: {
        dnsName: "_webtrustscan.ejemplo.com",
        fileUrl: "https://ejemplo.com/.well-known/webtrustscan-verify.txt",
      },
    });
    expect(domain.verification.token).toMatch(/^[0-9a-f]{40}$/);
    expect(await listDomains(db, pro.session.organization.id)).toHaveLength(1);
  });

  it("no admite el mismo dominio dos veces en una organización", async () => {
    await expect(addDomain(db, pro.session, "EJEMPLO.com")).rejects.toMatchObject({
      status: 409,
    });
  });

  it("aplica el límite de dominios del plan, también con peticiones simultáneas", async () => {
    await addDomain(db, free.session, "uno.com");

    await expect(addDomain(db, free.session, "dos.com")).rejects.toMatchObject({
      status: 403,
      message: expect.stringMatching(/1 dominio/),
    });

    const results = await Promise.allSettled(
      ["a.com", "b.com", "c.com"].map((host) => addDomain(db, free.session, host)),
    );
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    expect(await listDomains(db, free.session.organization.id)).toHaveLength(1);
  });

  it("un rol de solo lectura no puede añadir, verificar, auditar ni borrar", async () => {
    const [{ id }] = await db.query<{ id: string }>(
      "insert into domains (id, organization_id, hostname, verification_token) values (gen_random_uuid(), $1, 'lectura.com', 'tok') returning id",
      [viewer.session.organization.id],
    );

    await expect(addDomain(db, viewer.session, "otro.com")).rejects.toMatchObject({ status: 403 });
    await expect(verifyDomain(db, viewer.session, id)).rejects.toMatchObject({ status: 403 });
    await expect(runDomainAudit(db, viewer.session, id)).rejects.toMatchObject({ status: 403 });
    await expect(deleteDomain(db, viewer.session, id)).rejects.toMatchObject({ status: 403 });
    // Leer sí puede.
    expect((await getDomain(db, viewer.session.organization.id, id)).hostname).toBe("lectura.com");
  });
});

describe("verificación de propiedad", () => {
  const txt = (name: string, value: string) => zoneClient({ txt: { [name]: [value] } });
  const noFile = async () => null;

  it("verifica por registro TXT con el token exacto", async () => {
    const domain = await addDomain(db, pro.session, "verificado-dns.com");
    const wrong = await verifyDomain(db, pro.session, domain.id, {
      dnsClient: txt(domain.verification.dnsName, "webtrustscan-verify=otro-token"),
      fetchFile: noFile,
    });
    expect(wrong).toMatchObject({ verified: false, method: null });

    const ok = await verifyDomain(db, pro.session, domain.id, {
      dnsClient: txt(domain.verification.dnsName, domain.verification.dnsValue),
      fetchFile: noFile,
    });
    expect(ok).toMatchObject({ verified: true, method: "dns" });
    expect(ok.domain.verified).toBe(true);
  });

  it("verifica por fichero y, si la prueba desaparece, retira la verificación", async () => {
    const domain = await addDomain(db, pro.session, "verificado-fichero.com");
    const requested: string[] = [];
    const ok = await verifyDomain(db, pro.session, domain.id, {
      dnsClient: zoneClient({ failing: true }),
      fetchFile: async (url) => {
        requested.push(url);
        return `# verificación\n${domain.verification.dnsValue}\n`;
      },
    });

    expect(ok).toMatchObject({ verified: true, method: "file" });
    expect(requested).toEqual([domain.verification.fileUrl]);

    const gone = await verifyDomain(db, pro.session, domain.id, {
      dnsClient: zoneClient(),
      fetchFile: noFile,
    });
    expect(gone.verified).toBe(false);
    expect(gone.domain.verified).toBe(false);
  });

  it("el token de otra organización no sirve para verificar el mismo dominio", async () => {
    const mine = await addDomain(db, pro.session, "disputado.com");
    const agency = await createAccount(db, "agencia@ejemplo.com", { plan: "agency" });
    const theirs = await addDomain(db, agency.session, "disputado.com");

    expect(theirs.verification.token).not.toBe(mine.verification.token);

    // El dueño real publica SU token: la otra organización no queda verificada.
    const dns = txt(mine.verification.dnsName, mine.verification.dnsValue);

    expect((await verifyDomain(db, pro.session, mine.id, { dnsClient: dns, fetchFile: noFile })).verified).toBe(true);
    expect((await verifyDomain(db, agency.session, theirs.id, { dnsClient: dns, fetchFile: noFile })).verified).toBe(false);
  });

  it("la descarga real del fichero pasa por la capa SSRF", async () => {
    // Sin inyectar `fetchFile`: un dominio que no resuelve (o que resolviera
    // a una IP interna) simplemente no se verifica, sin lanzar.
    const domain = await addDomain(db, pro.session, "no-existe.invalid");
    const result = await verifyDomain(db, pro.session, domain.id, {
      dnsClient: zoneClient(),
    });

    expect(result.verified).toBe(false);
  });
});

describe("auditorías guardadas, historial y comparación", () => {
  it("guarda el informe completo y lo devuelve en el historial", async () => {
    const { run } = await labSite("historial");
    const domain = await addDomain(db, pro.session, "historial.com");
    const { summary, report } = await runDomainAudit(db, pro.session, domain.id, { run });

    // El único hallazgo abierto es del informe de correo (sin DMARC en la zona de prueba).
    expect(summary).toMatchObject({ webScore: 100, webGrade: "A", webCoverage: 100, openFindings: 1 });

    const stored = await getAudit(db, pro.session.organization.id, summary.id);
    expect(stored.report).toEqual(JSON.parse(JSON.stringify(report)));

    const history = await listAudits(db, pro.session.organization.id, domain.id);
    expect(history.map((item) => item.id)).toEqual([summary.id]);

    const listed = await getDomain(db, pro.session.organization.id, domain.id);
    expect(listed.latestAudit).toMatchObject({ id: summary.id, webScore: 100 });
  });

  it("conserva solo las N más recientes según el plan", async () => {
    const { run } = await labSite("retencion");
    const account = await createAccount(db, "retencion@ejemplo.com");
    const domain = await addDomain(db, account.session, "retencion.com");
    await db.query("update organizations set plan = 'pro' where id = $1", [account.session.organization.id]);
    const session = { ...account.session, organization: { ...account.session.organization, plan: "free" as const } };
    const ids: string[] = [];

    // El plan Free conserva 5; se lanzan 7 en horas distintas.
    for (let i = 0; i < 7; i += 1) {
      const now = () => new Date(Date.UTC(2026, 0, 1 + i));
      ids.push((await runDomainAudit(db, session, domain.id, { run, now })).summary.id);
    }

    const history = await listAudits(db, session.organization.id, domain.id);
    expect(history.map((item) => item.id)).toEqual(ids.slice(2).reverse());
  });

  it("limita las auditorías por hora de la organización", async () => {
    const { run } = await labSite("cuota");
    const account = await createAccount(db, "cuota@ejemplo.com");
    const domain = await addDomain(db, account.session, "cuota.com");
    const now = () => new Date("2026-03-01T10:00:00Z");

    for (let i = 0; i < 5; i += 1) {
      await runDomainAudit(db, account.session, domain.id, { run, now });
    }

    await expect(
      runDomainAudit(db, account.session, domain.id, { run, now }),
    ).rejects.toMatchObject({ status: 429 });
    // Pasada la hora vuelve a estar permitido.
    await runDomainAudit(db, account.session, domain.id, {
      run,
      now: () => new Date("2026-03-01T11:00:01Z"),
    });
  });

  it("si el análisis no puede completarse no se guarda nada", async () => {
    const domain = await addDomain(db, pro.session, "caido.invalid");

    await expect(
      runDomainAudit(db, pro.session, domain.id, {
        run: () => runAudit("https://caido.invalid"),
      }),
    ).rejects.toMatchObject({ status: 409 });
    expect(await listAudits(db, pro.session.organization.id, domain.id)).toEqual([]);
  });

  it("compara dos auditorías y distingue regresión, resuelto y no comprobado", async () => {
    const good = await labSite("cmp-bien");
    const bad = await labSite("cmp-mal", {
      ...GOOD_HEADERS,
      "strict-transport-security": "max-age=0",
      "x-content-type-options": "",
    });
    const domain = await addDomain(db, pro.session, "comparar.com");
    const first = await runDomainAudit(db, pro.session, domain.id, {
      run: good.run,
      now: () => new Date("2026-04-01T00:00:00Z"),
    });
    const second = await runDomainAudit(db, pro.session, domain.id, {
      run: bad.run,
      now: () => new Date("2026-04-02T00:00:00Z"),
    });
    const org = pro.session.organization.id;

    const worse = await compareAudits(db, org, first.summary.id, second.summary.id);
    expect(worse.regressions.map((change) => change.id).sort()).toEqual([
      "headers.nosniff",
      "transport.hsts",
    ]);
    expect(worse.resolved).toEqual([]);
    expect(worse.webScoreDelta).toBeLessThan(0);
    expect(worse.engineChanged).toBe(false);

    // El orden de los argumentos no cambia el sentido: siempre antigua → nueva.
    expect(await compareAudits(db, org, second.summary.id, first.summary.id)).toEqual(worse);

    // Sentido contrario construido a mano: los fallos pasan a resueltos.
    const better = compareReports(second.report, first.report);
    expect(better.resolved.map((change) => change.id).sort()).toEqual([
      "headers.nosniff",
      "transport.hsts",
    ]);
    expect(better.regressions).toEqual([]);
  });

  it("un control que pasa a «no comprobado» no cuenta como regresión", async () => {
    const { run } = await labSite("cmp-bloqueo");
    const report = await run();
    const blocked: AuditReport = {
      ...report,
      findings: report.findings.map((finding) =>
        finding.id === "headers.csp"
          ? { ...finding, status: "not_tested" as const, credit: null }
          : finding,
      ),
    };
    const comparison = compareReports(report, blocked);

    expect(comparison.regressions).toEqual([]);
    expect(comparison.unverified.map((change) => change.id)).toEqual(["headers.csp"]);
  });

  it("no compara auditorías de dominios distintos", async () => {
    const { run } = await labSite("cmp-otro");
    const a = await addDomain(db, pro.session, "dominio-a.com");
    const b = await addDomain(db, pro.session, "dominio-b.com");
    const first = await runDomainAudit(db, pro.session, a.id, { run });
    const second = await runDomainAudit(db, pro.session, b.id, { run });

    await expect(
      compareAudits(db, pro.session.organization.id, first.summary.id, second.summary.id),
    ).rejects.toMatchObject({ status: 400 });
  });

  it("al borrar un dominio se borran sus auditorías", async () => {
    const { run } = await labSite("borrado");
    const { session } = await createAccount(db, "borrado@ejemplo.com");
    const domain = await addDomain(db, session, "borrar.com");
    const { summary } = await runDomainAudit(db, session, domain.id, { run });

    await deleteDomain(db, session, domain.id);

    await expect(getAudit(db, session.organization.id, summary.id)).rejects.toMatchObject({ status: 404 });
    await expect(getDomain(db, session.organization.id, domain.id)).rejects.toMatchObject({ status: 404 });
  });
});
