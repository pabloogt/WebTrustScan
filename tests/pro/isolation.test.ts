import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { GET as compareRoute } from "@/app/api/audits/compare/route";
import { GET as auditRoute } from "@/app/api/audits/[id]/route";
import {
  GET as historyRoute,
  POST as runRoute,
} from "@/app/api/domains/[id]/audits/route";
import {
  DELETE as deleteRoute,
  GET as domainRoute,
} from "@/app/api/domains/[id]/route";
import { POST as verifyRoute } from "@/app/api/domains/[id]/verify/route";
import { GET as listRoute, POST as addRoute } from "@/app/api/domains/route";
import { runAudit } from "@/lib/engine/run";
import { runDomainAudit } from "@/lib/pro/audits";
import { setDbForTests, type Db } from "@/lib/pro/db";
import { addDomain } from "@/lib/pro/domains";
import { resetRateLimitsForTests } from "@/lib/pro/http";
import { GOOD_HEADERS, labOptions, respond, startSite, type Site } from "../lab/harness";
import { call, createAccount, createTestDb, type Account } from "./helpers";

/**
 * Aislamiento entre organizaciones. La organización B conoce (o adivina) los
 * identificadores de los recursos de A e intenta usarlos por todas las rutas.
 * Todo debe responder 404, igual que si no existieran.
 */

let db: Db;
let site: Site;
let alice: Account;
let bob: Account;
let domainA: string;
let domainB: string;
let auditA1: string;
let auditA2: string;
let auditB: string;

beforeAll(async () => {
  db = await createTestDb();
  setDbForTests(db);
  site = await startSite({ name: "aislado", handler: respond(GOOD_HEADERS) });

  const run = () => runAudit(site.url, labOptions(site));

  alice = await createAccount(db, "alice@a.example", { plan: "pro" });
  bob = await createAccount(db, "bob@b.example", { plan: "pro" });

  domainA = (await addDomain(db, alice.session, "empresa-a.com")).id;
  domainB = (await addDomain(db, bob.session, "empresa-b.com")).id;
  auditA1 = (await runDomainAudit(db, alice.session, domainA, { run, now: () => new Date("2026-05-01T00:00:00Z") })).summary.id;
  auditA2 = (await runDomainAudit(db, alice.session, domainA, { run, now: () => new Date("2026-05-02T00:00:00Z") })).summary.id;
  auditB = (await runDomainAudit(db, bob.session, domainB, { run })).summary.id;
});

afterAll(async () => {
  setDbForTests(null);
  await site.close();
  await db.close();
});

beforeEach(() => {
  resetRateLimitsForTests();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("aislamiento entre organizaciones", () => {
  it("cada organización solo lista sus dominios", async () => {
    const a = await call(listRoute, { token: alice.token });
    const b = await call(listRoute, { token: bob.token });
    const hosts = (data: Record<string, unknown>) =>
      (data.domains as { hostname: string }[]).map((domain) => domain.hostname);

    expect(hosts(a.data)).toEqual(["empresa-a.com"]);
    expect(hosts(b.data)).toEqual(["empresa-b.com"]);
    expect(JSON.stringify(b.data)).not.toContain("empresa-a.com");
  });

  it("B no puede leer, verificar, auditar ni borrar un dominio de A", async () => {
    const params = { id: domainA };

    expect((await call(domainRoute, { token: bob.token, params })).status).toBe(404);
    expect((await call(historyRoute, { token: bob.token, params })).status).toBe(404);
    expect((await call(verifyRoute, { method: "POST", token: bob.token, params })).status).toBe(404);
    expect((await call(runRoute, { method: "POST", token: bob.token, params })).status).toBe(404);
    expect((await call(deleteRoute, { method: "DELETE", token: bob.token, params })).status).toBe(404);

    // El dominio de A sigue intacto.
    const still = await call(domainRoute, { token: alice.token, params });
    expect(still.status).toBe(200);
    expect((still.data.domain as { hostname: string }).hostname).toBe("empresa-a.com");
  });

  it("B no puede leer una auditoría de A aunque conozca su identificador", async () => {
    const stolen = await call(auditRoute, { token: bob.token, params: { id: auditA1 } });

    expect(stolen.status).toBe(404);
    expect(JSON.stringify(stolen.data)).not.toContain("findings");

    const own = await call(auditRoute, { token: alice.token, params: { id: auditA1 } });
    expect(own.status).toBe(200);
    expect(own.data.report).toBeDefined();
  });

  it("B no puede comparar auditorías de A, ni mezclar una suya con una de A", async () => {
    const compare = (token: string, from: string, to: string) =>
      call(compareRoute, { token, path: `/api/audits/compare?from=${from}&to=${to}` });

    expect((await compare(alice.token, auditA1, auditA2)).status).toBe(200);
    expect((await compare(bob.token, auditA1, auditA2)).status).toBe(404);
    expect((await compare(bob.token, auditB, auditA1)).status).toBe(404);
    expect((await compare(bob.token, auditA1, auditB)).status).toBe(404);
  });

  it("un recurso ajeno y uno inexistente responden exactamente igual", async () => {
    const foreign = await call(auditRoute, { token: bob.token, params: { id: auditA1 } });
    const missing = await call(auditRoute, {
      token: bob.token,
      params: { id: "00000000-0000-4000-8000-000000000000" },
    });

    expect(foreign.status).toBe(missing.status);
    expect(foreign.data).toEqual(missing.data);
  });

  it.each([
    "no-es-un-uuid",
    "1 or 1=1",
    "'; drop table audits; --",
    "../../etc/passwd",
    "",
  ])("identificadores malformados (%s) responden 404 sin error interno", async (id) => {
    for (const handler of [domainRoute, historyRoute, auditRoute]) {
      expect((await call(handler, { token: alice.token, params: { id } })).status).toBe(404);
    }
    expect(console.error).not.toHaveBeenCalled();
  });

  it("sin sesión ninguna ruta de datos responde", async () => {
    const params = { id: domainA };

    expect((await call(listRoute)).status).toBe(401);
    expect((await call(domainRoute, { params })).status).toBe(401);
    expect((await call(historyRoute, { params })).status).toBe(401);
    expect((await call(auditRoute, { params: { id: auditA1 } })).status).toBe(401);
    expect((await call(compareRoute, { path: `/api/audits/compare?from=${auditA1}&to=${auditA2}` })).status).toBe(401);
    expect((await call(addRoute, { method: "POST", body: { hostname: "x.com" } })).status).toBe(401);
    expect((await call(runRoute, { method: "POST", params })).status).toBe(401);
  });

  it("las rutas que modifican estado exigen mismo origen aunque haya sesión", async () => {
    const evil = "https://sitio-malicioso.example";
    const params = { id: domainA };

    expect((await call(addRoute, { method: "POST", token: alice.token, origin: evil, body: { hostname: "x.com" } })).status).toBe(403);
    expect((await call(deleteRoute, { method: "DELETE", token: alice.token, origin: evil, params })).status).toBe(403);
    expect((await call(runRoute, { method: "POST", token: alice.token, origin: evil, params })).status).toBe(403);
    expect((await call(verifyRoute, { method: "POST", token: alice.token, origin: evil, params })).status).toBe(403);
  });

  it("la organización nunca se toma de la petición", async () => {
    // Bob intenta crear un dominio «dentro» de la organización de Alice.
    const result = await call(addRoute, {
      method: "POST",
      token: bob.token,
      body: {
        hostname: "inyectado.com",
        organizationId: alice.session.organization.id,
        organization_id: alice.session.organization.id,
      },
    });

    expect(result.status).toBe(201);

    const rows = await db.query<{ organization_id: string }>(
      "select organization_id from domains where hostname = 'inyectado.com'",
    );
    expect(rows).toEqual([{ organization_id: bob.session.organization.id }]);
  });

  it("las respuestas con datos privados no se cachean", async () => {
    const response = (await call(auditRoute, { token: alice.token, params: { id: auditA1 } })).response;

    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("la ruta de auditoría solo analiza el dominio guardado, nunca una URL de la petición", async () => {
    const account = await createAccount(db, "ssrf@c.example");
    const domain = await addDomain(db, account.session, "no-existe.invalid");
    const result = await call(runRoute, {
      method: "POST",
      token: account.token,
      params: { id: domain.id },
      body: { url: "http://169.254.169.254/latest/meta-data/", hostname: "127.0.0.1" },
    });

    // Se intenta el dominio guardado (que no resuelve): el cuerpo se ignora.
    expect(result.status).toBe(409);
    expect(result.data.error).toMatch(/No se ha encontrado ese dominio/);
  });
});
