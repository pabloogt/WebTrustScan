import { listAudits, runDomainAudit } from "@/lib/pro/audits";
import { json, requireSession, route } from "@/lib/pro/http";

// El análisis tiene su propio tope de 20 s; se deja margen a la plataforma.
export const maxDuration = 30;

export const GET = route<{ id: string }>(async ({ request, db, params }) => {
  const session = await requireSession(db, request);

  return json({
    audits: await listAudits(db, session.organization.id, params.id),
  });
});

export const POST = route<{ id: string }>(async ({ request, db, params }) => {
  const session = await requireSession(db, request);

  return json(await runDomainAudit(db, session, params.id), 201);
});
