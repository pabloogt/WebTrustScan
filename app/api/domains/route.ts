import { addDomain, listDomains } from "@/lib/pro/domains";
import { json, readJson, requireSession, route } from "@/lib/pro/http";

export const GET = route(async ({ request, db }) => {
  const session = await requireSession(db, request);

  return json({ domains: await listDomains(db, session.organization.id) });
});

export const POST = route(async ({ request, db }) => {
  const session = await requireSession(db, request);
  const body = await readJson(request);

  return json({ domain: await addDomain(db, session, body.hostname) }, 201);
});
