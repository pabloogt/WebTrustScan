import { deleteDomain, getDomain } from "@/lib/pro/domains";
import { json, requireSession, route } from "@/lib/pro/http";

export const GET = route<{ id: string }>(async ({ request, db, params }) => {
  const session = await requireSession(db, request);

  return json({ domain: await getDomain(db, session.organization.id, params.id) });
});

export const DELETE = route<{ id: string }>(async ({ request, db, params }) => {
  const session = await requireSession(db, request);

  await deleteDomain(db, session, params.id);
  return json({ ok: true });
});
