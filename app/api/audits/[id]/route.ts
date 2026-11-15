import { getAudit } from "@/lib/pro/audits";
import { json, requireSession, route } from "@/lib/pro/http";

export const GET = route<{ id: string }>(async ({ request, db, params }) => {
  const session = await requireSession(db, request);

  return json(await getAudit(db, session.organization.id, params.id));
});
