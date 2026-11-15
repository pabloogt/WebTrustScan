import { PLAN_LIMITS } from "@/lib/pro/plans";
import { json, requireSession, route } from "@/lib/pro/http";

export const GET = route(async ({ request, db }) => {
  const session = await requireSession(db, request);

  return json({ session, limits: PLAN_LIMITS[session.organization.plan] });
});
