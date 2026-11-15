import { compareAudits } from "@/lib/pro/audits";
import { json, requireSession, route } from "@/lib/pro/http";

export const GET = route(async ({ request, db }) => {
  const session = await requireSession(db, request);
  const { searchParams } = request.nextUrl;

  return json({
    comparison: await compareAudits(
      db,
      session.organization.id,
      searchParams.get("from"),
      searchParams.get("to"),
    ),
  });
});
