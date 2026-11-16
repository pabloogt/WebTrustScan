import { json, requireUser, route } from "@/lib/accounts/http";
import { enforceLimit } from "@/lib/limits";
import { RATE_LIMITS } from "@/lib/plans";

export const GET = route(async ({ deps }) => {
  const user = await requireUser(deps);

  await enforceLimit("account-read", user.id, RATE_LIMITS.accountReads);

  return json({ audits: await deps.data.listAudits() });
});
