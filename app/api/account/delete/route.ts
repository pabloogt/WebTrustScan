import { json, readJson, requireUser, route } from "@/lib/accounts/http";
import { deleteAccount } from "@/lib/accounts/service";

export const POST = route(async ({ request, deps }) => {
  await deleteAccount(deps, await requireUser(deps), request.headers, await readJson(request));
  return json({ ok: true });
});
