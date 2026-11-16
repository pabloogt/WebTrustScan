import { json, readJson, requireUser, route } from "@/lib/accounts/http";
import { overview, updateProfile } from "@/lib/accounts/service";

export const GET = route(async ({ deps }) =>
  json(await overview(deps, await requireUser(deps))),
);

export const PATCH = route(async ({ request, deps }) => {
  await updateProfile(deps, await requireUser(deps), await readJson(request));
  return json({ ok: true });
});
