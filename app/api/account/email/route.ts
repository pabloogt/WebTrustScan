import { json, readJson, requireUser, route } from "@/lib/accounts/http";
import { changeEmail } from "@/lib/accounts/service";

export const POST = route(async ({ request, deps }) =>
  json(
    await changeEmail(deps, await requireUser(deps), request.headers, await readJson(request)),
  ),
);
