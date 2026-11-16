import { json, readJson, route } from "@/lib/accounts/http";
import { requestRecovery } from "@/lib/accounts/service";

export const POST = route(async ({ request, deps }) =>
  json(await requestRecovery(deps, request.headers, await readJson(request))),
);
