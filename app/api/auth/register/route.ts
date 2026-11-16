import { json, readJson, route } from "@/lib/accounts/http";
import { register } from "@/lib/accounts/service";

export const POST = route(async ({ request, deps }) =>
  // Siempre 200 con el mismo texto: no revela si la cuenta ya existía.
  json(await register(deps, request.headers, await readJson(request))),
);
