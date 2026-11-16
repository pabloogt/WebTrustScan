import { json, readJson, route } from "@/lib/accounts/http";
import { login } from "@/lib/accounts/service";

export const POST = route(async ({ request, deps }) => {
  const user = await login(deps, request.headers, await readJson(request));

  // Las cookies de sesión (HttpOnly) las ha fijado ya el cliente de Supabase.
  return json({ user: { email: user.email } });
});
