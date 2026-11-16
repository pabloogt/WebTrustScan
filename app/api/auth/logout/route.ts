import { json, readJson, route } from "@/lib/accounts/http";

export const POST = route(async ({ request, deps }) => {
  const body = await readJson(request).catch(() => ({}) as Record<string, unknown>);

  // "global" revoca todas las sesiones de la cuenta, no solo esta.
  await deps.auth.signOut(body.scope === "all" ? "global" : "local");

  return json({ ok: true });
});
