import { destroySession } from "@/lib/pro/auth";
import { clearSessionCookie, json, readSessionToken, route } from "@/lib/pro/http";

export const POST = route(async ({ request, db }) => {
  const token = readSessionToken(request);

  if (token) await destroySession(db, token);

  const response = json({ ok: true });
  clearSessionCookie(response);
  return response;
});
