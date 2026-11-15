import { authenticate, createSession, getSession } from "@/lib/pro/auth";
import { ProError } from "@/lib/pro/errors";
import { enforceRateLimit, json, readJson, route, setSessionCookie } from "@/lib/pro/http";

export const POST = route(async ({ request, db }) => {
  await enforceRateLimit(request, "login", 10, 60_000);

  const body = await readJson(request);
  const userId = await authenticate(db, body.email, body.password);

  if (!userId) {
    // Mismo mensaje exista o no la cuenta.
    throw new ProError(401, "Correo o contraseña incorrectos.");
  }

  // Sesión nueva en cada acceso: nunca se reutiliza un token anterior.
  const token = await createSession(db, userId);
  const response = json({ session: await getSession(db, token) });

  setSessionCookie(response, token);
  return response;
});
