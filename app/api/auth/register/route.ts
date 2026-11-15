import { createSession, getSession, registerUser } from "@/lib/pro/auth";
import { enforceRateLimit, json, readJson, route, setSessionCookie } from "@/lib/pro/http";

export const POST = route(async ({ request, db }) => {
  // El alta es costosa (scrypt) y crea datos: límite estricto por cliente.
  await enforceRateLimit(request, "register", 5, 3_600_000);

  const body = await readJson(request);
  const { userId } = await registerUser(db, {
    email: body.email,
    password: body.password,
    organizationName: body.organizationName,
  });
  const token = await createSession(db, userId);
  const response = json({ session: await getSession(db, token) }, 201);

  setSessionCookie(response, token);
  return response;
});
