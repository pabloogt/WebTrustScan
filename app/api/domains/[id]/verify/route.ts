import { verifyDomain } from "@/lib/pro/domains";
import { enforceRateLimit, json, requireSession, route } from "@/lib/pro/http";

export const POST = route<{ id: string }>(async ({ request, db, params }) => {
  const session = await requireSession(db, request);

  // Cada intento hace una consulta DNS y una petición saliente.
  await enforceRateLimit(request, "verify", 10, 60_000);

  const { verified, method, domain } = await verifyDomain(db, session, params.id);

  return json({ verified, method, domain });
});
