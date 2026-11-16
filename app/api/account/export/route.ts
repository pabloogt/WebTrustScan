import { NextResponse } from "next/server";
import { requireUser, route } from "@/lib/accounts/http";
import { enforceLimit } from "@/lib/limits";

export const GET = route(async ({ deps }) => {
  const user = await requireUser(deps);

  await enforceLimit("account-export", user.id, { max: 5, windowSeconds: 3_600 });

  const body = JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      account: { email: user.email },
      // Se lee con la sesión del usuario: RLS garantiza que solo sale lo suyo.
      ...(await deps.data.exportAll(user.id)),
    },
    null,
    2,
  );

  return new NextResponse(body, {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": 'attachment; filename="webtrustscan-mis-datos.json"',
      "Cache-Control": "no-store",
    },
  });
});
