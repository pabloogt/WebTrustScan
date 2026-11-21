import { RECOVERY_COOKIE, verifyRecoveryTicket } from "@/lib/accounts/analyze";
import { errorResponse, json, readJson, requireUser, route } from "@/lib/accounts/http";
import { changePassword } from "@/lib/accounts/service";

export const POST = route(async ({ request, deps }) => {
  const user = await requireUser(deps);
  // Con un pase de recuperación vigente no se pide la contraseña anterior.
  const recovering = verifyRecoveryTicket(
    request.cookies.get(RECOVERY_COOKIE)?.value,
    user.id,
  );

  try {
    await changePassword(deps, user, request.headers, await readJson(request), {
      requireCurrent: !recovering,
    });
  } catch (error) {
    return errorResponse(error);
  }

  const response = json({ ok: true });
  // El pase es de un solo uso.
  response.cookies.set(RECOVERY_COOKIE, "", { path: "/", maxAge: 0 });
  return response;
});
