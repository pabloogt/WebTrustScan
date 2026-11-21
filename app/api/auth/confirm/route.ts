import {
  RECOVERY_COOKIE,
  RECOVERY_COOKIE_SECONDS,
  createRecoveryTicket,
} from "@/lib/accounts/analyze";
import { json, readJson, route } from "@/lib/accounts/http";
import { confirmLink } from "@/lib/accounts/service";

/**
 * Canjea el enlace de un correo. Lo llama la página /auth/confirm cuando el
 * usuario pulsa «Continuar». Al ser POST y exigir mismo origen, abrir el
 * enlace de forma automática (un filtro de correo) no consume el token.
 */
export const POST = route(async ({ request, deps }) => {
  const { next, recoveryFor } = await confirmLink(deps, request.headers, await readJson(request));
  const response = json({ next });

  if (recoveryFor) {
    // Pase firmado de 15 minutos: permite fijar la contraseña sin la anterior.
    response.cookies.set(RECOVERY_COOKIE, createRecoveryTicket(recoveryFor), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: RECOVERY_COOKIE_SECONDS,
    });
  }

  return response;
});
