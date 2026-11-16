import { NextResponse, type NextRequest } from "next/server";
import {
  RECOVERY_COOKIE,
  RECOVERY_COOKIE_SECONDS,
  createRecoveryTicket,
} from "@/lib/accounts/analyze";
import { accountsEnabled } from "@/lib/accounts/config";
import { getDeps, safeNextPath } from "@/lib/accounts/http";
import type { OtpType } from "@/lib/accounts/ports";
import { checkLimit, clientKey } from "@/lib/limits";

const TYPES: OtpType[] = ["email", "signup", "recovery", "email_change"];

/**
 * Destino de los enlaces de los correos (confirmación de alta, recuperación
 * y cambio de correo). Canjea el enlace en el servidor, que es quien fija
 * las cookies de sesión, y redirige a una ruta interna.
 */
export async function GET(request: NextRequest) {
  if (!accountsEnabled()) {
    return NextResponse.json({ error: "No encontrado." }, { status: 404 });
  }

  const { searchParams } = request.nextUrl;
  const type = searchParams.get("type") as OtpType | null;
  const tokenHash = searchParams.get("token_hash");
  const failed = new URL("/acceso?estado=enlace-no-valido", request.nextUrl.origin);

  if (!type || !TYPES.includes(type) || !tokenHash || tokenHash.length > 200) {
    return NextResponse.redirect(failed);
  }

  try {
    // Frena a quien intente adivinar enlaces.
    const limit = await checkLimit("confirm", clientKey(request.headers), {
      max: 20,
      windowSeconds: 600,
    });
    if (!limit.allowed) return NextResponse.redirect(failed);

    const deps = await getDeps();
    const result = await deps.auth.verifyLink(type, tokenHash);

    if (!result.ok) return NextResponse.redirect(failed);

    if (type === "recovery") {
      const user = await deps.auth.getUser();
      if (!user) return NextResponse.redirect(failed);

      const response = NextResponse.redirect(
        new URL("/cuenta/nueva-contrasena", request.nextUrl.origin),
      );
      response.cookies.set(RECOVERY_COOKIE, createRecoveryTicket(user.id), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: RECOVERY_COOKIE_SECONDS,
      });
      return response;
    }

    return NextResponse.redirect(
      new URL(safeNextPath(searchParams.get("next")), request.nextUrl.origin),
    );
  } catch (error) {
    console.error("No se pudo canjear un enlace de correo:", error instanceof Error ? error.name : "error");
    return NextResponse.redirect(failed);
  }
}
