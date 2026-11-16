import { notFound } from "next/navigation";
import { accountsEnabled } from "@/lib/accounts/config";
import { getDeps } from "@/lib/accounts/http";
import type { SessionUser } from "@/lib/accounts/ports";

/**
 * Sesión para una página de servidor. Con las cuentas desactivadas la página
 * no existe (404), y eso se decide antes de tocar Supabase.
 */
export async function pageSession(): Promise<SessionUser | null> {
  if (!accountsEnabled()) notFound();

  try {
    return await (await getDeps()).auth.getUser();
  } catch {
    // Cuentas activadas pero sin configurar o caídas: se trata como sin sesión.
    return null;
  }
}
