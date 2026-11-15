/**
 * Interruptor de las cuentas (registro, acceso, panel y toda la API Pro).
 *
 * POR DEFECTO ESTÁN DESACTIVADAS. Solo se activan si la variable de entorno
 * de servidor ACCOUNTS_ENABLED vale exactamente "true". Cualquier otro valor
 * —ausente, vacío, "1", "TRUE", "yes"— las deja desactivadas: ante la duda,
 * cerrado.
 *
 * La variable se lee en el servidor en cada petición y no lleva el prefijo
 * NEXT_PUBLIC_, así que nunca llega al navegador ni se puede cambiar desde él.
 */
export function accountsEnabled(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return env.ACCOUNTS_ENABLED === "true";
}
