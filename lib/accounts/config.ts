type Env = Record<string, string | undefined>;

/**
 * Interruptor global de las cuentas (acceso, panel y toda su API).
 *
 * POR DEFECTO ESTÁN DESACTIVADAS. Solo se activan si la variable de entorno
 * de servidor ACCOUNTS_ENABLED vale exactamente "true". Cualquier otro valor
 * —ausente, vacío, "1", "TRUE", "yes"— las deja desactivadas.
 *
 * Se comprueba ANTES de crear ningún cliente de Supabase: con las cuentas
 * desactivadas no se hace ninguna conexión con la base de datos.
 */
export function accountsEnabled(env: Env = process.env): boolean {
  return env.ACCOUNTS_ENABLED === "true";
}

export type SupabaseConfig = {
  url: string;
  /** Clave pública: solo da acceso a lo que permitan RLS y los permisos. */
  publishableKey: string;
  /** Clave secreta: se salta RLS. Solo en servidor; nunca NEXT_PUBLIC_. */
  secretKey: string | null;
};

/** Configuración de Supabase, o null si falta algo imprescindible. */
export function supabaseConfig(env: Env = process.env): SupabaseConfig | null {
  const url = env.NEXT_PUBLIC_SUPABASE_URL;
  const publishableKey =
    env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !publishableKey) return null;

  return {
    url,
    publishableKey,
    secretKey: env.SUPABASE_SECRET_KEY ?? env.SUPABASE_SERVICE_ROLE_KEY ?? null,
  };
}

/**
 * URL pública de la aplicación, para los enlaces de los correos. Se toma de
 * configuración, nunca de la cabecera Host de la petición (que un atacante
 * podría falsear para que el enlace apunte a su dominio).
 */
export function appBaseUrl(env: Env = process.env): string {
  const value = env.APP_BASE_URL?.replace(/\/+$/, "");

  if (value && /^https?:\/\//.test(value)) return value;
  if (env.NODE_ENV !== "production") return "http://localhost:3000";

  throw new Error("APP_BASE_URL no está configurada.");
}
