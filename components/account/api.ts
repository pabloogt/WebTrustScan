/**
 * Cliente de la API de cuentas. Siempre mismo origen: el navegador nunca
 * habla con Supabase ni maneja tokens (las cookies de sesión son HttpOnly).
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly data: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export async function api<T>(
  path: string,
  options: { method?: "GET" | "POST" | "PATCH" | "DELETE"; body?: unknown } = {},
): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? "GET",
    credentials: "same-origin",
    headers:
      options.body === undefined ? undefined : { "Content-Type": "application/json" },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const data = (await response.json().catch(() => null)) as
    | (T & { error?: string })
    | null;

  if (!response.ok || !data) {
    throw new ApiError(
      response.status,
      data?.error ?? "No se pudo completar la operación.",
      (data as Record<string, unknown> | null) ?? {},
    );
  }

  return data;
}

export const field =
  "w-full rounded-xl border border-slate-700 bg-slate-800 px-4 py-3 text-white placeholder:text-slate-500 outline-none focus:border-slate-500";
export const primaryButton =
  "rounded-xl bg-white px-5 py-2.5 font-semibold text-slate-900 transition hover:bg-slate-200 disabled:opacity-60";
export const secondaryButton =
  "rounded-xl border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-slate-500 disabled:opacity-50";
export const card = "rounded-2xl border border-slate-800 bg-slate-900 p-6";

export const messageOf = (cause: unknown, fallback = "Ha ocurrido un error.") =>
  cause instanceof Error ? cause.message : fallback;
