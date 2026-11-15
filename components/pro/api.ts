/** Cliente mínimo de la API Pro (mismo origen, cookie de sesión HttpOnly). */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(
  path: string,
  options: { method?: "GET" | "POST" | "DELETE"; body?: unknown } = {},
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
    );
  }

  return data;
}

export type SessionInfo = {
  session: {
    user: { id: string; email: string };
    organization: { id: string; name: string; plan: "free" | "pro" | "agency" };
    role: string;
  };
  limits: { domains: number; storedAuditsPerDomain: number; auditsPerHour: number };
};
