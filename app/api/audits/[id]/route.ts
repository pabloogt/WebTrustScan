import { AccountError, isUuid, json, requireUser, route } from "@/lib/accounts/http";
import { enforceLimit } from "@/lib/limits";
import { RATE_LIMITS } from "@/lib/plans";

// Un análisis ajeno responde igual que uno inexistente: no se revela que el
// identificador es válido.
const notFound = () => new AccountError(404, "El análisis no existe.");

export const GET = route<{ id: string }>(async ({ deps, params }) => {
  const user = await requireUser(deps);

  await enforceLimit("account-read", user.id, RATE_LIMITS.accountReads);
  if (!isUuid(params.id)) throw notFound();

  const audit = await deps.data.getAudit(params.id);
  if (!audit) throw notFound();

  return json(audit);
});

export const DELETE = route<{ id: string }>(async ({ deps, params }) => {
  const user = await requireUser(deps);

  await enforceLimit("account-change", user.id, RATE_LIMITS.accountChanges);
  if (!isUuid(params.id) || !(await deps.data.deleteAudit(params.id))) throw notFound();

  // Borrar del historial no devuelve el análisis a la cuota.
  return json({ ok: true });
});
