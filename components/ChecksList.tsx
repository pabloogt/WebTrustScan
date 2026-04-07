import { AuditCheck, CheckStatus } from "@/types/audit";

type ChecksListProps = {
  checks: AuditCheck[];
};

function getStatusStyles(status: CheckStatus) {
  if (status === "pass") {
    return "bg-green-500/15 text-green-300 border-green-500/30";
  }

  if (status === "warn") {
    return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
  }

  return "bg-red-500/15 text-red-300 border-red-500/30";
}

function getStatusLabel(status: CheckStatus) {
  if (status === "pass") return "Bien";
  if (status === "warn") return "Mejorable";
  return "Crítico";
}

function getStatusIcon(status: CheckStatus) {
  if (status === "pass") return "✓";
  if (status === "warn") return "!";
  return "✕";
}

export default function ChecksList({ checks }: ChecksListProps) {
  return (
    <div className="space-y-4">
      {checks.map((check) => (
        <article
          key={check.key}
          className="bg-slate-900 border border-slate-800 rounded-2xl p-5"
        >
          <div className="flex items-start gap-4">
            <div
              className={`mt-1 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border text-base font-bold ${getStatusStyles(
                check.status
              )}`}
            >
              {getStatusIcon(check.status)}
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <h2 className="text-lg font-semibold">{check.title}</h2>

                <span
                  className={`inline-flex w-fit rounded-full border px-3 py-1 text-sm font-medium ${getStatusStyles(
                    check.status
                  )}`}
                >
                  {getStatusLabel(check.status)}
                </span>
              </div>

              <p className="mt-3 text-slate-300">{check.description}</p>

              {check.fix && (
                <div className="mt-4 rounded-xl bg-slate-800 p-4">
                  <p className="text-sm font-semibold text-slate-200">
                    Cómo arreglarlo
                  </p>
                  <p className="mt-1 text-sm text-slate-300">{check.fix}</p>
                </div>
              )}
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}