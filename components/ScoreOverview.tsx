import { AuditResult } from "@/types/audit";

type ScoreOverviewProps = {
  result: AuditResult;
};

export default function ScoreOverview({ result }: ScoreOverviewProps) {
  const scoreMeta =
    result.score >= 85
      ? {
          label: "Buena",
          ring: "border-green-500/40 text-green-300 bg-green-500/10",
          badge: "bg-green-500/15 text-green-300 border-green-500/30",
        }
      : result.score >= 60
      ? {
          label: "Aceptable",
          ring: "border-yellow-500/40 text-yellow-300 bg-yellow-500/10",
          badge: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
        }
      : {
          label: "Débil",
          ring: "border-red-500/40 text-red-300 bg-red-500/10",
          badge: "bg-red-500/15 text-red-300 border-red-500/30",
        };

  const passedChecks = result.checks.filter(
    (check) => check.status === "pass"
  ).length;

  const nonPassedChecks = result.checks.filter(
    (check) => check.status !== "pass"
  ).length;

  return (
    <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <p className="text-sm text-slate-400">Puntuación global</p>

        <div
          className={`mt-4 h-28 w-28 rounded-full border-4 flex items-center justify-center text-3xl font-bold ${scoreMeta.ring}`}
        >
          {result.score}
        </div>

        <div className="mt-5">
          <span
            className={`inline-flex rounded-full border px-3 py-1 text-sm font-medium ${scoreMeta.badge}`}
          >
            Seguridad {scoreMeta.label}
          </span>
        </div>

        <p className="mt-5 text-sm text-slate-300">{result.summary}</p>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <p className="text-sm text-slate-400">URL analizada</p>
        <p className="mt-2 text-lg font-medium break-all">{result.url}</p>

        <div className="mt-6 grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl bg-slate-800 p-4">
            <p className="text-sm text-slate-400">Checks totales</p>
            <p className="mt-2 text-2xl font-semibold">{result.checks.length}</p>
          </div>

          <div className="rounded-xl bg-slate-800 p-4">
            <p className="text-sm text-slate-400">Correctos</p>
            <p className="mt-2 text-2xl font-semibold">{passedChecks}</p>
          </div>

          <div className="rounded-xl bg-slate-800 p-4">
            <p className="text-sm text-slate-400">A mejorar</p>
            <p className="mt-2 text-2xl font-semibold">{nonPassedChecks}</p>
          </div>
        </div>
      </div>
    </div>
  );
}