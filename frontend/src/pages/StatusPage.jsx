import Notice from "../components/Notice.jsx";
import { useHealth } from "../hooks/useHealth.js";

const BADGE = {
  ok: ["Operational", "bg-emerald-100 text-emerald-800"],
  degraded: ["Degraded", "bg-amber-100 text-amber-800"],
  unreachable: ["Unreachable", "bg-rose-100 text-rose-800"],
  loading: ["Checking…", "bg-slate-100 text-slate-700"],
};

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between py-2">
      <dt className="text-sm text-slate-500">{label}</dt>
      <dd className="text-sm font-medium text-slate-900">{value}</dd>
    </div>
  );
}

export default function StatusPage() {
  const { phase, data, error, refresh } = useHealth();
  const [label, tone] = BADGE[phase];

  return (
    <section aria-labelledby="status-heading" className="mx-auto max-w-xl">
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between gap-3">
          <h2 id="status-heading" className="text-lg font-semibold">
            Backend status
          </h2>
          <span data-testid="status-badge" className={`rounded-full px-3 py-1 text-xs font-semibold ${tone}`}>
            {label}
          </span>
        </div>

        {phase === "loading" && (
          <p role="status" className="mt-4 text-sm text-slate-500">
            Contacting the API…
          </p>
        )}

        {phase === "unreachable" && (
          <div className="mt-4">
            <Notice tone="error" title="The API is not reachable">
              {error?.message}
            </Notice>
          </div>
        )}

        {data && (
          <dl className="mt-4 divide-y divide-slate-100">
            <Row label="Service" value={data.service} />
            <Row label="Version" value={data.version} />
            <Row label="Database" value={data.database} />
          </dl>
        )}

        {phase === "degraded" && (
          <div className="mt-4">
            <Notice tone="warning" title="The API is running but a dependency is failing">
              Database check reported “{data?.database}”.
            </Notice>
          </div>
        )}

        <button
          type="button"
          onClick={refresh}
          disabled={phase === "loading"}
          className="mt-5 rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
        >
          Re-check
        </button>
      </div>
    </section>
  );
}
