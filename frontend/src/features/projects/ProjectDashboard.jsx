import { useEffect, useState } from "react";
import { getDashboard } from "../../api/workflow";

const SEV = {
  critical: "bg-red-700 text-white",
  high: "bg-red-100 text-red-800",
  medium: "bg-amber-100 text-amber-800",
  low: "bg-gray-100 text-gray-800",
};

export default function ProjectDashboard({ projectId }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let alive = true;
    getDashboard(projectId)
      .then((d) => alive && setData(d))
      .catch((e) => alive && setError(e));
    return () => { alive = false; };
  }, [projectId]);

  if (error) return <div role="alert" className="text-red-700">Could not load dashboard: {error.message}</div>;
  if (!data) return <div className="text-gray-500">Loading dashboard...</div>;

  return (
    <div className="space-y-5">
      <ol className="flex gap-2">
        {data.stages.map((s) => (
          <li key={s.key} className={`flex-1 rounded border px-3 py-2 text-sm ${s.done ? "bg-green-50 border-green-300 text-green-800" : "bg-gray-50 text-gray-600"}`}>
            {s.done ? "✓" : "○"} {s.label}
          </li>
        ))}
      </ol>

      {data.next_step ? (
        <p className="text-sm">Next step: <strong>{data.next_step}</strong></p>
      ) : (
        <p className="text-sm text-green-700">Full workflow completed.</p>
      )}

      <div className="flex gap-3">
        {Object.entries(data.finding_counts).map(([sev, n]) => (
          <div key={sev} className={`rounded px-3 py-2 text-sm ${SEV[sev]}`}>
            <div className="text-xl font-semibold">{n}</div>{sev}
          </div>
        ))}
      </div>

      <p className="text-sm text-gray-600">
        {data.simulations_run} simulation(s) run, {data.safe_fixes} safe fix(es). Snapshot v{data.snapshot_version ?? "-"}. Read-only: nothing is applied to AWS.
      </p>
    </div>
  );
}
