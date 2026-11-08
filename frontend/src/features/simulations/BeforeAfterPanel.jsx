const VERDICTS = {
  safe_improvement: { label: "Safe improvement", cls: "bg-green-50 text-green-800 border-green-300" },
  no_improvement: { label: "No improvement", cls: "bg-gray-50 text-gray-800 border-gray-300" },
  breaks_required_connectivity: { label: "Breaks required connectivity", cls: "bg-red-50 text-red-800 border-red-300" },
  needs_review: { label: "Needs review", cls: "bg-amber-50 text-amber-800 border-amber-300" },
};

const RESULT_CLS = {
  allowed: "bg-green-100 text-green-800",
  blocked: "bg-red-100 text-red-800",
  unknown: "bg-amber-100 text-amber-800",
};

const Pill = ({ value }) => (
  <span className={`px-2 py-0.5 rounded text-xs font-medium ${RESULT_CLS[value] || ""}`}>{value}</span>
);

function FindingList({ title, items, empty }) {
  return (
    <div className="flex-1">
      <h4 className="font-medium mb-1">{title} ({items.length})</h4>
      {items.length === 0 ? (
        <p className="text-sm text-gray-500">{empty}</p>
      ) : (
        <ul className="text-sm space-y-1">
          {items.map((f) => (
            <li key={`${f.rule_id}-${f.resource_ref}`}>
              <code>{f.rule_id}</code> on <code>{f.resource_ref}</code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function BeforeAfterPanel({ result }) {
  if (!result) return null;
  const v = VERDICTS[result.verdict] || VERDICTS.needs_review;
  const p = result.proposal;

  return (
    <section className="space-y-4" aria-label="Simulation result">
      <div className="flex items-center justify-between rounded border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-900">
        <span>🔒 Read-only simulation. No real AWS resources were changed.</span>
      </div>

      <div className={`rounded border px-3 py-2 font-medium ${v.cls}`}>{v.label}</div>

      {result.warnings.length > 0 && (
        <ul className="space-y-1" role="alert">
          {result.warnings.map((w, i) => (
            <li key={i} className="text-sm rounded bg-amber-50 border border-amber-200 px-3 py-2">
              ⚠️ <strong>{w.code}</strong>: {w.message}
            </li>
          ))}
        </ul>
      )}

      <div className="rounded border p-3 text-sm">
        <h4 className="font-medium mb-1">Proposed change</h4>
        <code className="block whitespace-pre-wrap">{JSON.stringify(p, null, 2)}</code>
      </div>

      <div className="flex gap-4">
        <FindingList title="Resolved" items={result.resolved_findings} empty="Nothing resolved." />
        <FindingList title="Still present" items={result.remaining_findings} empty="None remaining." />
        <FindingList title="Newly introduced" items={result.introduced_findings} empty="No new findings." />
      </div>

      <table className="w-full text-sm border">
        <thead className="bg-gray-50 text-left">
          <tr><th className="p-2">Path</th><th className="p-2">Before</th><th className="p-2">After</th><th className="p-2">Required</th></tr>
        </thead>
        <tbody>
          {result.path_changes.map((c) => (
            <tr key={c.id} className={c.changed ? "bg-yellow-50" : ""}>
              <td className="p-2"><code>{c.id}</code></td>
              <td className="p-2"><Pill value={c.before} /></td>
              <td className="p-2"><Pill value={c.after} /></td>
              <td className="p-2">{c.required ? "yes" : "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-xs text-gray-500">
        Results come from a deterministic, simplified model of AWS networking. "unknown" means the path is outside the supported model.
      </p>
    </section>
  );
}
