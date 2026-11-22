import { SEVERITY_FILL, SEVERITY_ORDER } from "./colors.js";

/** Stacked bar of the findings of one analysis by severity. */
export default function SeverityBars({ bySeverity }) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (bySeverity?.[s] ?? 0), 0);
  if (total === 0) {
    return <p className="text-sm text-emerald-700">No findings in the latest analysis.</p>;
  }
  return (
    <div className="space-y-2">
      <div
        role="img"
        aria-label={`Findings by severity: ${SEVERITY_ORDER.filter((s) => bySeverity[s]).map((s) => `${bySeverity[s]} ${s}`).join(", ")}`}
        className="flex h-4 overflow-hidden rounded-full bg-slate-100"
      >
        {SEVERITY_ORDER.filter((s) => bySeverity[s] > 0).map((s) => (
          <div
            key={s}
            style={{ width: `${(bySeverity[s] / total) * 100}%`, background: SEVERITY_FILL[s] }}
          />
        ))}
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
        {SEVERITY_ORDER.map((s) => (
          <li key={s} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: SEVERITY_FILL[s] }} />
            {s} <strong className="text-slate-900">{bySeverity?.[s] ?? 0}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}
