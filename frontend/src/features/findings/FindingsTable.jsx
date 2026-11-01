import { CATEGORY_LABELS } from "./severity.js";
import SeverityBadge from "./SeverityBadge.jsx";

export default function FindingsTable({ findings, selectedId, onSelect }) {
  return (
    <ul
      aria-label="Findings"
      className="divide-y divide-slate-200 overflow-hidden rounded-lg border border-slate-200 bg-white"
    >
      {findings.map((f) => (
        <li key={f.id}>
          <button
            type="button"
            onClick={() => onSelect(f.id)}
            aria-pressed={selectedId === f.id}
            className={`flex w-full items-start gap-3 px-3 py-2.5 text-left hover:bg-slate-50 ${
              selectedId === f.id ? "bg-indigo-50" : ""
            }`}
          >
            <span className="w-20 shrink-0 pt-0.5">
              <SeverityBadge severity={f.severity} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium text-slate-900">
                <span className="font-mono text-xs text-slate-500">
                  {f.rule_id}
                </span>{" "}
                {f.title}
              </span>
              <span className="block truncate text-xs text-slate-500">
                {f.resource_name || f.resource_id} ({f.resource_id}) ·{" "}
                {CATEGORY_LABELS[f.category] ?? f.category}
              </span>
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}