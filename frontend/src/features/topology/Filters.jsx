import { FILTERABLE_TYPES, TYPE_LABELS } from "./layout.js";

export default function Filters({ hiddenTypes, onToggle }) {
  return (
    <fieldset className="flex flex-wrap items-center gap-x-4 gap-y-1">
      <legend className="sr-only">Show resource types</legend>
      <span className="text-xs font-medium uppercase tracking-wide text-slate-500">Show</span>
      {FILTERABLE_TYPES.map((type) => (
        <label key={type} className="flex items-center gap-1.5 text-sm text-slate-700">
          <input type="checkbox" checked={!hiddenTypes.has(type)} onChange={() => onToggle(type)} />
          {TYPE_LABELS[type]}s
        </label>
      ))}
    </fieldset>
  );
}

export function Legend() {
  const items = [
    ["border-l-sky-500", "Internet / gateway"],
    ["border-l-amber-500", "Route table"],
    ["border-l-emerald-500", "Subnet"],
    ["border-l-violet-500", "Network ACL"],
    ["border-l-indigo-500", "Instance"],
    ["border-l-rose-400", "Security group"],
  ];
  return (
    <ul aria-label="Legend" className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
      {items.map(([accent, label]) => (
        <li key={label} className="flex items-center gap-1.5">
          <span className={`inline-block h-3 w-3 rounded-sm border border-l-4 border-slate-300 ${accent}`} />
          {label}
        </li>
      ))}
      <li className="flex items-center gap-1.5">
        <span className="inline-block w-6 border-t-2 border-dashed border-rose-600" />
        One-sided security-group rule
      </li>
    </ul>
  );
}