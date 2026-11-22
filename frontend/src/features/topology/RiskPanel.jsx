import { SEVERITY_LABEL } from "./riskOverlay.js";

const TONE = {
  critical: "bg-red-700 text-white",
  high: "bg-red-100 text-red-900",
  medium: "bg-amber-100 text-amber-900",
  low: "bg-sky-100 text-sky-900",
  info: "bg-slate-200 text-slate-800",
};

const STATUS_TEXT = { pass: "passed", fail: "blocked", unknown: "unknown", info: "note" };

export function Severity({ value }) {
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${TONE[value] ?? TONE.info}`}
    >
      {SEVERITY_LABEL[value] ?? value}
    </span>
  );
}

/** Why things are red: the internet paths, and the reasons behind the selected resource. */
export default function RiskPanel({
  risk,
  names,
  selection,
  activePathId,
  onSelectPath,
}) {
  const nodeEntry = selection?.kind === "node" ? risk.nodes?.[selection.id] : null;
  const activePath = risk.paths.find((p) => p.id === activePathId) ?? null;
  const label = (id) => names.get(id) ?? id;

  return (
    <aside
      aria-label="Risk details"
      className="space-y-3 rounded-xl border border-red-200 bg-white p-4 text-sm"
    >
      <div>
        <h3 className="font-semibold text-slate-900">Risk overlay</h3>
        <p className="text-xs text-slate-500">
          {risk.summary.risky_nodes} resource(s) flagged,{" "}
          {risk.summary.verified_paths} verified internet path(s). A path is a
          modelled possibility from the configuration, not proof of a breach.
        </p>
      </div>

      {risk.paths.length === 0 ? (
        <p className="text-slate-600">
          No instance with a public IP is reachable from the internet through a
          risky rule.
        </p>
      ) : (
        <ul aria-label="Internet paths" className="space-y-1">
          {risk.paths.map((path) => (
            <li key={path.id}>
              <button
                type="button"
                aria-pressed={activePathId === path.id}
                onClick={() => onSelectPath(activePathId === path.id ? null : path.id)}
                className={`w-full rounded-lg border px-2 py-1.5 text-left ${
                  activePathId === path.id
                    ? "border-red-400 bg-red-50"
                    : "border-slate-200 hover:border-slate-400"
                }`}
              >
                <span className="flex items-center gap-2">
                  <Severity value={path.severity} />
                  <span className="font-medium">{path.title.replace("->", "→")}</span>
                </span>
                <span className="block text-xs text-slate-500">
                  {path.verified ? "verified reachable" : "reachability unverified"}
                  {path.rule_ids.length ? ` · ${path.rule_ids.join(", ")}` : ""}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {activePath && (
        <div aria-label="Path trace" className="space-y-2 border-t border-slate-200 pt-3">
          <p className="text-slate-800">{activePath.explanation}</p>
          <p className="text-xs text-slate-500">
            {activePath.steps.map(label).join(" → ")}
          </p>
          <ol className="space-y-1">
            {activePath.trace.map((step, index) => (
              <li key={`${step.check}-${index}`} className="text-xs text-slate-700">
                <span className="font-semibold">{step.check}</span>{" "}
                <span className="text-slate-500">
                  ({STATUS_TEXT[step.status] ?? step.status})
                </span>
                : {step.detail}
              </li>
            ))}
          </ol>
          {activePath.assumptions.length > 0 && (
            <p className="text-xs text-slate-500">
              Assumes: {activePath.assumptions.join(" ")}
            </p>
          )}
        </div>
      )}

      {nodeEntry && (
        <div aria-label="Why this resource is flagged" className="space-y-2 border-t border-slate-200 pt-3">
          <h4 className="font-semibold">
            Why {label(selection.id)} is flagged
          </h4>
          <ul className="space-y-1.5">
            {nodeEntry.reasons.map((reason, index) => (
              <li key={`${reason.rule_id}-${reason.via ?? ""}-${index}`}>
                <span className="flex items-center gap-2">
                  <Severity value={reason.severity} />
                  <span className="font-medium">{reason.title}</span>
                </span>
                {reason.via && (
                  <span className="block text-xs text-slate-500">
                    through security group {label(reason.via)}
                  </span>
                )}
                <span className="block text-xs text-slate-600">{reason.text}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </aside>
  );
}
