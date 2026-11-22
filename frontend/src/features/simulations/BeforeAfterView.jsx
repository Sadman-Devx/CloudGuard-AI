/**
 * Side-by-side view of what a simulated change does: the rule that changes (old on the left, new on
 * the right), the findings, and every path whose verdict flips. Pure display of the simulation result.
 */
import { describeRule } from "./describeRule.js";

const VERDICT = {
  lost: ["allowed", "blocked"],
  newly_allowed: ["blocked", "allowed"],
  preserved: ["allowed", "allowed"],
  still_allowed: ["allowed", "allowed"],
  still_blocked: ["blocked", "blocked"],
};

function Verdict({ value }) {
  const tone =
    value === "allowed"
      ? "bg-red-50 text-red-800"
      : value === "blocked"
        ? "bg-emerald-50 text-emerald-800"
        : "bg-slate-100 text-slate-600";
  return <span className={`rounded px-1.5 py-0.5 text-xs ${tone}`}>{value}</span>;
}

function RuleCell({ rule, kind }) {
  if (!rule) {
    return (
      <span className="text-xs italic text-slate-400">
        {kind === "removed" ? "removed" : "nothing here yet"}
      </span>
    );
  }
  const tone =
    kind === "removed"
      ? "border-red-200 bg-red-50 text-red-900 line-through decoration-red-400"
      : kind === "added"
        ? "border-emerald-200 bg-emerald-50 text-emerald-900"
        : "border-slate-200 bg-white text-slate-800";
  return (
    <code className={`block rounded border px-2 py-1 text-xs ${tone}`}>
      {describeRule(rule)}
    </code>
  );
}

export default function BeforeAfterView({ result, score }) {
  const mods = result?.modifications ?? [];
  const flips = (result?.connectivity ?? []).filter(
    (c) => c.required || c.change === "lost" || c.change === "newly_allowed",
  );
  if (mods.length === 0 && flips.length === 0) return null;
  const before = result.findings?.before_summary;
  const after = result.findings?.after_summary;

  return (
    <section aria-label="Before and after" className="space-y-3 rounded-lg border border-slate-200 p-3">
      <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        What changes, side by side
      </h5>

      {mods.length > 0 && (
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2 text-xs font-semibold text-slate-600">
            <span>Before this change</span>
            <span>After this change</span>
          </div>
          {mods.map((mod, index) => (
            <div key={`${mod.security_group}-${mod.network_acl ?? ""}-${mod.index}-${index}`}>
              <p className="mb-1 text-xs text-slate-500">
                {mod.network_acl ?? mod.security_group} ·{" "}
                {mod.direction ?? "ingress"}
                {mod.note ? ` · ${mod.note}` : ""}
              </p>
              <div className="grid grid-cols-2 gap-2">
                <RuleCell rule={mod.before} kind={mod.before ? "removed" : "none"} />
                <RuleCell rule={mod.after} kind={mod.after ? "added" : "removed"} />
              </div>
            </div>
          ))}
        </div>
      )}

      {before && after && (
        <div className="grid grid-cols-2 gap-2 text-sm">
          <p>
            <span className="text-slate-500">Findings </span>
            <strong>{before.total}</strong>
            {score?.before && (
              <span className="text-slate-500">
                {" "}
                · score {score.before.value} ({score.before.grade})
              </span>
            )}
          </p>
          <p>
            <span className="text-slate-500">Findings </span>
            <strong>{after.total}</strong>
            {score?.after && (
              <span className="text-slate-500">
                {" "}
                · score {score.after.value} ({score.after.grade})
              </span>
            )}
          </p>
        </div>
      )}

      {flips.length > 0 && (
        <div>
          <div className="grid grid-cols-[1fr_auto_auto] items-center gap-x-3 gap-y-1 text-sm">
            <span className="text-xs font-semibold text-slate-600">Path</span>
            <span className="text-xs font-semibold text-slate-600">Before</span>
            <span className="text-xs font-semibold text-slate-600">After</span>
            {flips.map((c) => {
              const [was, now] = VERDICT[c.change] ?? ["?", "?"];
              return [
                <span key={`${c.key}-l`} className="text-slate-800">
                  {c.label}
                  {c.required ? " (required)" : ""}
                </span>,
                <Verdict key={`${c.key}-b`} value={was} />,
                <Verdict key={`${c.key}-a`} value={now} />,
              ];
            })}
          </div>
        </div>
      )}
    </section>
  );
}
