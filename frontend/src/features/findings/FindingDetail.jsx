import CopilotPanel from "../copilot/CopilotPanel.jsx";
import {
  CATEGORY_LABELS,
  EXPOSURE_LABELS,
  describeRuleEntry,
} from "./severity.js";
import SeverityBadge from "./SeverityBadge.jsx";

export default function FindingDetail({ finding, rule }) {
  const context = finding.evidence.context;
  return (
    <aside
      aria-label="Finding details"
      className="space-y-4 rounded-lg border border-slate-200 bg-white p-4"
    >
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="font-mono text-xs text-slate-500">
            {finding.rule_id}
          </span>
          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600">
            {CATEGORY_LABELS[finding.category] ?? finding.category}
          </span>
        </div>
        <h3 className="mt-2 text-base font-semibold text-slate-900">
          {finding.title}
        </h3>
        <p className="mt-1 text-sm text-slate-700">{finding.summary}</p>
      </div>

      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-sm">
        <dt className="text-slate-500">Affected</dt>
        <dd>
          Security group{" "}
          <span className="font-medium">
            {finding.resource_name || finding.resource_id}
          </span>{" "}
          <span className="font-mono text-xs text-slate-500">
            ({finding.resource_id})
          </span>
        </dd>
        <dt className="text-slate-500">Exposure context</dt>
        <dd>{EXPOSURE_LABELS[context.exposure] ?? context.exposure}</dd>
        {context.attached_instances.length > 0 && (
          <>
            <dt className="text-slate-500">Attached to</dt>
            <dd>
              {context.attached_instances
                .map(
                  (i) =>
                    `${i.name} (${i.has_public_ip ? "public IP" : "no public IP"}, ${i.subnet_kind ?? "unknown"} subnet)`,
                )
                .join("; ")}
            </dd>
          </>
        )}
      </dl>

      <section aria-label="Evidence">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Evidence
        </h4>
        <ul className="mt-1 space-y-1 text-sm">
          {finding.evidence.matching_rules.map((m) => (
            <li
              key={`${m.direction}-${m.index}`}
              className="rounded bg-slate-50 px-2 py-1 font-mono text-xs"
            >
              {describeRuleEntry(m)}
              {m.description ? (
                <span className="font-sans text-slate-500">
                  {" "}
                  — {m.description}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      </section>

      <section aria-label="Recommended action">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Recommended action
        </h4>
        <p className="mt-1 text-sm text-slate-800">{finding.remediation}</p>
      </section>

      {rule && (
        <section aria-label="Limitations">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            What this does not tell you
          </h4>
          <p className="mt-1 text-xs text-slate-600">{rule.limitations}</p>
        </section>
      )}

      <CopilotPanel key={finding.id} finding={finding} />
    </aside>
  );
}