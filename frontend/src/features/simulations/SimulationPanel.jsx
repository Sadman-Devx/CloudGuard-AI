import { useState } from "react";

import { runSimulation } from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";
import TwinSlider from "../score/TwinSlider.jsx";

const OUTCOMES = {
  improves_security: {
    label: "Improves security",
    cls: "bg-emerald-100 text-emerald-900",
  },
  no_effect: { label: "No effect", cls: "bg-slate-200 text-slate-800" },
  introduces_new_risk: {
    label: "Introduces new risk",
    cls: "bg-amber-200 text-amber-900",
  },
  breaks_required_connectivity: {
    label: "Breaks required connectivity",
    cls: "bg-red-200 text-red-900",
  },
  required_connectivity_unmet: {
    label: "Required connectivity not met",
    cls: "bg-amber-200 text-amber-900",
  },
  inconclusive: { label: "Inconclusive", cls: "bg-amber-200 text-amber-900" },
};

const CHANGES = {
  lost: "now blocked",
  newly_allowed: "newly allowed",
  still_allowed: "unchanged (allowed)",
  still_blocked: "unchanged (blocked)",
  inconclusive: "could not be determined",
};

function FindingList({ title, items }) {
  if (!items?.length) return null;
  return (
    <div>
      <h6 className="text-xs font-semibold text-slate-600">{title}</h6>
      <ul className="list-disc pl-5 text-sm text-slate-700">
        {items.map((f) => (
          <li key={`${f.rule_id}-${f.resource_id}`}>
            {f.rule_id} · {f.resource_id} — {f.title}
          </li>
        ))}
      </ul>
    </div>
  );
}

function describeSimulationError(error) {
  const details = error?.details;
  const messages = Array.isArray(details)
    ? details.map((item) => item?.message ?? String(item))
    : Object.values(details ?? {}).flat();
  const detailText = messages.filter((item) => typeof item === "string").join(" ");
  if (error?.status === 429) {
    return "Too many simulations in a short time. Wait a moment and try again.";
  }
  return [error?.message ?? "The simulation failed.", detailText]
    .filter(Boolean)
    .join(" ");
}

export default function SimulationPanel({
  snapshotId,
  interactionId,
  finding,
}) {
  const [state, setState] = useState({ busy: false, data: null, error: null });
  const [expanded, setExpanded] = useState(true);
  const [action, setAction] = useState("restrict_ingress_cidr");
  const [source, setSource] = useState("");
  const rules =
    finding?.evidence?.matching_rules?.filter(
      (rule) => rule.direction === "ingress" && rule.cidr === "0.0.0.0/0",
    ) ?? [];
  const [ruleKey, setRuleKey] = useState("");
  const selectedRule =
    rules.find((rule) => `${rule.direction}-${rule.index}` === ruleKey) ??
    rules[0];
  const manual = Boolean(finding && !interactionId);

  const run = async () => {
    setState({ busy: true, data: null, error: null });
    try {
      const proposedChange =
        manual && selectedRule
          ? {
              action,
              security_group_id: finding.resource_id,
              protocol: selectedRule.protocol,
              ...(selectedRule.protocol === "-1"
                ? {}
                : {
                    from_port: selectedRule.from_port,
                    to_port: selectedRule.to_port,
                  }),
              new_source_security_group_id:
                action === "replace_ingress_source" ? source : null,
              new_cidr: action === "restrict_ingress_cidr" ? source : null,
            }
          : null;
      const data = await runSimulation(snapshotId, {
        interactionId,
        proposedChange,
        findingId: finding?.id,
      });
      setState({ busy: false, data, error: null });
    } catch (error) {
      setState({ busy: false, data: null, error });
    }
  };

  const { busy, data, error } = state;
  const result = data?.result;
  const outcome = OUTCOMES[data?.outcome] ?? OUTCOMES.inconclusive;

  return (
    <section
      aria-label="Simulation"
      className="space-y-3 border-t border-slate-200 pt-4"
    >
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-900">
          {manual ? "Manual digital twin simulation" : "Digital twin simulation"}
        </h4>
        <div className="flex items-center gap-2">
          <button
            type="button"
            aria-expanded={expanded}
            onClick={() => setExpanded((visible) => !visible)}
            className="text-xs font-medium text-indigo-700 hover:text-indigo-900"
          >
            {expanded ? "Collapse" : "Expand"}
          </button>
          {!manual && (
            <button
              type="button"
              onClick={run}
              disabled={busy}
              className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-900 disabled:opacity-50"
            >
              {busy
                ? "Simulating…"
                : data
                  ? "Simulate again"
                  : "Simulate this change"}
            </button>
          )}
        </div>
      </div>
      {expanded && (
        <>
          <p className="text-xs text-slate-500">
            {manual
              ? "Choose a change based on your intended access. The API validates it against this snapshot; nothing is applied to a cloud account."
              : "Runs the proposed change on a copy of this snapshot. No changes are applied to any cloud account."}
          </p>
          {manual && (
            <form
              className="space-y-3 rounded-lg border border-slate-200 bg-white p-3"
              onSubmit={(event) => {
                event.preventDefault();
                run();
              }}
            >
              {rules.length ? (
                <>
                  {rules.length > 1 && (
                    <label className="block text-sm">
                      <span className="mb-1 block text-xs font-medium text-slate-600">
                        Internet-open ingress rule
                      </span>
                      <select
                        value={ruleKey || `${selectedRule.direction}-${selectedRule.index}`}
                        onChange={(event) => setRuleKey(event.target.value)}
                        className="w-full rounded border border-slate-300 px-2 py-1.5"
                      >
                        {rules.map((rule) => (
                          <option
                            key={`${rule.direction}-${rule.index}`}
                            value={`${rule.direction}-${rule.index}`}
                          >
                            {rule.protocol}/{rule.from_port}-{rule.to_port} · rule #
                            {rule.index + 1}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  <label className="block text-sm">
                    <span className="mb-1 block text-xs font-medium text-slate-600">
                      Proposed change
                    </span>
                    <select
                      value={action}
                      onChange={(event) => setAction(event.target.value)}
                      className="w-full rounded border border-slate-300 px-2 py-1.5"
                    >
                      <option value="restrict_ingress_cidr">
                        Restrict to an IPv4 CIDR
                      </option>
                      <option value="replace_ingress_source">
                        Allow a security group
                      </option>
                      <option value="remove_ingress_rule">
                        Remove the ingress rule
                      </option>
                    </select>
                  </label>
                  {action !== "remove_ingress_rule" && (
                    <label className="block text-sm">
                      <span className="mb-1 block text-xs font-medium text-slate-600">
                        {action === "restrict_ingress_cidr"
                          ? "Trusted IPv4 CIDR"
                          : "Source security group ID"}
                      </span>
                      <input
                        required
                        value={source}
                        onChange={(event) => setSource(event.target.value)}
                        placeholder={
                          action === "restrict_ingress_cidr"
                            ? "For example, 10.0.1.0/24"
                            : "For example, sg-app"
                        }
                        className="w-full rounded border border-slate-300 px-2 py-1.5"
                      />
                    </label>
                  )}
                  <button
                    type="submit"
                    disabled={busy || !selectedRule}
                    className="rounded-lg bg-slate-800 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-900 disabled:opacity-50"
                  >
                    {busy
                      ? "Simulating…"
                      : data
                        ? "Simulate again"
                        : "Simulate this change"}
                  </button>
                </>
              ) : (
                <p className="text-sm text-slate-600">
                  No internet-open ingress rule was found in this finding to
                  simulate.
                </p>
              )}
            </form>
          )}
          {error && (
            <Notice tone="error" title="Could not run the simulation">
              {describeSimulationError(error)}
            </Notice>
          )}
          {data && result && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded px-2 py-0.5 text-[11px] font-semibold ${outcome.cls}`}
                >
                  {outcome.label}
                </span>
                <span className="text-xs text-slate-600">
                  {data.recommended
                    ? "Recommended"
                    : "Not recommended without review"}
                </span>
              </div>
              {result.summary_lines?.length > 0 && (
                <ul className="list-disc pl-5 text-sm text-slate-800">
                  {result.summary_lines.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              )}
              {result.warnings?.length > 0 && (
                <Notice tone="warning" title="Warnings">
                  <ul className="list-disc pl-5">
                    {result.warnings.map((warning) => (
                      <li key={warning.code}>{warning.message}</li>
                    ))}
                  </ul>
                </Notice>
              )}
              <TwinSlider score={data.score} findings={result.findings} />
              <p className="text-sm text-slate-700">
                Findings: {result.findings.before_summary.total} before →{" "}
                {result.findings.after_summary.total} after
              </p>
              <FindingList title="Resolved" items={result.findings.resolved} />
              <FindingList title="Still open" items={result.findings.remaining} />
              <FindingList
                title="Newly introduced"
                items={result.findings.introduced}
              />
              {result.connectivity?.length > 0 && (
                <div>
                  <h6 className="text-xs font-semibold text-slate-600">
                    Connectivity checked
                  </h6>
                  <ul className="space-y-1 text-sm text-slate-700">
                    {result.connectivity.map((c) => (
                      <li key={c.key}>
                        {c.label}: {CHANGES[c.change] ?? c.change}
                        {c.required ? " (required)" : ""}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}