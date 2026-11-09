import { useState } from "react";

import { runSimulation } from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";

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
  if (error?.status === 429) {
    return "Too many simulations in a short time. Wait a moment and try again.";
  }
  return error?.message ?? "The simulation failed.";
}

export default function SimulationPanel({ snapshotId, interactionId }) {
  const [state, setState] = useState({ busy: false, data: null, error: null });

  const run = async () => {
    setState({ busy: true, data: null, error: null });
    try {
      const data = await runSimulation(snapshotId, interactionId);
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
          Digital twin simulation
        </h4>
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
      </div>
      <p className="text-xs text-slate-500">
        Runs the proposed change on a copy of this snapshot. No changes are
        applied to any cloud account.
      </p>
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
                {result.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </Notice>
          )}
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
    </section>
  );
}
