import { useState } from "react";

import {
  explainFinding,
  getCopilotStatus,
  getExplanation,
} from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";
import { useAsyncData } from "../../hooks/useAsyncData.js";
import { ACTION_LABELS, describeChange } from "../findings/severity.js";

function SourceBadge({ result }) {
  if (result.source === "meta_model") {
    return (
      <span className="rounded bg-indigo-600 px-2 py-0.5 text-[11px] font-semibold text-white">
        Meta model · {result.model}
      </span>
    );
  }
  if (result.source === "offline_demo") {
    return (
      <span className="rounded bg-slate-200 px-2 py-0.5 text-[11px] font-semibold text-slate-800">
        Offline demo provider — not a Meta model
      </span>
    );
  }
  return (
    <span className="rounded bg-amber-200 px-2 py-0.5 text-[11px] font-semibold text-amber-900">
      Rule-based fallback — model unavailable
    </span>
  );
}

function Result({ result, saved }) {
  const change = result.proposed_change;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SourceBadge result={result} />
        {(saved || result.cached) && (
          <span className="text-[11px] text-slate-500">saved answer</span>
        )}
      </div>
      {result.status === "fallback" && result.fallback_reason && (
        <Notice tone="warning" title="The model did not give a usable answer">
          {result.fallback_reason} Showing a deterministic explanation instead.
        </Notice>
      )}
      <p className="text-sm text-slate-800">{result.explanation}</p>

      <section aria-label="Proposed change">
        <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Proposed change
        </h5>
        {change ? (
          <div className="mt-1 rounded border border-indigo-200 bg-indigo-50 px-3 py-2 text-sm">
            <p className="font-medium text-indigo-900">
              {ACTION_LABELS[change.action]}
            </p>
            <p className="font-mono text-xs text-indigo-900">
              {describeChange(change)}
            </p>
          </div>
        ) : (
          <p className="mt-1 text-sm text-slate-600">
            No safe automatic change could be proposed; a person needs to decide
            the new source.
          </p>
        )}
        <p className="mt-1 text-xs text-slate-500">
          Proposal only — nothing is applied to any cloud account. It must be
          simulated before you rely on it.
        </p>
      </section>

      {result.assumptions.length > 0 && (
        <section aria-label="Assumptions">
          <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Assumptions
          </h5>
          <ul className="mt-1 list-disc pl-5 text-sm text-slate-700">
            {result.assumptions.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </section>
      )}
      {result.uncertainty && (
        <p className="text-xs text-slate-600">
          <span className="font-semibold">Uncertainty:</span>{" "}
          {result.uncertainty}
        </p>
      )}
    </div>
  );
}

export default function CopilotPanel({ finding }) {
  const status = useAsyncData("copilot-status", getCopilotStatus);
  const stored = useAsyncData(finding.id, (signal) =>
    getExplanation(finding.id, signal),
  );
  const [generated, setGenerated] = useState(null); // { result } | { error }
  const [busy, setBusy] = useState(false);

  const result = generated?.result ?? stored.data;
  const error = generated?.error ?? stored.error;

  const run = async (refresh) => {
    setBusy(true);
    setGenerated(null);
    try {
      setGenerated({ result: await explainFinding(finding.id, { refresh }) });
    } catch (e) {
      setGenerated({ error: e });
    } finally {
      setBusy(false);
    }
  };

  const demo = status.data && !status.data.is_meta_model;

  return (
    <section
      aria-label="AI copilot"
      className="space-y-3 border-t border-slate-200 pt-4"
    >
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-900">AI copilot</h4>
        <button
          type="button"
          onClick={() => run(Boolean(result))}
          disabled={busy || stored.loading}
          className="rounded-lg bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          {busy ? "Asking…" : result ? "Ask again" : "Explain with AI"}
        </button>
      </div>
      {demo && (
        <p className="text-xs text-slate-500">
          No Meta API key is configured, so answers come from the offline demo
          provider. Set META_API_KEY and META_MODEL_ID on the backend to use a
          Meta model.
        </p>
      )}
      {error && (
        <Notice tone="error" title="Could not get an explanation">
          {error.message}
        </Notice>
      )}
      {busy && (
        <p role="status" className="text-sm text-slate-500">
          Waiting for the model…
        </p>
      )}
      {result && !busy && <Result result={result} saved={!generated?.result} />}
    </section>
  );
}