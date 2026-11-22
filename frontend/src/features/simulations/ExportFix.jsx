import { useState } from "react";

import { getSimulationExport } from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";

const FORMATS = [
  ["aws-cli", "AWS CLI script"],
  ["terraform", "Terraform patch"],
  ["pr", "Pull request text"],
];

/**
 * Fix as code: the verified change rendered for a person to review and apply. CloudGuard only
 * produces text; it never runs it and never changes a cloud account.
 */
export default function ExportFix({ simulationId }) {
  const [state, setState] = useState({ format: null, loading: false, error: null, out: null });
  const [copied, setCopied] = useState(false);

  if (!simulationId) return null;

  const load = async (format) => {
    setCopied(false);
    setState({ format, loading: true, error: null, out: null });
    try {
      const out = await getSimulationExport(simulationId, format);
      setState({ format, loading: false, error: null, out });
    } catch (error) {
      setState({ format, loading: false, error, out: null });
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(state.out.content);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const download = () => {
    const blob = new Blob([state.out.content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = state.out.filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section aria-label="Export this fix" className="space-y-2 rounded-lg border border-slate-200 p-3">
      <h5 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        Export this fix as code
      </h5>
      <div className="flex flex-wrap gap-2">
        {FORMATS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            aria-pressed={state.format === id}
            onClick={() => load(id)}
            className={`rounded-lg border px-3 py-1.5 text-sm ${
              state.format === id
                ? "border-slate-900 bg-slate-900 text-white"
                : "border-slate-300 bg-white text-slate-700 hover:bg-slate-50"
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      {state.loading && (
        <p role="status" className="text-sm text-slate-500">
          Preparing…
        </p>
      )}
      {state.error && (
        <Notice tone="error" title="Could not export this simulation">
          {state.error.message}
        </Notice>
      )}
      {state.out && (
        <div className="space-y-2">
          {state.out.warnings.map((w) => (
            <Notice key={w} tone="warning">
              {w}
            </Notice>
          ))}
          <pre
            aria-label="Exported fix"
            className="max-h-72 overflow-auto rounded-lg bg-slate-900 p-3 text-xs leading-relaxed text-slate-100"
          >
            {state.out.content}
          </pre>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={copy}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button
              type="button"
              onClick={download}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
            >
              Download {state.out.filename}
            </button>
          </div>
          <p className="text-xs text-slate-500">
            Verified on a digital twin only. Review it, then apply it through your
            normal change process.
          </p>
        </div>
      )}
    </section>
  );
}
