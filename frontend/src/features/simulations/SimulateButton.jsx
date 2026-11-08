import { useState } from "react";
import { simulateProposal } from "../../api/workflow";
import BeforeAfterPanel from "./BeforeAfterPanel";

// Drop this under the AI explanation panel for a finding.
// Pass `proposal` from the Copilot response, or leave it undefined to use the stored one.
export default function SimulateButton({ findingId, proposal, onDone }) {
  const [state, setState] = useState({ status: "idle", result: null, error: null });

  async function run() {
    setState({ status: "loading", result: null, error: null });
    try {
      const result = await simulateProposal(findingId, proposal);
      setState({ status: "done", result, error: null });
      onDone?.(result);
    } catch (e) {
      setState({ status: "error", result: null, error: e });
    }
  }

  return (
    <div className="space-y-3">
      <button
        onClick={run}
        disabled={state.status === "loading"}
        className="rounded bg-blue-600 px-4 py-2 text-white disabled:opacity-50"
      >
        {state.status === "loading" ? "Simulating..." : "Simulate this fix"}
      </button>

      {state.status === "error" && (
        <div role="alert" className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">
          {state.error.code === "INVALID_PROPOSAL"
            ? `The AI proposal was rejected by validation: ${state.error.message}`
            : state.error.message}
        </div>
      )}
      <BeforeAfterPanel result={state.result} />
    </div>
  );
}
