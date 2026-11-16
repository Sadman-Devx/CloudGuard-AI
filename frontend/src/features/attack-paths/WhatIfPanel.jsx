import { useState } from "react";

import { simulateAttackFix } from "../../api/endpoints.js";
import Notice from "../../components/Notice.jsx";

/**
 * "What if this hop were blocked?" Removes one edge of the selected path from a copy of the graph.
 * For a real security-group change use the Findings tab (copilot proposal + Before/After slider).
 */
export default function WhatIfPanel({ snapshotId, path }) {
  const [edgeIndex, setEdgeIndex] = useState(0);
  const [state, setState] = useState({ pathKey: null, result: null, error: null });
  const [busy, setBusy] = useState(false);

  const pathKey = path ? path.node_ids.join(">") : null;
  const current = state.pathKey === pathKey ? state : { result: null, error: null };

  if (!path) return null;
  const edge = path.edges[Math.min(edgeIndex, path.edges.length - 1)];
  const nameOf = (id) => path.nodes.find((n) => n.id === id)?.name ?? id;

  const run = async () => {
    setBusy(true);
    try {
      const result = await simulateAttackFix(snapshotId, {
        remove_edges: [[edge.source, edge.target]],
      });
      setState({ pathKey, result, error: null });
    } catch (error) {
      setState({ pathKey, result: null, error });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section
      aria-label="What if"
      className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm"
    >
      <h3 className="font-semibold">What if this hop were blocked?</h3>
      <label className="block">
        <span className="block text-xs font-medium text-slate-500">Hop to block</span>
        <select
          value={Math.min(edgeIndex, path.edges.length - 1)}
          onChange={(e) => setEdgeIndex(Number(e.target.value))}
          className="mt-0.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm"
        >
          {path.edges.map((e, i) => (
            <option key={`${e.source}>${e.target}`} value={i}>
              {nameOf(e.source)} → {nameOf(e.target)}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        onClick={run}
        disabled={busy}
        className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
      >
        {busy ? "Simulating…" : "Simulate"}
      </button>
      {current.error && (
        <Notice tone="error" title="Simulation failed">
          {current.error.message}
        </Notice>
      )}
      {current.result && (
        <p role="status">
          Total attack risk {current.result.risk_before} →{" "}
          <strong>{current.result.risk_after}</strong> (
          {current.result.risk_reduction_pct}% lower),{" "}
          {current.result.paths_before} → {current.result.paths_after} path(s).
          Nothing was changed in your cloud account.
        </p>
      )}
    </section>
  );
}
