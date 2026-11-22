import { useState } from "react";

import { getAttackGraph, getAttackPaths } from "../api/endpoints.js";
import Notice from "../components/Notice.jsx";
import AttackGraphView from "../features/attack-paths/AttackGraphView.jsx";
import BlastRadiusPanel from "../features/attack-paths/BlastRadiusPanel.jsx";
import { edgeKey } from "../features/attack-paths/layout.js";
import PathList from "../features/attack-paths/PathList.jsx";
import WhatIfPanel from "../features/attack-paths/WhatIfPanel.jsx";
import { useAsyncData } from "../hooks/useAsyncData.js";
import { useSnapshotSelection } from "../hooks/useSnapshotSelection.js";

/**
 * Attack paths of an imported snapshot: how an attacker could get from the internet to the
 * sensitive resources, built from the same configuration the rules and the reachability engine use.
 */
export default function AttackPathsPage({ focus = null }) {
  const {
    projects,
    snapshots,
    projectId,
    snapshotId,
    chooseProject,
    chooseSnapshot,
  } = useSnapshotSelection(focus);
  // Choices belong to one snapshot; switching snapshot drops them without an effect.
  const [choice, setChoice] = useState({ snapshotId: null, path: null, node: null });
  const mine = choice.snapshotId === snapshotId ? choice : { path: null, node: null };

  const graph = useAsyncData(snapshotId, (signal) => getAttackGraph(snapshotId, signal));
  const paths = useAsyncData(snapshotId, (signal) => getAttackPaths(snapshotId, {}, signal));

  const loadError = projects.error ?? snapshots.error;
  if (loadError) {
    return (
      <Notice tone="error" title="Could not load data">
        {loadError.message}
      </Notice>
    );
  }
  if (projects.loading) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Loading…
      </p>
    );
  }

  const pathList = paths.data?.paths ?? [];
  const selectedPath = mine.path != null ? (pathList[mine.path] ?? null) : null;
  const highlight = new Set(
    (selectedPath?.edges ?? []).map((e) => edgeKey(e.source, e.target)),
  );
  const warnings = [...(graph.data?.warnings ?? [])];
  if (paths.data?.search?.truncated) {
    warnings.push({
      code: "SEARCH_TRUNCATED",
      message:
        "The path search hit its limit; the ranking shows the best paths found so far.",
    });
  }

  const select = (patch) => setChoice({ snapshotId, ...mine, ...patch });

  return (
    <section aria-labelledby="attack-heading" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id="attack-heading" className="text-lg font-semibold">
            Attack paths
          </h2>
          <p className="text-sm text-slate-500">
            Routes an attacker could take from the internet to sensitive
            databases and buckets, derived from this snapshot. A path is a
            modelled possibility, not proof of a breach.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <label className="text-sm">
            <span className="block text-xs font-medium text-slate-500">Project</span>
            <select
              value={projectId ?? ""}
              onChange={(e) => chooseProject(Number(e.target.value))}
              className="mt-0.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm"
            >
              {(projects.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="block text-xs font-medium text-slate-500">Snapshot</span>
            <select
              value={snapshotId ?? ""}
              onChange={(e) => chooseSnapshot(Number(e.target.value))}
              disabled={!snapshots.data?.length}
              className="mt-0.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm disabled:opacity-50"
            >
              {(snapshots.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  v{s.version} · {s.name || s.source_name || "Unnamed"}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {!projects.data?.length && (
        <Notice tone="info" title="No projects yet">
          Create a project and import a configuration on the Import tab first.
        </Notice>
      )}
      {projectId && snapshots.data && snapshots.data.length === 0 && (
        <Notice tone="info" title="This project has no snapshots yet">
          Import the attack_path_demo sample on the Import tab to see a full
          example.
        </Notice>
      )}
      {(graph.error || paths.error) && (
        <Notice tone="error" title="Could not build the attack graph">
          {(graph.error ?? paths.error).message}
        </Notice>
      )}
      {snapshotId && (graph.loading || paths.loading) && (
        <p role="status" className="text-sm text-slate-500">
          Building the attack graph…
        </p>
      )}
      {warnings.map((w) => (
        <Notice key={w.code} tone="warning">
          {w.message}
        </Notice>
      ))}

      {graph.data && paths.data && (
        <>
          <AttackGraphView
            nodes={graph.data.nodes}
            edges={graph.data.edges}
            highlight={highlight}
            selectedId={mine.node}
            onSelect={(id) => select({ node: id })}
          />
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
            <div className="space-y-2">
              <h3 className="text-sm font-semibold">
                Top attack paths ({pathList.length})
              </h3>
              <PathList
                paths={pathList}
                selectedIndex={mine.path}
                onSelect={(index) => select({ path: index })}
              />
              {paths.data.choke_points?.length > 0 && (
                <p className="text-xs text-slate-500">
                  Choke points (fixing one removes the most risk):{" "}
                  {paths.data.choke_points
                    .slice(0, 3)
                    .map((c) => `${c.name} (${Math.round(c.risk_share * 100)}%)`)
                    .join(", ")}
                </p>
              )}
            </div>
            <div className="space-y-4">
              <BlastRadiusPanel snapshotId={snapshotId} nodeId={mine.node} />
              <WhatIfPanel snapshotId={snapshotId} path={selectedPath} />
            </div>
          </div>
        </>
      )}
    </section>
  );
}
