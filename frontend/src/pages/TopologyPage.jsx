import { useMemo, useState } from "react";

import { getTopology, listProjects, listSnapshots } from "../api/endpoints.js";
import Notice from "../components/Notice.jsx";
import DetailPanel from "../features/topology/DetailPanel.jsx";
import Filters, { Legend } from "../features/topology/Filters.jsx";
import TopologyGraph from "../features/topology/TopologyGraph.jsx";
import { useAsyncData } from "../hooks/useAsyncData.js";

function Stat({ label, value, tone = "default" }) {
  const tones = { default: "text-slate-900", warn: "text-rose-700" };
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className={`text-xl font-semibold ${tones[tone]}`}>{value}</dd>
    </div>
  );
}

/**
 * @param {{focus?: {projectId: number, snapshotId: number} | null}} props
 *   focus: set when the user arrives from the Import screen to open a specific snapshot.
 */
export default function TopologyPage({ focus = null }) {
  // User choices; `null` means "follow the default" (focus, else first project / latest snapshot).
  const [chosenProject, setChosenProject] = useState(null);
  const [chosenSnapshot, setChosenSnapshot] = useState(null);
  const [hiddenTypes, setHiddenTypes] = useState(() => new Set());
  const [selection, setSelection] = useState(null);

  const projects = useAsyncData("projects", listProjects);
  const projectId = chosenProject ?? focus?.projectId ?? projects.data?.[0]?.id ?? null;

  const snapshots = useAsyncData(projectId, (signal) => listSnapshots(projectId, signal));
  const snapshotId =
    chosenSnapshot && snapshots.data?.some((s) => s.id === chosenSnapshot)
      ? chosenSnapshot
      : focus && focus.projectId === projectId && snapshots.data?.some((s) => s.id === focus.snapshotId)
        ? focus.snapshotId
        : (snapshots.data?.[0]?.id ?? null);

  const topology = useAsyncData(snapshotId, (signal) => getTopology(snapshotId, signal));

  const toggleType = (type) =>
    setHiddenTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  const summary = topology.data?.summary;
  const oneSided = summary?.one_sided_sg_flows ?? [];
  const names = useMemo(() => new Map((topology.data?.nodes ?? []).map((n) => [n.id, n.label])), [topology.data]);

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

  return (
    <section aria-labelledby="topology-heading" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id="topology-heading" className="text-lg font-semibold">
            Network topology
          </h2>
          <p className="text-sm text-slate-500">
            Shows how the imported configuration is wired together. It does not prove that any path is reachable.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <label className="text-sm">
            <span className="block text-xs font-medium text-slate-500">Project</span>
            <select
              value={projectId ?? ""}
              onChange={(e) => {
                setChosenProject(Number(e.target.value));
                setChosenSnapshot(null);
                setSelection(null);
              }}
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
              onChange={(e) => {
                setChosenSnapshot(Number(e.target.value));
                setSelection(null);
              }}
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
          Import a sample or upload a configuration on the Import tab.
        </Notice>
      )}
      {topology.loading && (
        <p role="status" className="text-sm text-slate-500">
          Building topology…
        </p>
      )}
      {topology.error && (
        <Notice tone="error" title="Could not build the topology">
          {topology.error.message}
        </Notice>
      )}

      {topology.data && (
        <>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Resources" value={summary.node_count} />
            <Stat label="Public subnets" value={summary.public_subnets.length} />
            <Stat label="Instances with public IP" value={summary.instances_with_public_ip.length} />
            <Stat label="One-sided SG rules" value={oneSided.length} tone={oneSided.length ? "warn" : "default"} />
          </dl>

          {oneSided.length > 0 && (
            <Notice tone="warning" title="One-sided security-group rules">
              <ul className="list-disc pl-5">
                {oneSided.map((flow) => {
                  const [from, to] = flow.split("->");
                  return (
                    <li key={flow}>
                      {names.get(from) ?? from} → {names.get(to) ?? to}: only one side declares the rule.
                    </li>
                  );
                })}
              </ul>
            </Notice>
          )}
          {topology.data.issues.length > 0 && (
            <Notice tone="warning" title={`${topology.data.issues.length} reference problem(s) in this snapshot`}>
              <ul className="list-disc pl-5">
                {topology.data.issues.map((issue, i) => (
                  <li key={i}>{issue.message}</li>
                ))}
              </ul>
            </Notice>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <Filters hiddenTypes={hiddenTypes} onToggle={toggleType} />
            <Legend />
          </div>

          <div className="grid gap-4 xl:grid-cols-[1fr_300px]">
            <TopologyGraph topology={topology.data} hiddenTypes={hiddenTypes} selection={selection} onSelect={setSelection} />
            <DetailPanel
              topology={topology.data}
              selection={selection}
              onSelect={setSelection}
              onClear={() => setSelection(null)}
            />
          </div>
        </>
      )}
    </section>
  );
}