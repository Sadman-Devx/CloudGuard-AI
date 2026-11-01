import { useState } from "react";

import { analyzeSnapshot, getFindings, listRules } from "../api/endpoints.js";
import Notice from "../components/Notice.jsx";
import FindingDetail from "../features/findings/FindingDetail.jsx";
import FindingsTable from "../features/findings/FindingsTable.jsx";
import { SEVERITIES } from "../features/findings/severity.js";
import SeverityBadge from "../features/findings/SeverityBadge.jsx";
import { useAsyncData } from "../hooks/useAsyncData.js";
import { useSnapshotSelection } from "../hooks/useSnapshotSelection.js";

export default function FindingsPage({ focus = null }) {
  const {
    projects,
    snapshots,
    projectId,
    snapshotId,
    chooseProject,
    chooseSnapshot,
  } = useSnapshotSelection(focus);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedId, setSelectedId] = useState(null);
  const [fresh, setFresh] = useState(null); // { snapshotId, data } after "Run analysis"
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState(null);

  const stored = useAsyncData(snapshotId, (signal) =>
    getFindings(snapshotId, signal),
  );
  const rules = useAsyncData("rules", listRules);

  const data = fresh?.snapshotId === snapshotId ? fresh.data : stored.data;
  const results = data?.results ?? [];
  const visible =
    severityFilter === "all"
      ? results
      : results.filter((f) => f.severity === severityFilter);
  const selected = results.find((f) => f.id === selectedId) ?? null;
  const ruleById = new Map((rules.data ?? []).map((r) => [r.id, r]));

  const run = async () => {
    setRunning(true);
    setRunError(null);
    try {
      setFresh({ snapshotId, data: await analyzeSnapshot(snapshotId) });
      setSelectedId(null);
    } catch (e) {
      setRunError(e);
    } finally {
      setRunning(false);
    }
  };

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

  const counts = data?.analysis?.summary?.by_severity;

  return (
    <section aria-labelledby="findings-heading" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id="findings-heading" className="text-lg font-semibold">
            Security findings
          </h2>
          <p className="text-sm text-slate-500">
            Deterministic rules SG-001 to SG-006. A finding is a risky rule or a
            potential exposure, not proof that something is reachable or
            exploitable.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <label className="text-sm">
            <span className="block text-xs font-medium text-slate-500">
              Project
            </span>
            <select
              value={projectId ?? ""}
              onChange={(e) => {
                chooseProject(Number(e.target.value));
                setSelectedId(null);
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
            <span className="block text-xs font-medium text-slate-500">
              Snapshot
            </span>
            <select
              value={snapshotId ?? ""}
              onChange={(e) => {
                chooseSnapshot(Number(e.target.value));
                setSelectedId(null);
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
      {stored.error && (
        <Notice tone="error" title="Could not load findings">
          {stored.error.message}
        </Notice>
      )}
      {runError && (
        <Notice tone="error" title="Analysis failed">
          {runError.message}
        </Notice>
      )}

      {snapshotId && (
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={run}
            disabled={running || stored.loading}
            className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
          >
            {running
              ? "Analysing…"
              : data?.analysis
                ? "Re-run analysis"
                : "Run analysis"}
          </button>
          {data?.analysis && (
            <span className="text-xs text-slate-500">
              Rules v{data.analysis.rules_version} ·{" "}
              {data.analysis.summary.total} finding(s)
            </span>
          )}
        </div>
      )}

      {snapshotId && stored.loading && (
        <p role="status" className="text-sm text-slate-500">
          Loading findings…
        </p>
      )}

      {data && !data.analysis && (
        <Notice tone="info" title="Not analysed yet">
          Run the analysis to check this snapshot against rules SG-001 to
          SG-006.
        </Notice>
      )}

      {data?.analysis && (
        <>
          <dl
            aria-label="Findings by severity"
            className="grid grid-cols-5 gap-2"
          >
            {SEVERITIES.map((s) => (
              <div
                key={s}
                className="rounded-lg border border-slate-200 bg-white px-3 py-2"
              >
                <dt>
                  <SeverityBadge severity={s} />
                </dt>
                <dd className="mt-1 text-xl font-semibold text-slate-900">
                  {counts[s]}
                </dd>
              </div>
            ))}
          </dl>

          {results.length === 0 ? (
            <Notice
              tone="success"
              title="No findings from rules SG-001 to SG-006"
            >
              This does not prove the network is secure: only these six
              security-group checks were run, and routes, NACLs and reachability
              are not evaluated here.
            </Notice>
          ) : (
            <>
              <label className="inline-block text-sm">
                <span className="block text-xs font-medium text-slate-500">
                  Severity
                </span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="mt-0.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm"
                >
                  <option value="all">All</option>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </label>
              <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
                <div>
                  {visible.length === 0 ? (
                    <p className="text-sm text-slate-500">
                      No findings with this severity.
                    </p>
                  ) : (
                    <FindingsTable
                      findings={visible}
                      selectedId={selectedId}
                      onSelect={setSelectedId}
                    />
                  )}
                </div>
                {selected ? (
                  <FindingDetail
                    finding={selected}
                    rule={ruleById.get(selected.rule_id)}
                  />
                ) : (
                  <p className="rounded-lg border border-dashed border-slate-300 p-6 text-sm text-slate-500">
                    Select a finding to see its evidence and ask the AI copilot
                    to explain it.
                  </p>
                )}
              </div>
            </>
          )}
        </>
      )}
    </section>
  );
}