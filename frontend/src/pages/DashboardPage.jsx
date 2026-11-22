import { useState } from "react";

import {
  getDashboard,
  getProjectDashboard,
  refreshProjectDashboard,
} from "../api/endpoints.js";
import Notice from "../components/Notice.jsx";
import ScoreRing from "../features/dashboard/ScoreRing.jsx";
import SeverityBars from "../features/dashboard/SeverityBars.jsx";
import Sparkline from "../features/dashboard/Sparkline.jsx";
import TrendChart from "../features/dashboard/TrendChart.jsx";
import { Severity } from "../features/topology/RiskPanel.jsx";
import { useAsyncData } from "../hooks/useAsyncData.js";

function Delta({ value }) {
  if (value == null) return <span className="text-xs text-slate-400">first analysis</span>;
  if (value === 0) return <span className="text-xs text-slate-500">no change</span>;
  const up = value > 0;
  return (
    <span className={`text-xs font-medium ${up ? "text-emerald-700" : "text-red-700"}`}>
      {up ? "▲" : "▼"} {Math.abs(value)} since the previous snapshot
    </span>
  );
}

function ProjectCard({ project, onOpen }) {
  const latest = project.latest;
  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(project.id)}
        className="flex w-full items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 text-left shadow-sm hover:border-slate-400"
      >
        {latest ? (
          <ScoreRing value={latest.score} grade={latest.grade} size={72} />
        ) : (
          <div className="flex h-[72px] w-[72px] items-center justify-center rounded-full border-2 border-dashed border-slate-300 text-xs text-slate-400">
            n/a
          </div>
        )}
        <div className="min-w-0 flex-1">
          <p className="truncate font-semibold text-slate-900">{project.name}</p>
          <p className="text-xs text-slate-500">
            {project.snapshot_count} snapshot{project.snapshot_count === 1 ? "" : "s"}
            {latest ? ` · ${latest.total} finding${latest.total === 1 ? "" : "s"}` : " · not analysed yet"}
          </p>
          {latest && <Delta value={project.delta} />}
        </div>
        <Sparkline points={project.trend} />
      </button>
    </li>
  );
}

function ProjectDetail({ projectId, onBack }) {
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(null);
  const detail = useAsyncData(`${projectId}:${reload}`, (signal) =>
    getProjectDashboard(projectId, signal),
  );

  const analyseAll = async () => {
    setBusy(true);
    try {
      setRefresh(await refreshProjectDashboard(projectId));
    } catch (error) {
      setRefresh({ error });
    } finally {
      setBusy(false);
      setReload((n) => n + 1);
    }
  };

  if (detail.error) {
    return (
      <Notice tone="error" title="Could not load this project">
        {detail.error.message}
      </Notice>
    );
  }
  if (!detail.data) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Loading…
      </p>
    );
  }
  const d = detail.data;
  const latest = d.latest;

  return (
    <div className="space-y-5">
      <button type="button" onClick={onBack} className="text-sm text-slate-600 underline">
        ← All projects
      </button>
      <div className="flex flex-wrap items-center gap-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        {latest ? (
          <ScoreRing value={latest.score} grade={latest.grade} size={120} />
        ) : (
          <p className="text-sm text-slate-500">No analysed snapshot yet.</p>
        )}
        <div className="space-y-1">
          <h3 className="text-lg font-semibold">{d.name}</h3>
          {latest && (
            <>
              <p className="text-sm text-slate-600">
                Latest: v{latest.version} · {latest.total} finding{latest.total === 1 ? "" : "s"}
              </p>
              <Delta value={d.delta} />
            </>
          )}
          <p className="text-xs text-slate-500">
            {d.fixes.simulations} simulated fix{d.fixes.simulations === 1 ? "" : "es"},{" "}
            {d.fixes.recommended} recommended
          </p>
        </div>
        {d.unanalyzed_count > 0 && (
          <div className="ml-auto text-right">
            <p className="text-xs text-slate-500">
              {d.unanalyzed_count} snapshot{d.unanalyzed_count === 1 ? "" : "s"} not analysed
            </p>
            <button
              type="button"
              onClick={analyseAll}
              disabled={busy}
              className="mt-1 rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {busy ? "Analysing…" : "Analyse them now"}
            </button>
          </div>
        )}
      </div>

      {refresh?.error && (
        <Notice tone="error" title="Could not analyse">
          {refresh.error.message}
        </Notice>
      )}
      {refresh && !refresh.error && (
        <Notice tone="info">
          Analysed {refresh.analyzed} snapshot(s)
          {refresh.skipped.length ? `, skipped ${refresh.skipped.length} (incompatible)` : ""}
          {refresh.remaining ? `; ${refresh.remaining} more remain, run it again` : ""}.
        </Notice>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <section aria-label="Score trend" className="rounded-xl border border-slate-200 bg-white p-4">
          <h4 className="mb-2 text-sm font-semibold">Score over time</h4>
          <TrendChart points={d.trend} />
        </section>
        <section aria-label="Severity mix" className="space-y-4 rounded-xl border border-slate-200 bg-white p-4">
          <div>
            <h4 className="mb-2 text-sm font-semibold">Findings by severity (latest)</h4>
            <SeverityBars bySeverity={latest?.by_severity} />
          </div>
          {d.top_rules.length > 0 && (
            <div>
              <h4 className="mb-1 text-sm font-semibold">Rules causing most findings</h4>
              <ul className="space-y-0.5 text-sm">
                {d.top_rules.map((r) => (
                  <li key={r.rule_id} className="flex justify-between gap-2">
                    <span>
                      <span className="font-mono text-xs">{r.rule_id}</span> {r.title}
                    </span>
                    <strong>{r.count}</strong>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      </div>

      {d.worst_resources.length > 0 && (
        <section aria-label="Worst findings" className="rounded-xl border border-slate-200 bg-white p-4">
          <h4 className="mb-2 text-sm font-semibold">Most serious findings (latest snapshot)</h4>
          <ul className="space-y-1 text-sm">
            {d.worst_resources.map((f) => (
              <li key={f.id} className="flex items-center gap-2">
                <Severity value={f.severity} />
                <span className="font-mono text-xs">{f.rule_id}</span>
                <span className="flex-1">{f.title}</span>
                <span className="text-xs text-slate-500">{f.resource_id}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

/** Portfolio of projects with their current score and trend, and a detail view per project. */
export default function DashboardPage() {
  const [projectId, setProjectId] = useState(null);
  const overview = useAsyncData("dashboard", getDashboard);

  if (overview.error) {
    return (
      <Notice tone="error" title="Could not load the dashboard">
        {overview.error.message}
      </Notice>
    );
  }
  if (!overview.data) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Loading…
      </p>
    );
  }
  const { projects, totals } = overview.data;

  return (
    <section aria-labelledby="dashboard-heading" className="space-y-4">
      <div>
        <h2 id="dashboard-heading" className="text-lg font-semibold">
          Risk dashboard
        </h2>
        <p className="text-sm text-slate-500">
          Score = 100 minus a penalty per finding (the worst finding of each security group counts
          in full, extra findings on the same group count half). Higher is safer.
        </p>
      </div>
      {projectId ? (
        <ProjectDetail projectId={projectId} onBack={() => setProjectId(null)} />
      ) : projects.length === 0 ? (
        <Notice tone="info" title="No projects yet">
          Create a project and import a configuration on the Import tab.
        </Notice>
      ) : (
        <>
          <dl className="grid grid-cols-3 gap-3">
            {[
              ["Projects", totals.projects],
              ["Average score", totals.average_score ?? "n/a"],
              ["Lowest score", totals.lowest_score ?? "n/a"],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-200 bg-white p-3">
                <dt className="text-xs text-slate-500">{label}</dt>
                <dd className="text-xl font-semibold">{value}</dd>
              </div>
            ))}
          </dl>
          <ul className="grid gap-3 md:grid-cols-2">
            {projects.map((p) => (
              <ProjectCard key={p.id} project={p} onOpen={setProjectId} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
