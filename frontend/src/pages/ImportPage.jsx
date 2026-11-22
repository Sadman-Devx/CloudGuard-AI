import { useCallback, useEffect, useState } from "react";

import {
  createProject,
  importAws,
  importFixture,
  importIac,
  listFixtures,
  listProjects,
  uploadConfig,
} from "../api/endpoints.js";
import Notice from "../components/Notice.jsx";
import AwsImportForm from "../features/import/AwsImportForm.jsx";
import IacImportForm from "../features/import/IacImportForm.jsx";
import ImportForm from "../features/import/ImportForm.jsx";
import SnapshotSummary from "../features/import/SnapshotSummary.jsx";
import ValidationErrors from "../features/import/ValidationErrors.jsx";
import ProjectPicker from "../features/projects/ProjectPicker.jsx";

export default function ImportPage({ onViewTopology }) {
  const [projects, setProjects] = useState([]);
  const [fixtures, setFixtures] = useState([]);
  const [projectId, setProjectId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState(null);
  const [source, setSource] = useState("sample");

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      listProjects(controller.signal),
      listFixtures(controller.signal),
    ])
      .then(([projectList, fixtureList]) => {
        setProjects(projectList);
        setFixtures(fixtureList);
        if (projectList.length) setProjectId(projectList[0].id);
      })
      .catch((e) => {
        if (e?.name !== "AbortError") setLoadError(e);
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, []);

  const run = useCallback(async (action) => {
    setBusy(true);
    setError(null);
    setSnapshot(null);
    try {
      return await action();
    } catch (e) {
      setError(e);
      return null;
    } finally {
      setBusy(false);
    }
  }, []);

  const handleCreate = async (name) => {
    const project = await run(() => createProject(name));
    if (!project) return false;
    setProjects((current) => [project, ...current]);
    setProjectId(project.id);
    return true;
  };

  const handleImportFixture = async (name) =>
    setSnapshot(await run(() => importFixture(projectId, name)));
  const handleUpload = async (config, fileName) =>
    setSnapshot(await run(() => uploadConfig(projectId, config, fileName)));
  const handleIac = async (body) =>
    setSnapshot(await run(() => importIac(projectId, body)));
  const handleAws = async (body) =>
    setSnapshot(await run(() => importAws(projectId, body)));

  if (loading) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Loading…
      </p>
    );
  }
  if (loadError) {
    return (
      <Notice tone="error" title="Could not load projects">
        {loadError.message}
      </Notice>
    );
  }

  return (
    <section
      aria-labelledby="import-heading"
      className="mx-auto max-w-3xl space-y-6"
    >
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <h2 id="import-heading" className="text-lg font-semibold">
          Import a network configuration
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Configurations are validated and stored as immutable snapshots.
          Sample, JSON and infrastructure-as-code imports never contact AWS;
          the optional live import only reads.
        </p>

        <div className="mt-5 space-y-6">
          <ProjectPicker
            projects={projects}
            selectedId={projectId}
            onSelect={setProjectId}
            onCreate={handleCreate}
            busy={busy}
          />
          <div
            role="group"
            aria-label="Import source"
            className="inline-flex flex-wrap overflow-hidden rounded-lg border border-slate-300 text-sm"
          >
            {[
              ["sample", "Sample or JSON"],
              ["iac", "Terraform / CloudFormation"],
              ["aws", "Live AWS"],
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                aria-pressed={source === id}
                onClick={() => setSource(id)}
                className={`px-3 py-1.5 ${
                  source === id
                    ? "bg-slate-900 text-white"
                    : "bg-white text-slate-700 hover:bg-slate-50"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          {source === "sample" && (
            <ImportForm
              fixtures={fixtures}
              disabled={!projectId}
              busy={busy}
              onImportFixture={handleImportFixture}
              onUploadFile={handleUpload}
            />
          )}
          {source === "iac" && (
            <IacImportForm
              disabled={!projectId}
              busy={busy}
              onImport={handleIac}
            />
          )}
          {source === "aws" && (
            <AwsImportForm
              disabled={!projectId}
              busy={busy}
              onImport={handleAws}
            />
          )}
          {!projectId && (
            <p className="text-sm text-slate-500">
              Create or select a project to enable importing.
            </p>
          )}
        </div>
      </div>

      {busy && (
        <p role="status" className="text-sm text-slate-500">
          Working…
        </p>
      )}
      {error && <ValidationErrors error={error} />}
      {snapshot && (
        <SnapshotSummary snapshot={snapshot} onViewTopology={onViewTopology} />
      )}
    </section>
  );
}
