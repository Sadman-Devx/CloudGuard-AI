import { apiRequest } from "./client.js";

export const getHealth = (signal) =>
  apiRequest("/api/health/", { signal, acceptStatuses: [503] });

export const listProjects = async (signal) =>
  (await apiRequest("/api/projects/", { signal })).results;

export const createProject = (name) =>
  apiRequest("/api/projects/", { method: "POST", body: { name } });

export const listFixtures = async (signal) =>
  (await apiRequest("/api/fixtures/", { signal })).results;

export const importFixture = (projectId, fixture) =>
  apiRequest(`/api/projects/${projectId}/snapshots/from-fixture/`, {
    method: "POST",
    body: { fixture },
  });

export const uploadConfig = (projectId, config, sourceName = "") =>
  apiRequest(`/api/projects/${projectId}/snapshots/`, {
    method: "POST",
    body: config,
    headers: sourceName ? { "X-Source-Name": sourceName } : {},
  });

export const listSnapshots = async (projectId, signal) =>
  (await apiRequest(`/api/projects/${projectId}/snapshots/`, { signal }))
    .results;

export const getTopology = (snapshotId, signal) =>
  apiRequest(`/api/snapshots/${snapshotId}/topology/`, { signal });

// ---- Day 4: security findings
export const analyzeSnapshot = (snapshotId) =>
  apiRequest(`/api/snapshots/${snapshotId}/analyze/`, { method: "POST" });

export const getFindings = (snapshotId, signal) =>
  apiRequest(`/api/snapshots/${snapshotId}/findings/`, { signal });

export const listRules = async (signal) =>
  (await apiRequest("/api/rules/", { signal })).results;

// ---- Day 5: Meta AI copilot
export const getCopilotStatus = (signal) =>
  apiRequest("/api/copilot/status/", { signal });

export const getExplanation = async (findingId, signal) =>
  (await apiRequest(`/api/findings/${findingId}/explain/`, { signal }))
    .interaction;

export const explainFinding = async (findingId, { refresh = false } = {}) =>
  (
    await apiRequest(`/api/findings/${findingId}/explain/`, {
      method: "POST",
      body: { refresh },
    })
  ).interaction;