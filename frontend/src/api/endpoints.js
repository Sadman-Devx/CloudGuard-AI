import { apiRequest } from "./client.js";

export const getHealth = (signal) =>
  apiRequest("/api/health/", { signal, acceptStatuses: [503] });

export const listProjects = async (signal) => (await apiRequest("/api/projects/", { signal })).results;

export const createProject = (name) => apiRequest("/api/projects/", { method: "POST", body: { name } });

export const listFixtures = async (signal) => (await apiRequest("/api/fixtures/", { signal })).results;

export const importFixture = (projectId, fixture) =>
  apiRequest(`/api/projects/${projectId}/snapshots/from-fixture/`, { method: "POST", body: { fixture } });

export const uploadConfig = (projectId, config, sourceName = "") =>
  apiRequest(`/api/projects/${projectId}/snapshots/`, {
    method: "POST",
    body: config,
    headers: sourceName ? { "X-Source-Name": sourceName } : {},
  });
