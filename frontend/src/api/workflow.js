const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

async function request(path, options) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body?.error?.message || `Request failed (${res.status})`);
    err.code = body?.error?.code;
    throw err;
  }
  return body;
}

// proposal is optional: if omitted, the backend uses the stored AI Copilot proposal.
export const simulateProposal = (findingId, proposal) =>
  request(`/findings/${findingId}/simulate-proposal/`, {
    method: "POST",
    body: JSON.stringify(proposal ? { proposal } : {}),
  });

export const getDashboard = (projectId) => request(`/projects/${projectId}/dashboard/`);
