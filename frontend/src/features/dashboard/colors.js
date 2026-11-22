// Shared colours of the dashboard (kept out of the components so they can be reused and tested).

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_FILL = {
  critical: "#991b1b",
  high: "#dc2626",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#94a3b8",
};

export function scoreColor(value) {
  if (value >= 80) return "#059669";
  if (value >= 60) return "#d97706";
  return "#dc2626";
}
