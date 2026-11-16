// Colours and labels of the attack graph's node types.

export const TYPE_STYLE = {
  internet: { fill: "#e2e8f0", stroke: "#64748b", label: "Internet" },
  load_balancer: { fill: "#e0f2fe", stroke: "#0284c7", label: "Load balancer" },
  ec2: { fill: "#e0e7ff", stroke: "#4f46e5", label: "Instance" },
  iam_role: { fill: "#fef3c7", stroke: "#d97706", label: "IAM role" },
  rds: { fill: "#ffe4e6", stroke: "#e11d48", label: "Database" },
  s3: { fill: "#d1fae5", stroke: "#059669", label: "Bucket" },
};
export const FALLBACK = { fill: "#f1f5f9", stroke: "#94a3b8", label: "Resource" };

export const typeLabel = (type) => (TYPE_STYLE[type] ?? FALLBACK).label;
