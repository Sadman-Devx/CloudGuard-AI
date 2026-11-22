// Pure helpers that merge the server's risk overlay into the React Flow nodes and edges.

export const SEVERITY_LABEL = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const pairKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);

/** The paths to highlight: the chosen one, else every verified path. */
export function highlightedPaths(risk, activePathId) {
  const paths = risk?.paths ?? [];
  if (activePathId) return paths.filter((p) => p.id === activePathId);
  return paths.filter((p) => p.verified);
}

export function hotEdgeKeys(paths) {
  const keys = new Set();
  for (const path of paths) {
    for (let i = 0; i < path.steps.length - 1; i += 1) {
      keys.add(pairKey(path.steps[i], path.steps[i + 1]));
    }
  }
  return keys;
}

export function decorateNodes(nodes, risk, activePathId) {
  if (!risk) return nodes;
  const onPath = new Set(highlightedPaths(risk, activePathId).flatMap((p) => p.steps));
  return nodes.map((node) => {
    const entry = risk.nodes?.[node.id];
    const hot = onPath.has(node.id);
    if (!entry && !hot) return node;
    return {
      ...node,
      data: {
        ...node.data,
        risk: entry ? { severity: entry.severity, kind: entry.kind, count: entry.reasons.length } : null,
        onRiskPath: hot,
      },
    };
  });
}

export function decorateEdges(edges, risk, activePathId) {
  if (!risk) return edges;
  const hot = hotEdgeKeys(highlightedPaths(risk, activePathId));
  if (hot.size === 0) return edges;
  return edges.map((edge) =>
    hot.has(pairKey(edge.source, edge.target))
      ? {
          ...edge,
          animated: true,
          style: { ...edge.style, stroke: "#dc2626", strokeWidth: 3 },
          zIndex: 3,
        }
      : edge,
  );
}
