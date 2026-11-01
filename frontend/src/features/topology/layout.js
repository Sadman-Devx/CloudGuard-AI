// Pure, deterministic layout: topology (from the API) -> React Flow nodes/edges.
// Columns left to right follow the packet path: Internet -> gateway -> route table -> subnet -> ACL ->
// instance -> security group. Each VPC is a group box; several VPCs stack vertically.

export const NODE_W = 184;
export const NODE_H = 64;
export const COL_GAP = 64;
export const ROW_GAP = 20;
export const VPC_PAD = 28;
export const VPC_HEADER = 44;
export const VPC_GAP = 60;
// Same-column edges are drawn as brackets to the right of the last column; reserve room for them and
// their labels inside the VPC box so nothing is clipped when the graph is fitted to the screen.
export const BRACKET_BASE = 24;
export const BRACKET_STEP = 18;
export const BRACKET_STAGGER = 5;
export const BRACKET_LABEL_ROOM = 96;

// Resource types sharing a column are stacked top to bottom in this order. Four columns keep the
// graph compact enough to stay legible when fitted to the screen.
export const COLUMN_GROUPS = [["internet_gateway", "route_table"], ["subnet", "network_acl"], ["instance"], ["security_group"]];
export const COLUMN_ORDER = COLUMN_GROUPS.flat();

/** Resource types the user may hide to reduce clutter. */
export const FILTERABLE_TYPES = ["route_table", "network_acl", "security_group"];

export const TYPE_LABELS = {
  internet: "Internet",
  vpc: "VPC",
  internet_gateway: "Internet gateway",
  route_table: "Route table",
  subnet: "Subnet",
  network_acl: "Network ACL",
  instance: "Instance",
  security_group: "Security group",
};

export const EDGE_STYLES = {
  attached: { stroke: "#64748b" },
  routes_via: { stroke: "#d97706", strokeDasharray: "6 4" },
  associated_route_table: { stroke: "#94a3b8" },
  associated_network_acl: { stroke: "#94a3b8" },
  placed_in_subnet: { stroke: "#94a3b8" },
  protected_by: { stroke: "#94a3b8", strokeDasharray: "2 4" },
  sg_traffic: { stroke: "#4f46e5", strokeWidth: 2 },
};
const ONE_SIDED_STROKE = "#e11d48";

/** Height in px needed to show the whole layout (used to size the graph container). */
export function layoutHeight(rfNodes) {
  const bottoms = rfNodes
    .filter((n) => !n.parentId)
    .map((n) => n.position.y + (n.style?.height ?? NODE_H));
  return bottoms.length ? Math.max(...bottoms) : 0;
}

/** Remove hidden resource types and every edge that would be left dangling. */
export function filterTopology(topology, hiddenTypes = new Set()) {
  const nodes = topology.nodes.filter((n) => !hiddenTypes.has(n.type));
  const ids = new Set(nodes.map((n) => n.id));
  const edges = topology.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
  return { nodes, edges };
}

export function edgeLabel(edge) {
  if (edge.kind === "sg_traffic") {
    const suffix = { ingress_only: " · ingress only", egress_only: " · egress only" }[edge.data?.sides] ?? "";
    return `${edge.label}${suffix}`;
  }
  if (edge.kind === "routes_via") return edge.label;
  return "";
}

function orderBy(items, keyOf) {
  return [...items].sort((a, b) => {
    const [ka, kb] = [keyOf(a), keyOf(b)];
    for (let i = 0; i < ka.length; i += 1) {
      if (ka[i] < kb[i]) return -1;
      if (ka[i] > kb[i]) return 1;
    }
    return 0;
  });
}

function firstIndex(edges, nodeId, role, indexOf) {
  const other = role === "source" ? "target" : "source";
  const indexes = edges.filter((e) => e[role] === nodeId && indexOf.has(e[other])).map((e) => indexOf.get(e[other]));
  return indexes.length ? Math.min(...indexes) : Number.MAX_SAFE_INTEGER;
}

/** Order the nodes of each column to keep connected nodes on nearby rows (fewer edge crossings). */
function orderColumns(children, edges) {
  const byType = (type) => children.filter((n) => n.type === type);
  const subnets = orderBy(byType("subnet"), (n) => [n.data?.kind === "public" ? 0 : 1, n.id]);
  const subnetIndex = new Map(subnets.map((n, i) => [n.id, i]));

  const instances = orderBy(byType("instance"), (n) => [firstIndex(edges, n.id, "source", subnetIndex), n.id]);
  const instanceIndex = new Map(instances.map((n, i) => [n.id, i]));

  return {
    internet_gateway: orderBy(byType("internet_gateway"), (n) => [n.id]),
    route_table: orderBy(byType("route_table"), (n) => [firstIndex(edges, n.id, "target", subnetIndex), n.id]),
    subnet: subnets,
    network_acl: orderBy(byType("network_acl"), (n) => [firstIndex(edges, n.id, "target", subnetIndex), n.id]),
    instance: instances,
    security_group: orderBy(byType("security_group"), (n) => [firstIndex(edges, n.id, "target", instanceIndex), n.id]),
  };
}

/**
 * @param {{nodes: object[], edges: object[]}} graph already filtered
 * @returns {{nodes: object[], edges: object[]}} React Flow nodes and edges
 */
export function layoutTopology({ nodes, edges }) {
  const rfNodes = [];
  const column = new Map(); // node id -> absolute column index (for choosing edge handles)
  const vpcs = orderBy(nodes.filter((n) => n.type === "vpc"), (n) => [n.id]);
  const vpcIds = new Set(vpcs.map((v) => v.id));
  const internet = nodes.find((n) => n.type === "internet");

  const originX = internet ? NODE_W + 72 : 0;
  const trafficEdges = edges.filter((e) => e.kind === "sg_traffic").length;
  const gutter = trafficEdges ? BRACKET_BASE + BRACKET_STEP * Math.min(trafficEdges, BRACKET_STAGGER) + BRACKET_LABEL_ROOM : 0;
  let cursorY = 0;
  const vpcBoxes = [];

  for (const vpc of vpcs) {
    const children = nodes.filter((n) => n.parent === vpc.id);
    const ordered = orderColumns(children, edges);
    const columns = COLUMN_GROUPS.map((types) => types.flatMap((type) => ordered[type])).filter((c) => c.length > 0);
    const rows = Math.max(1, ...columns.map((c) => c.length));
    const width =
      VPC_PAD * 2 + Math.max(1, columns.length) * NODE_W + Math.max(0, columns.length - 1) * COL_GAP + gutter;
    const height = VPC_HEADER + VPC_PAD + rows * NODE_H + (rows - 1) * ROW_GAP;

    rfNodes.push({
      id: vpc.id,
      type: "vpc",
      position: { x: originX, y: cursorY },
      data: vpc,
      style: { width, height },
      draggable: false,
      zIndex: 0,
    });
    columns.forEach((members, columnIndex) => {
      members.forEach((node, row) => {
        column.set(node.id, columnIndex);
        rfNodes.push({
          id: node.id,
          type: "resource",
          parentId: vpc.id,
          extent: "parent",
          position: {
            x: VPC_PAD + columnIndex * (NODE_W + COL_GAP),
            y: VPC_HEADER + row * (NODE_H + ROW_GAP),
          },
          data: node,
          zIndex: 1,
        });
      });
    });
    vpcBoxes.push({ y: cursorY, height });
    cursorY += height + VPC_GAP;
  }

  if (internet) {
    const total = Math.max(NODE_H, cursorY - VPC_GAP);
    column.set(internet.id, -1);
    rfNodes.unshift({
      id: internet.id,
      type: "internet",
      position: { x: 0, y: Math.round(total / 2 - NODE_H / 2) },
      data: internet,
      zIndex: 1,
    });
  }

  // Anything not inside a defined VPC (only possible for malformed data) goes in a row below.
  const orphans = orderBy(
    nodes.filter((n) => n.type !== "vpc" && n.type !== "internet" && !vpcIds.has(n.parent)),
    (n) => [n.id],
  );
  orphans.forEach((node, index) => {
    column.set(node.id, 100 + index);
    rfNodes.push({
      id: node.id,
      type: "resource",
      position: { x: originX + index * (NODE_W + 20), y: cursorY },
      data: node,
      zIndex: 1,
    });
  });

  let bracket = 0;
  const rfEdges = edges.map((edge) => {
    const [from, to] = [column.get(edge.source) ?? 0, column.get(edge.target) ?? 0];
    const sameColumn = from === to;
    const forward = from < to;
    const oneSided = edge.kind === "sg_traffic" && edge.data?.sides !== "both";
    // Edges inside one column leave and re-enter on the same side as a bracket. Stagger the bracket
    // width so edges that share an endpoint never lie on top of each other.
    const side = edge.kind === "sg_traffic" || edge.kind === "associated_network_acl" ? "r" : "l";
    const handles = sameColumn
      ? { sourceHandle: side, targetHandle: side }
      : { sourceHandle: forward ? "r" : "l", targetHandle: forward ? "l" : "r" };
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      ...handles,
      ...(sameColumn ? { type: "smoothstep", pathOptions: { offset: BRACKET_BASE + BRACKET_STEP * (bracket++ % BRACKET_STAGGER), borderRadius: 10 } } : {}),
      label: edgeLabel(edge),
      data: edge,
      style: { ...EDGE_STYLES[edge.kind], ...(oneSided ? { stroke: ONE_SIDED_STROKE, strokeDasharray: "8 4" } : {}) },
      labelStyle: { fontSize: 11, fill: oneSided ? ONE_SIDED_STROKE : "#334155" },
      labelBgPadding: [4, 2],
      labelBgBorderRadius: 4,
      zIndex: 2,
    };
  });

  return { nodes: rfNodes, edges: rfEdges };
}

/** Container height for a topology: fits the content, within sensible bounds. */
export function graphHeight(topology, hiddenTypes = new Set()) {
  const height = layoutHeight(layoutTopology(filterTopology(topology, hiddenTypes)).nodes);
  return Math.min(760, Math.max(360, height + 120));
}