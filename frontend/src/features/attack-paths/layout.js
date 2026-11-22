// Layered layout for the attack graph: column = number of hops from the internet.

export const NODE_W = 168;
export const NODE_H = 46;
const COL_W = 232;
const ROW_H = 68;
const PAD = 24;

const TYPE_ORDER = ["internet", "load_balancer", "ec2", "iam_role", "rds", "s3"];
const orderOf = (type) => {
  const i = TYPE_ORDER.indexOf(type);
  return i === -1 ? TYPE_ORDER.length : i;
};

/** @returns {{positions: Map<string,{x:number,y:number}>, width:number, height:number}} */
export function layerGraph(nodes, edges) {
  const next = new Map(nodes.map((n) => [n.id, []]));
  for (const e of edges) next.get(e.source)?.push(e.target);

  const roots = nodes.filter((n) => n.type === "internet").map((n) => n.id);
  if (roots.length === 0) {
    roots.push(...nodes.filter((n) => n.internet_exposed).map((n) => n.id));
  }

  const depth = new Map(roots.map((id) => [id, 0]));
  const queue = [...roots];
  while (queue.length) {
    const id = queue.shift();
    for (const target of next.get(id) ?? []) {
      if (!depth.has(target)) {
        depth.set(target, depth.get(id) + 1);
        queue.push(target);
      }
    }
  }
  const deepest = Math.max(0, ...depth.values());
  const layerOf = (id) => depth.get(id) ?? deepest + 1; // unreachable nodes go last

  const layers = new Map();
  for (const n of nodes) {
    const layer = layerOf(n.id);
    if (!layers.has(layer)) layers.set(layer, []);
    layers.get(layer).push(n);
  }

  const positions = new Map();
  let rows = 1;
  for (const [layer, members] of layers) {
    members.sort(
      (a, b) =>
        orderOf(a.type) - orderOf(b.type) ||
        (a.name ?? a.id).localeCompare(b.name ?? b.id),
    );
    rows = Math.max(rows, members.length);
    members.forEach((n, row) => {
      positions.set(n.id, { x: PAD + layer * COL_W, y: PAD + row * ROW_H });
    });
  }
  const columns = layers.size === 0 ? 1 : Math.max(...layers.keys()) + 1;
  return {
    positions,
    width: PAD * 2 + (columns - 1) * COL_W + NODE_W,
    height: PAD * 2 + (rows - 1) * ROW_H + NODE_H,
  };
}

export const edgeKey = (source, target) => `${source}>${target}`;
