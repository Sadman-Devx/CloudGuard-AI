import { describe, expect, it } from "vitest";

import { BRACKET_LABEL_ROOM, COL_GAP, NODE_H, NODE_W, edgeLabel, filterTopology, graphHeight, layoutHeight, layoutTopology } from "./layout.js";

const node = (id, type, parent = "vpc-1", data = {}) => ({ id, type, label: id, parent, data });
const edge = (source, target, kind, extra = {}) => ({
  id: `${kind}:${source}->${target}`,
  source,
  target,
  kind,
  label: "",
  data: {},
  ...extra,
});

function sample() {
  return {
    nodes: [
      node("internet", "internet", null),
      node("vpc-1", "vpc", null),
      node("igw-1", "internet_gateway"),
      node("rtb-1", "route_table"),
      node("subnet-b", "subnet", "vpc-1", { kind: "private" }),
      node("subnet-a", "subnet", "vpc-1", { kind: "public" }),
      node("i-2", "instance"),
      node("i-1", "instance"),
      node("sg-1", "security_group"),
    ],
    edges: [
      edge("internet", "igw-1", "attached", { label: "attached" }),
      edge("rtb-1", "igw-1", "routes_via", { label: "0.0.0.0/0" }),
      edge("subnet-a", "rtb-1", "associated_route_table"),
      edge("subnet-b", "rtb-1", "associated_route_table"),
      edge("i-1", "subnet-a", "placed_in_subnet"),
      edge("i-2", "subnet-b", "placed_in_subnet"),
      edge("i-1", "sg-1", "protected_by"),
      edge("i-2", "sg-1", "protected_by"),
    ],
  };
}

const byId = (result) => Object.fromEntries(result.nodes.map((n) => [n.id, n]));

describe("layoutTopology", () => {
  it("places the VPC as a group and children inside it, parent before children", () => {
    const result = layoutTopology(sample());
    const nodes = byId(result);
    expect(nodes["vpc-1"].type).toBe("vpc");
    expect(nodes["vpc-1"].style.width).toBeGreaterThan(NODE_W);
    for (const id of ["igw-1", "rtb-1", "subnet-a", "i-1", "sg-1"]) {
      expect(nodes[id].parentId).toBe("vpc-1");
      expect(nodes[id].extent).toBe("parent");
    }
    const order = result.nodes.map((n) => n.id);
    expect(order.indexOf("vpc-1")).toBeLessThan(order.indexOf("subnet-a"));
  });

  it("orders columns along the packet path, left to right", () => {
    const nodes = byId(layoutTopology(sample()));
    const x = (id) => nodes[id].position.x;
    expect(nodes.internet.position.x).toBeLessThan(nodes["vpc-1"].position.x);
    expect(x("igw-1")).toBeLessThan(x("subnet-a"));
    expect(x("subnet-a")).toBeLessThan(x("i-1"));
    expect(x("i-1")).toBeLessThan(x("sg-1"));
  });

  it("stacks gateways above route tables, and ACLs below subnets, in shared columns", () => {
    const graph = sample();
    graph.nodes.push(node("acl-1", "network_acl"));
    graph.edges.push(edge("subnet-a", "acl-1", "associated_network_acl"));
    const nodes = byId(layoutTopology(graph));
    expect(nodes["igw-1"].position.x).toBe(nodes["rtb-1"].position.x);
    expect(nodes["igw-1"].position.y).toBeLessThan(nodes["rtb-1"].position.y);
    expect(nodes["acl-1"].position.x).toBe(nodes["subnet-a"].position.x);
    expect(nodes["acl-1"].position.y).toBeGreaterThan(nodes["subnet-b"].position.y);
  });

  it("collapses empty columns (no gap when a column has no resources)", () => {
    const graph = sample();
    graph.nodes = graph.nodes.filter((n) => n.type !== "route_table" && n.type !== "internet_gateway");
    graph.edges = filterTopology(graph).edges;
    const nodes = byId(layoutTopology(graph));
    expect(nodes["subnet-a"].position.x).toBe(28); // first column starts at the VPC padding
    expect(nodes["i-1"].position.x - nodes["subnet-a"].position.x).toBe(NODE_W + COL_GAP);
  });

  it("puts public subnets first and keeps instances next to their subnet", () => {
    const nodes = byId(layoutTopology(sample()));
    expect(nodes["subnet-a"].position.y).toBeLessThan(nodes["subnet-b"].position.y);
    expect(nodes["i-1"].position.y).toBeLessThan(nodes["i-2"].position.y);
    expect(nodes["i-1"].position.y).toBe(nodes["subnet-a"].position.y);
  });

  it("never overlaps nodes in the same column", () => {
    const nodes = layoutTopology(sample()).nodes.filter((n) => n.type === "resource");
    for (const a of nodes) {
      for (const b of nodes) {
        if (a.id < b.id && a.position.x === b.position.x) {
          expect(Math.abs(a.position.y - b.position.y)).toBeGreaterThanOrEqual(NODE_H);
        }
      }
    }
  });

  it("sizes the VPC box to contain every child", () => {
    const result = layoutTopology(sample());
    const nodes = byId(result);
    const { width, height } = nodes["vpc-1"].style;
    for (const n of result.nodes.filter((x) => x.parentId)) {
      expect(n.position.x + NODE_W).toBeLessThanOrEqual(width);
      expect(n.position.y + NODE_H).toBeLessThanOrEqual(height);
    }
  });

  it("is deterministic regardless of input order", () => {
    const forward = sample();
    const reversed = { nodes: [...forward.nodes].reverse(), edges: [...forward.edges].reverse() };
    const positions = (r) => Object.fromEntries(r.nodes.map((n) => [n.id, n.position]));
    expect(positions(layoutTopology(reversed))).toEqual(positions(layoutTopology(forward)));
  });

  it("stacks multiple VPCs vertically without overlap", () => {
    const graph = sample();
    graph.nodes.push(node("vpc-2", "vpc", null), node("subnet-z", "subnet", "vpc-2", { kind: "private" }));
    const nodes = byId(layoutTopology(graph));
    expect(nodes["vpc-2"].position.y).toBeGreaterThanOrEqual(nodes["vpc-1"].position.y + nodes["vpc-1"].style.height);
  });

  it("places nodes with a missing VPC in a visible fallback row instead of dropping them", () => {
    const graph = { nodes: [node("vpc-1", "vpc", null), node("sg-x", "security_group", "vpc-gone")], edges: [] };
    const nodes = byId(layoutTopology(graph));
    expect(nodes["sg-x"]).toBeDefined();
    expect(nodes["sg-x"].parentId).toBeUndefined();
  });

  it("handles an empty topology", () => {
    expect(layoutTopology({ nodes: [], edges: [] })).toEqual({ nodes: [], edges: [] });
  });

  it("chooses edge handles by direction so lines do not run through nodes", () => {
    const edges = Object.fromEntries(layoutTopology(sample()).edges.map((e) => [e.id, e]));
    expect(edges["placed_in_subnet:i-1->subnet-a"]).toMatchObject({ sourceHandle: "l", targetHandle: "r" }); // instance is right of subnet
    expect(edges["associated_route_table:subnet-a->rtb-1"]).toMatchObject({ sourceHandle: "l", targetHandle: "r" });
    expect(edges["protected_by:i-1->sg-1"]).toMatchObject({ sourceHandle: "r", targetHandle: "l" });
  });

  it("draws same-column edges as staggered brackets so shared endpoints never overlap", () => {
    const graph = sample();
    graph.nodes.push(node("sg-2", "security_group"), node("sg-3", "security_group"));
    graph.edges.push(
      edge("sg-1", "sg-3", "sg_traffic", { label: "tcp/1", data: { sides: "both" } }),
      edge("sg-2", "sg-3", "sg_traffic", { label: "tcp/2", data: { sides: "both" } }),
    );
    const flows = layoutTopology(graph).edges.filter((e) => e.data.kind === "sg_traffic");
    expect(flows).toHaveLength(2);
    for (const f of flows) {
      expect(f.type).toBe("smoothstep");
      expect([f.sourceHandle, f.targetHandle]).toEqual(["r", "r"]);
    }
    expect(new Set(flows.map((f) => f.pathOptions.offset)).size).toBe(2);
  });

  it("keeps cross-column edges as default curves", () => {
    const edges = layoutTopology(sample()).edges.filter((e) => e.data.kind === "protected_by");
    expect(edges.every((e) => e.type === undefined)).toBe(true);
  });
});

describe("layoutHeight", () => {
  it("covers the tallest VPC and is zero for an empty graph", () => {
    const result = layoutTopology(sample());
    const vpc = result.nodes.find((n) => n.id === "vpc-1");
    expect(layoutHeight(result.nodes)).toBe(vpc.position.y + vpc.style.height);
    expect(layoutHeight([])).toBe(0);
  });
});

describe("bracket room", () => {
  it("widens the VPC only when security-group traffic edges need brackets", () => {
    const plain = byId(layoutTopology(sample()))["vpc-1"].style.width;
    const graph = sample();
    graph.nodes.push(node("sg-2", "security_group"));
    graph.edges.push(edge("sg-1", "sg-2", "sg_traffic", { label: "tcp/1", data: { sides: "both" } }));
    const withTraffic = byId(layoutTopology(graph))["vpc-1"].style.width;
    expect(withTraffic).toBeGreaterThan(plain + BRACKET_LABEL_ROOM);
  });

  it("keeps every bracket inside the VPC box", () => {
    const graph = sample();
    for (let i = 2; i <= 7; i += 1) graph.nodes.push(node(`sg-${i}`, "security_group"));
    for (let i = 2; i <= 7; i += 1) graph.edges.push(edge("sg-1", `sg-${i}`, "sg_traffic", { label: "tcp/1", data: { sides: "both" } }));
    const result = layoutTopology(graph);
    const vpc = byId(result)["vpc-1"];
    const sg = byId(result)["sg-1"];
    const farthest = Math.max(...result.edges.filter((e) => e.pathOptions).map((e) => e.pathOptions.offset));
    expect(sg.position.x + NODE_W + farthest + BRACKET_LABEL_ROOM / 2).toBeLessThanOrEqual(vpc.style.width);
  });
});

describe("graphHeight", () => {
  it("stays within bounds for tiny and huge graphs", () => {
    expect(graphHeight({ nodes: [], edges: [] })).toBe(360);
    const many = { nodes: [node("vpc-1", "vpc", null), ...Array.from({ length: 40 }, (_, i) => node(`i-${i}`, "instance"))], edges: [] };
    expect(graphHeight(many)).toBe(760);
  });
});

describe("edge presentation", () => {
  const flow = (sides) => edge("sg-a", "sg-b", "sg_traffic", { label: "tcp/5432", data: { sides } });

  it("labels one-sided flows in text, not only colour", () => {
    expect(edgeLabel(flow("both"))).toBe("tcp/5432");
    expect(edgeLabel(flow("egress_only"))).toBe("tcp/5432 · egress only");
    expect(edgeLabel(flow("ingress_only"))).toBe("tcp/5432 · ingress only");
  });

  it("does not label plain association edges or the internet attachment", () => {
    expect(edgeLabel(edge("a", "b", "protected_by"))).toBe("");
    expect(edgeLabel(edge("internet", "igw-1", "attached", { label: "attached" }))).toBe("");
  });

  it("styles one-sided flows differently from agreed ones", () => {
    const graph = { nodes: [node("vpc-1", "vpc", null), node("sg-a", "security_group"), node("sg-b", "security_group")], edges: [flow("both"), { ...flow("egress_only"), id: "x" }] };
    const [agreed, oneSided] = layoutTopology(graph).edges;
    expect(agreed.style.stroke).not.toBe(oneSided.style.stroke);
  });
});

describe("filterTopology", () => {
  it("hides types and the edges attached to them", () => {
    const { nodes, edges } = filterTopology(sample(), new Set(["security_group"]));
    expect(nodes.find((n) => n.id === "sg-1")).toBeUndefined();
    expect(edges.some((e) => e.target === "sg-1")).toBe(false);
    expect(edges.some((e) => e.kind === "placed_in_subnet")).toBe(true);
  });

  it("returns everything when nothing is hidden", () => {
    const graph = sample();
    expect(filterTopology(graph)).toEqual({ nodes: graph.nodes, edges: graph.edges });
  });
});