import { describe, expect, it } from "vitest";

import { edgeKey, layerGraph } from "./layout.js";

const node = (id, type = "ec2", extra = {}) => ({ id, name: id, type, ...extra });

describe("layerGraph", () => {
  it("puts nodes in columns by hops from the internet", () => {
    const nodes = [
      node("internet", "internet"),
      node("web"),
      node("db", "rds"),
      node("orphan"),
    ];
    const edges = [
      { source: "internet", target: "web" },
      { source: "web", target: "db" },
    ];
    const { positions } = layerGraph(nodes, edges);
    expect(positions.get("internet").x).toBeLessThan(positions.get("web").x);
    expect(positions.get("web").x).toBeLessThan(positions.get("db").x);
    // a node the internet cannot reach goes in the last column
    expect(positions.get("orphan").x).toBeGreaterThan(positions.get("db").x);
  });

  it("stacks nodes of one column without overlap", () => {
    const nodes = [node("internet", "internet"), node("a"), node("b")];
    const edges = [
      { source: "internet", target: "a" },
      { source: "internet", target: "b" },
    ];
    const { positions } = layerGraph(nodes, edges);
    expect(positions.get("a").x).toBe(positions.get("b").x);
    expect(positions.get("a").y).not.toBe(positions.get("b").y);
  });

  it("handles an empty graph", () => {
    const { positions, width, height } = layerGraph([], []);
    expect(positions.size).toBe(0);
    expect(width).toBeGreaterThan(0);
    expect(height).toBeGreaterThan(0);
  });

  it("builds edge keys", () => {
    expect(edgeKey("a", "b")).toBe("a>b");
  });
});
