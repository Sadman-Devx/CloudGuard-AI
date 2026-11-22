import { describe, expect, it } from "vitest";

import {
  decorateEdges,
  decorateNodes,
  highlightedPaths,
  hotEdgeKeys,
} from "./riskOverlay.js";

const risk = {
  nodes: {
    web: { severity: "high", kind: "finding", reasons: [{ severity: "high" }, { severity: "low" }] },
  },
  paths: [
    { id: "web:22", verified: true, steps: ["internet", "igw", "web"] },
    { id: "db:5432", verified: false, steps: ["internet", "igw", "db"] },
  ],
};

describe("risk overlay helpers", () => {
  it("highlights verified paths unless one is chosen", () => {
    expect(highlightedPaths(risk, null).map((p) => p.id)).toEqual(["web:22"]);
    expect(highlightedPaths(risk, "db:5432").map((p) => p.id)).toEqual(["db:5432"]);
  });

  it("matches edges in either direction", () => {
    const keys = hotEdgeKeys(risk.paths.slice(0, 1));
    const edges = [
      { id: "e1", source: "igw", target: "internet", style: {} },
      { id: "e2", source: "web", target: "igw", style: {} },
      { id: "e3", source: "db", target: "igw", style: {} },
    ];
    expect(keys.size).toBe(2);
    const shown = decorateEdges(edges, risk, null);
    expect(shown.filter((e) => e.animated).map((e) => e.id)).toEqual(["e1", "e2"]);
    expect(shown[0].style.stroke).toBe("#dc2626");
  });

  it("adds risk data to flagged nodes and leaves the others alone", () => {
    const nodes = [
      { id: "web", data: { label: "web" } },
      { id: "other", data: { label: "other" } },
    ];
    const shown = decorateNodes(nodes, risk, null);
    expect(shown[0].data.risk).toEqual({ severity: "high", kind: "finding", count: 2 });
    expect(shown[0].data.onRiskPath).toBe(true);
    expect(shown[1]).toBe(nodes[1]);
  });

  it("returns the inputs unchanged without an overlay", () => {
    const nodes = [{ id: "a", data: {} }];
    expect(decorateNodes(nodes, null, null)).toBe(nodes);
    expect(decorateEdges([], null, null)).toEqual([]);
  });
});
