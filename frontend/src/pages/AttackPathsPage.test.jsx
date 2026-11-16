import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch } from "../test/mockFetch.js";
import AttackPathsPage from "./AttackPathsPage.jsx";

afterEach(() => vi.unstubAllGlobals());

const GRAPH = {
  demo: false,
  snapshot: 5,
  warnings: [{ code: "UNMODELLED_NETWORK", message: "NAT is recorded only." }],
  nodes: [
    { id: "internet", name: "Internet", type: "internet", criticality: 1 },
    { id: "web", name: "web-1", type: "ec2", criticality: 4 },
    { id: "db", name: "customers-db", type: "rds", criticality: 10, crown_jewel: true },
  ],
  edges: [
    { source: "internet", target: "web", kind: "network", label: "tcp/443" },
    { source: "web", target: "db", kind: "data_access", label: "postgres" },
  ],
};
const brief = (id, name, type) => ({ id, name, type, criticality: 1, crown_jewel: false });
const PATHS = {
  paths: [
    {
      node_ids: ["internet", "web", "db"],
      nodes: [brief("internet", "Internet", "internet"), brief("web", "web-1", "ec2"), brief("db", "customers-db", "rds")],
      edges: [
        { source: "internet", target: "web", kind: "network", label: "", probability: 0.4 },
        { source: "web", target: "db", kind: "data_access", label: "", probability: 0.5 },
      ],
      probability: 0.2,
      impact: 10,
      risk: 2,
      hops: 2,
    },
  ],
  choke_points: [{ id: "web", name: "web-1", type: "ec2", paths: 1, risk_share: 1 }],
  search: { expanded: 5, truncated: false },
  demo: false,
  snapshot: 5,
  warnings: [],
};

const routes = (extra = {}) => ({
  "GET /api/projects/": () => ({ body: { count: 1, results: [{ id: 1, name: "Demo" }] } }),
  "GET /api/projects/1/snapshots/": () => ({
    body: {
      count: 1,
      results: [{ id: 5, project: 1, version: 1, name: "Net", source_name: "", source_type: "fixture" }],
    },
  }),
  "GET /api/snapshots/5/attack-path/graph/": () => ({ body: GRAPH }),
  "GET /api/snapshots/5/attack-path/paths/?top_k=10&max_depth=6": () => ({ body: PATHS }),
  ...extra,
});

describe("AttackPathsPage", () => {
  it("shows the graph and the ranked paths of the selected snapshot", async () => {
    mockFetch(routes());
    render(<AttackPathsPage />);
    expect(await screen.findByRole("group", { name: "Attack graph" })).toBeInTheDocument();
    const list = await screen.findByRole("list", { name: "Attack paths" });
    expect(list).toHaveTextContent("risk 2");
    expect(list).toHaveTextContent("Internet → web-1 → customers-db");
    expect(screen.getByText("NAT is recorded only.")).toBeInTheDocument();
  });

  it("loads the blast radius when a node is selected", async () => {
    mockFetch(
      routes({
        "GET /api/snapshots/5/attack-path/blast-radius/web/": () => ({
          body: {
            start: brief("web", "web-1", "ec2"),
            reachable_count: 1,
            reachable: [{ ...brief("db", "customers-db", "rds"), crown_jewel: true, probability: 0.5, hops: 1, impact_score: 5 }],
            crown_jewels_reached: [{ id: "db" }],
            severity: "critical",
          },
        }),
      }),
    );
    render(<AttackPathsPage />);
    const node = await screen.findByRole("button", { name: /Instance web-1/ });
    await userEvent.click(node);
    expect(await screen.findByText("Blast radius of web-1")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("simulates blocking one hop of the selected path", async () => {
    const { calls } = mockFetch(
      routes({
        "POST /api/snapshots/5/attack-path/simulate/": () => ({
          body: { risk_before: 2, risk_after: 0, risk_reduction_pct: 100, paths_before: 1, paths_after: 0 },
        }),
      }),
    );
    render(<AttackPathsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /#1/ }));
    await userEvent.click(screen.getByRole("button", { name: "Simulate" }));
    expect(calls.at(-1).body).toEqual({ remove_edges: [["internet", "web"]] });
    expect(await screen.findByText(/100% lower/)).toBeInTheDocument();
  });

  it("says so when there is no snapshot", async () => {
    mockFetch({
      "GET /api/projects/": () => ({ body: { count: 1, results: [{ id: 1, name: "Demo" }] } }),
      "GET /api/projects/1/snapshots/": () => ({ body: { count: 0, results: [] } }),
    });
    render(<AttackPathsPage />);
    expect(await screen.findByText("This project has no snapshots yet")).toBeInTheDocument();
  });
});
