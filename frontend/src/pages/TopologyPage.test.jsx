import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TOPOLOGY } from "../test/topologyFixture.js";
import { mockFetch } from "../test/mockFetch.js";
import TopologyPage from "./TopologyPage.jsx";

// React Flow needs real layout measurements, which jsdom cannot provide. The graph is covered by
// layout unit tests and by the real-browser end-to-end run; here we only check the page wiring.
vi.mock("../features/topology/TopologyGraph.jsx", () => ({
  default: ({ topology, hiddenTypes, onSelect }) => (
    <div data-testid="graph-stub">
      <span data-testid="hidden">{[...hiddenTypes].sort().join(",")}</span>
      {topology.nodes.map((n) => (
        <button key={n.id} onClick={() => onSelect({ kind: "node", id: n.id })}>
          {`node:${n.id}`}
        </button>
      ))}
    </div>
  ),
}));

afterEach(() => vi.unstubAllGlobals());

const PROJECTS = [
  { id: 1, name: "Demo" },
  { id: 2, name: "Other" },
];
const snap = (id, project, version) => ({ id, project, version, name: "Net", source_name: "", source_type: "fixture" });

const routes = (extra = {}) => ({
  "GET /api/projects/": () => ({ body: { count: 2, results: PROJECTS } }),
  "GET /api/projects/1/snapshots/": () => ({ body: { count: 2, results: [snap(5, 1, 2), snap(4, 1, 1)] } }),
  "GET /api/snapshots/5/topology/": () => ({ body: TOPOLOGY }),
  ...extra,
});

describe("TopologyPage", () => {
  it("loads the latest snapshot of the first project and shows summary stats", async () => {
    const { calls } = mockFetch(routes());
    render(<TopologyPage />);
    expect(await screen.findByTestId("graph-stub")).toBeInTheDocument();
    expect(screen.getByLabelText("Project")).toHaveValue("1");
    expect(screen.getByLabelText("Snapshot")).toHaveValue("5");
    expect(screen.getByText("Resources").nextSibling).toHaveTextContent("10");
    expect(screen.getByText("Public subnets").nextSibling).toHaveTextContent("1");
    expect(screen.getByText("Instances with public IP").nextSibling).toHaveTextContent("1");
    expect(calls.map((c) => c.url)).toContain("/api/snapshots/5/topology/");
  });

  it("warns about one-sided security group rules using resource names", async () => {
    mockFetch(routes());
    render(<TopologyPage />);
    const warning = await screen.findByText("One-sided security-group rules");
    expect(warning.parentElement).toHaveTextContent("app → db: only one side declares the rule.");
    expect(screen.getByText("One-sided SG rules").nextSibling).toHaveTextContent("1");
  });

  it("opens the focused snapshot when arriving from the Import screen", async () => {
    mockFetch(
      routes({
        "GET /api/snapshots/4/topology/": () => ({ body: { ...TOPOLOGY, snapshot: 4, version: 1 } }),
      }),
    );
    render(<TopologyPage focus={{ projectId: 1, snapshotId: 4 }} />);
    await screen.findByTestId("graph-stub");
    await waitFor(() => expect(screen.getByLabelText("Snapshot")).toHaveValue("4"));
  });

  it("switches snapshot when the user picks another one", async () => {
    const { calls } = mockFetch(
      routes({ "GET /api/snapshots/4/topology/": () => ({ body: { ...TOPOLOGY, snapshot: 4, version: 1 } }) }),
    );
    render(<TopologyPage />);
    await screen.findByTestId("graph-stub");
    await userEvent.selectOptions(screen.getByLabelText("Snapshot"), "4");
    await waitFor(() => expect(calls.map((c) => c.url)).toContain("/api/snapshots/4/topology/"));
  });

  it("toggles resource-type filters and passes them to the graph", async () => {
    mockFetch(routes());
    render(<TopologyPage />);
    await screen.findByTestId("graph-stub");
    await userEvent.click(screen.getByRole("checkbox", { name: "Security groups" }));
    expect(screen.getByTestId("hidden")).toHaveTextContent("security_group");
    await userEvent.click(screen.getByRole("checkbox", { name: "Security groups" }));
    expect(screen.getByTestId("hidden")).toHaveTextContent("");
  });

  it("shows details after a node is selected in the graph", async () => {
    mockFetch(routes());
    render(<TopologyPage />);
    await userEvent.click(await screen.findByRole("button", { name: "node:sg-web" }));
    const panel = screen.getByRole("complementary", { name: "Resource details" });
    expect(within(panel).getByRole("heading", { name: "web" })).toBeInTheDocument();
    expect(within(panel).getByText("tcp/443 from 0.0.0.0/0")).toBeInTheDocument();
  });

  it("explains how to get started when there are no projects", async () => {
    mockFetch({ "GET /api/projects/": () => ({ body: { count: 0, results: [] } }) });
    render(<TopologyPage />);
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    expect(screen.queryByTestId("graph-stub")).not.toBeInTheDocument();
  });

  it("explains when a project has no snapshots", async () => {
    mockFetch({
      "GET /api/projects/": () => ({ body: { count: 1, results: [PROJECTS[0]] } }),
      "GET /api/projects/1/snapshots/": () => ({ body: { count: 0, results: [] } }),
    });
    render(<TopologyPage />);
    expect(await screen.findByText("This project has no snapshots yet")).toBeInTheDocument();
  });

  it("shows reference problems reported by the API", async () => {
    mockFetch(
      routes({
        "GET /api/snapshots/5/topology/": () => ({
          body: { ...TOPOLOGY, issues: [{ code: "dangling_reference", message: "i-1 refers to subnet 'x'", resource_id: "i-1" }] },
        }),
      }),
    );
    render(<TopologyPage />);
    expect(await screen.findByText("1 reference problem(s) in this snapshot")).toBeInTheDocument();
    expect(screen.getByText("i-1 refers to subnet 'x'")).toBeInTheDocument();
  });

  it("shows an actionable error if the topology cannot be built", async () => {
    mockFetch(
      routes({
        "GET /api/snapshots/5/topology/": () => ({
          status: 422,
          body: { error: { code: "invalid_configuration", message: "The uploaded configuration is invalid." } },
        }),
      }),
    );
    render(<TopologyPage />);
    expect(await screen.findByText("Could not build the topology")).toBeInTheDocument();
    expect(screen.queryByTestId("graph-stub")).not.toBeInTheDocument();
  });

  it("shows an error when projects cannot be loaded", async () => {
    mockFetch({
      "GET /api/projects/": () => {
        throw new TypeError("Failed to fetch");
      },
    });
    render(<TopologyPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load data");
  });
});