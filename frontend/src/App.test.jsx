import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import App from "./App.jsx";
import { mockFetch } from "./test/mockFetch.js";

vi.mock("./features/topology/TopologyGraph.jsx", () => ({
  default: () => <div data-testid="graph-stub" />,
}));
afterEach(() => vi.unstubAllGlobals());

describe("App navigation", () => {
  it("renders the four tabs and marks the active one", async () => {
    mockFetch({
      "GET /api/health/": () => ({
        body: { status: "ok", service: "s", version: "1", database: "ok" },
      }),
    });
    render(<App />);
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toHaveTextContent("Status");
    expect(nav).toHaveTextContent("Import");
    expect(nav).toHaveTextContent("Topology");
    expect(nav).toHaveTextContent("Findings");
    expect(screen.getByRole("button", { name: "Status" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByText(/Read-only/)).toBeInTheDocument();
  });

  it("switches to the Topology tab", async () => {
    mockFetch({
      "GET /api/health/": () => ({
        body: { status: "ok", service: "s", version: "1", database: "ok" },
      }),
      "GET /api/projects/": () => ({ body: { count: 0, results: [] } }),
    });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Topology" }));
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
  });

  it("switches to the Findings tab", async () => {
    mockFetch({
      "GET /api/health/": () => ({
        body: { status: "ok", service: "s", version: "1", database: "ok" },
      }),
      "GET /api/projects/": () => ({ body: { count: 0, results: [] } }),
      "GET /api/rules/": () => ({ body: { results: [] } }),
    });
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "Findings" }));
    expect(
      await screen.findByRole("heading", { name: "Security findings" }),
    ).toBeInTheDocument();
  });
});