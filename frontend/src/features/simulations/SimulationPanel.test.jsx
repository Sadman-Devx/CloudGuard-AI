import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch } from "../../test/mockFetch.js";
import SimulationPanel from "./SimulationPanel.jsx";

afterEach(() => vi.unstubAllGlobals());

describe("SimulationPanel", () => {
  it("renders structured simulation warnings without crashing", async () => {
    mockFetch({
      "POST /api/snapshots/8/simulations/": () => ({
        status: 201,
        body: {
          outcome: "improves_security",
          recommended: false,
          result: {
            warnings: [
              {
                code: "NO_REQUIRED_PATHS",
                message: "Required connectivity was not verified.",
              },
            ],
            summary_lines: [],
            findings: {
              before_summary: { total: 1 },
              after_summary: { total: 0 },
              resolved: [],
              remaining: [],
              introduced: [],
            },
            connectivity: [],
          },
        },
      }),
    });

    render(<SimulationPanel snapshotId={8} interactionId={1} />);
    await userEvent.click(
      screen.getByRole("button", { name: "Simulate this change" }),
    );

    expect(
      await screen.findByText("Required connectivity was not verified."),
    ).toBeInTheDocument();
    expect(screen.getByText("Findings: 1 before → 0 after")).toBeInTheDocument();
  });

    it("shows the before/after score slider when the API returns a score", async () => {
    mockFetch({
      "POST /api/snapshots/8/simulations/": () => ({
        status: 201,
        body: {
          outcome: "improves_security",
          recommended: true,
          score: {
            before: { value: 85, max: 100, grade: "B" },
            after: { value: 100, max: 100, grade: "A" },
            delta: 15,
          },
          result: {
            warnings: [],
            summary_lines: [],
            findings: {
              before_summary: { total: 1 },
              after_summary: { total: 0 },
              resolved: [
                {
                  rule_id: "SG-003",
                  resource_id: "sg-db",
                  severity: "high",
                  title: "Open database port",
                },
              ],
              remaining: [],
              introduced: [],
            },
            connectivity: [],
          },
        },
      }),
    });

    render(<SimulationPanel snapshotId={8} interactionId={1} />);
    await userEvent.click(
      screen.getByRole("button", { name: "Simulate this change" }),
    );

    expect(await screen.findByText(/85 → 100/)).toBeInTheDocument();
    expect(screen.getByLabelText("Before and after slider")).toBeInTheDocument();
  });
});
