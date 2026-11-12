import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch } from "../../test/mockFetch.js";
import SimulationPanel from "./SimulationPanel.jsx";

afterEach(() => vi.unstubAllGlobals());

describe("SimulationPanel", () => {
  it("lets a user manually restrict an ingress CIDR and shows the returned score comparison", async () => {
    const { calls } = mockFetch({
      "POST /api/snapshots/8/simulations/": () => ({
        status: 201,
        body: {
          outcome: "improves_security",
          recommended: true,
          score: {
            before: { value: 70, max: 100, grade: "C" },
            after: { value: 85, max: 100, grade: "B" },
            delta: 15,
          },
          result: {
            warnings: [],
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
    const finding = {
      id: 11,
      resource_id: "sg-web",
      evidence: {
        matching_rules: [
          {
            direction: "ingress",
            index: 0,
            protocol: "tcp",
            from_port: 22,
            to_port: 22,
            cidr: "0.0.0.0/0",
          },
        ],
      },
    };

    render(<SimulationPanel snapshotId={8} finding={finding} />);
    await userEvent.type(
      screen.getByLabelText("Trusted IPv4 CIDR"),
      "203.0.113.0/24",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Simulate this change" }),
    );

    expect(await screen.findByText(/70 → 85/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Collapse" }));
    expect(screen.queryByLabelText("Before and after slider")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Expand" }));
    expect(screen.getByLabelText("Before and after slider")).toBeInTheDocument();
    expect(calls[0].body).toEqual({
      finding_id: 11,
      proposed_change: {
        action: "restrict_ingress_cidr",
        security_group_id: "sg-web",
        protocol: "tcp",
        from_port: 22,
        to_port: 22,
        new_source_security_group_id: null,
        new_cidr: "203.0.113.0/24",
      },
    });
  });

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
