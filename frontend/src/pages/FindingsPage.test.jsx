import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FINDINGS, INTERACTION, RULES } from "../test/findingsFixture.js";
import { mockFetch } from "../test/mockFetch.js";
import FindingsPage from "./FindingsPage.jsx";

afterEach(() => vi.unstubAllGlobals());

const snap = (id, version) => ({
  id,
  project: 1,
  version,
  name: "Net",
  source_name: "",
  source_type: "fixture",
});

const routes = (extra = {}) => ({
  "GET /api/projects/": () => ({
    body: { count: 1, results: [{ id: 1, name: "Demo" }] },
  }),
  "GET /api/projects/1/snapshots/": () => ({
    body: { count: 1, results: [snap(5, 1)] },
  }),
  "GET /api/snapshots/5/findings/": () => ({ body: FINDINGS }),
  "GET /api/rules/": () => ({ body: { results: RULES } }),
  "GET /api/copilot/status/": () => ({
    body: {
      provider: "mock",
      model: "offline-demo",
      configured: true,
      is_meta_model: false,
    },
  }),
  "GET /api/findings/11/explain/": () => ({ body: { interaction: null } }),
  ...extra,
});

describe("FindingsPage", () => {
  it("lists findings with severity, rule id and affected resource, plus counts", async () => {
    mockFetch(routes());
    render(<FindingsPage />);
    const list = await screen.findByRole("list", { name: "Findings" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("high");
    expect(items[0]).toHaveTextContent("SG-001");
    expect(items[0]).toHaveTextContent("web (sg-web)");
    expect(items[1]).toHaveTextContent("Potential exposure");

    const counts = screen.getByLabelText("Findings by severity");
    expect(within(counts).getAllByText("1")).toHaveLength(2); // one high, one medium
    expect(within(counts).getAllByText("0")).toHaveLength(3);
  });

  it("shows evidence, remediation and limitations for the selected finding", async () => {
    mockFetch(routes());
    render(<FindingsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /SG-001/ }),
    );
    const panel = screen.getByRole("complementary", {
      name: "Finding details",
    });
    expect(
      within(panel).getByText("ingress rule #2: tcp/22 from 0.0.0.0/0"),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText("Remove the 0.0.0.0/0 source."),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText("Not proof of reachability."),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText("Possibly internet-facing (not verified)"),
    ).toBeInTheDocument();
    expect(
      within(panel).getByRole("button", { name: "Explain with AI" }),
    ).toBeInTheDocument();
  });

  it("filters by severity", async () => {
    mockFetch(routes());
    render(<FindingsPage />);
    await screen.findByRole("list", { name: "Findings" });
    await userEvent.selectOptions(screen.getByLabelText("Severity"), "medium");
    const items = within(
      screen.getByRole("list", { name: "Findings" }),
    ).getAllByRole("listitem");
    expect(items).toHaveLength(1);
    expect(items[0]).toHaveTextContent("SG-003");
    await userEvent.selectOptions(
      screen.getByLabelText("Severity"),
      "critical",
    );
    expect(
      screen.getByText("No findings with this severity."),
    ).toBeInTheDocument();
  });

  it("asks to run the analysis when the snapshot was never analysed, then shows results", async () => {
    const { calls } = mockFetch(
      routes({
        "GET /api/snapshots/5/findings/": () => ({
          body: { snapshot: 5, analysis: null, results: [] },
        }),
        "POST /api/snapshots/5/analyze/": () => ({ body: FINDINGS }),
      }),
    );
    render(<FindingsPage />);
    expect(await screen.findByText("Not analysed yet")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Run analysis" }));
    expect(
      await screen.findByRole("list", { name: "Findings" }),
    ).toBeInTheDocument();
    expect(
      calls.some(
        (c) => c.method === "POST" && c.url === "/api/snapshots/5/analyze/",
      ),
    ).toBe(true);
    expect(
      screen.getByRole("button", { name: "Re-run analysis" }),
    ).toBeInTheDocument();
  });

  it("does not present zero findings as proof of security", async () => {
    mockFetch(
      routes({
        "GET /api/snapshots/5/findings/": () => ({
          body: {
            snapshot: 5,
            analysis: {
              ...FINDINGS.analysis,
              summary: {
                total: 0,
                by_severity: {
                  critical: 0,
                  high: 0,
                  medium: 0,
                  low: 0,
                  info: 0,
                },
                by_rule: {},
              },
            },
            results: [],
          },
        }),
      }),
    );
    render(<FindingsPage />);
    const notice = await screen.findByText(
      "No findings from rules SG-001 to SG-006",
    );
    expect(notice.parentElement).toHaveTextContent(
      "does not prove the network is secure",
    );
  });

  it("shows an error when the analysis fails", async () => {
    mockFetch(
      routes({
        "GET /api/snapshots/5/findings/": () => ({
          body: { snapshot: 5, analysis: null, results: [] },
        }),
        "POST /api/snapshots/5/analyze/": () => ({
          status: 422,
          body: {
            error: {
              code: "invalid_configuration",
              message: "The uploaded configuration is invalid.",
            },
          },
        }),
      }),
    );
    render(<FindingsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Run analysis" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid");
  });

  it("explains a selected finding end to end", async () => {
    mockFetch(
      routes({
        "POST /api/findings/11/explain/": () => ({
          body: {
            interaction: {
              ...INTERACTION,
              source: "offline_demo",
              is_meta_model: false,
            },
          },
        }),
      }),
    );
    render(<FindingsPage />);
    await userEvent.click(
      await screen.findByRole("button", { name: /SG-001/ }),
    );
    await userEvent.click(
      await screen.findByRole("button", { name: "Explain with AI" }),
    );
    expect(
      await screen.findByText(/Anyone on the internet/),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Offline demo provider — not a Meta model"),
    ).toBeInTheDocument();
  });

  it("explains how to get started when there are no projects", async () => {
    mockFetch({
      "GET /api/projects/": () => ({ body: { count: 0, results: [] } }),
      "GET /api/rules/": () => ({ body: { results: RULES } }),
    });
    render(<FindingsPage />);
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
  });

  it("opens the focused snapshot", async () => {
    mockFetch(
      routes({
        "GET /api/projects/1/snapshots/": () => ({
          body: { count: 2, results: [snap(6, 2), snap(5, 1)] },
        }),
        "GET /api/snapshots/6/findings/": () => ({
          body: { snapshot: 6, analysis: null, results: [] },
        }),
      }),
    );
    render(<FindingsPage focus={{ projectId: 1, snapshotId: 5 }} />);
    await screen.findByRole("list", { name: "Findings" });
    await waitFor(() =>
      expect(screen.getByLabelText("Snapshot")).toHaveValue("5"),
    );
  });
});