import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { INTERACTION } from "../../test/findingsFixture.js";
import { mockFetch } from "../../test/mockFetch.js";
import CopilotPanel from "./CopilotPanel.jsx";

afterEach(() => vi.unstubAllGlobals());

const FINDING = { id: 11 };
const META = {
  provider: "meta",
  model: "muse-spark-1.3",
  configured: true,
  is_meta_model: true,
};
const DEMO = {
  provider: "mock",
  model: "offline-demo",
  configured: true,
  is_meta_model: false,
};

const routes = (extra = {}, status = META) => ({
  "GET /api/copilot/status/": () => ({ body: status }),
  "GET /api/findings/11/explain/": () => ({ body: { interaction: null } }),
  ...extra,
});

describe("CopilotPanel", () => {
  it("offers to explain and shows a Meta-labelled grounded answer", async () => {
    const { calls } = mockFetch(
      routes({
        "POST /api/findings/11/explain/": () => ({
          body: { interaction: INTERACTION },
        }),
      }),
    );
    render(<CopilotPanel finding={FINDING} />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Explain with AI" }),
    );

    expect(
      await screen.findByText(/Anyone on the internet/),
    ).toBeInTheDocument();
    expect(screen.getByText("Meta model · muse-spark-1.3")).toBeInTheDocument();
    expect(
      screen.getByText("Remove the rule open to 0.0.0.0/0"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("sg-web · tcp/22: remove the 0.0.0.0/0 entry"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Admins can use Session Manager."),
    ).toBeInTheDocument();
    expect(screen.getByText(/Routes were not evaluated/)).toBeInTheDocument();
    expect(
      screen.getByText(/nothing is applied to any cloud account/),
    ).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST").body).toEqual({
      refresh: false,
    });
    expect(
      screen.getByRole("button", { name: "Ask again" }),
    ).toBeInTheDocument();
  });

  it("shows a previously saved answer without calling the model", async () => {
    const { calls } = mockFetch(
      routes({
        "GET /api/findings/11/explain/": () => ({
          body: { interaction: { ...INTERACTION, cached: true } },
        }),
      }),
    );
    render(<CopilotPanel finding={FINDING} />);
    expect(
      await screen.findByText(/Anyone on the internet/),
    ).toBeInTheDocument();
    expect(screen.getByText("saved answer")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("offers a manual simulation when the answer has no safe automatic proposal", async () => {
    mockFetch(
      routes({
        "GET /api/findings/11/explain/": () => ({
          body: {
            interaction: {
              ...INTERACTION,
              proposed_change: null,
              explanation: "A human must decide the legitimate SSH source.",
            },
          },
        }),
      }),
    );
    render(
      <CopilotPanel
        finding={{
          id: 11,
          snapshot: 8,
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
        }}
      />,
    );

    expect(
      await screen.findByRole("heading", {
        name: "Manual digital twin simulation",
      }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Trusted IPv4 CIDR")).toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("button", { name: "Hide AI explanation" }),
    );
    expect(
      screen.queryByText("A human must decide the legitimate SSH source."),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText("Trusted IPv4 CIDR")).toBeInTheDocument();
  });

  it("asking again sends refresh=true", async () => {
    const { calls } = mockFetch(
      routes({
        "GET /api/findings/11/explain/": () => ({
          body: { interaction: INTERACTION },
        }),
        "POST /api/findings/11/explain/": () => ({
          body: { interaction: INTERACTION },
        }),
      }),
    );
    render(<CopilotPanel finding={FINDING} />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Ask again" }),
    );
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")?.body).toEqual({
        refresh: true,
      }),
    );
  });

  it("labels the offline demo provider as not a Meta model and explains how to enable Meta", async () => {
    mockFetch(
      routes(
        {
          "GET /api/findings/11/explain/": () => ({
            body: {
              interaction: {
                ...INTERACTION,
                source: "offline_demo",
                provider: "mock",
                model: "offline-demo",
                is_meta_model: false,
              },
            },
          }),
        },
        DEMO,
      ),
    );
    render(<CopilotPanel finding={FINDING} />);
    expect(
      await screen.findByText("Offline demo provider — not a Meta model"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/The Meta model provider is not active/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Meta model ·/)).not.toBeInTheDocument();
  });

  it("explains a fallback and its reason", async () => {
    mockFetch(
      routes({
        "GET /api/findings/11/explain/": () => ({
          body: {
            interaction: {
              ...INTERACTION,
              status: "fallback",
              source: "deterministic_fallback",
              is_meta_model: false,
              model: "",
              fallback_reason: "The Meta API request timed out.",
              proposed_change: null,
            },
          },
        }),
      }),
    );
    render(<CopilotPanel finding={FINDING} />);
    expect(
      await screen.findByText("Rule-based fallback — model unavailable"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/The Meta API request timed out\./),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/No safe automatic change could be proposed/),
    ).toBeInTheDocument();
  });

  it("shows API errors such as the hourly limit", async () => {
    mockFetch(
      routes({
        "POST /api/findings/11/explain/": () => ({
          status: 429,
          body: {
            error: {
              code: "ai_budget_exceeded",
              message:
                "The hourly limit for Meta model calls has been reached.",
            },
          },
        }),
      }),
    );
    render(<CopilotPanel finding={FINDING} />);
    await userEvent.click(
      await screen.findByRole("button", { name: "Explain with AI" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("hourly limit");
    expect(
      screen.getByRole("button", { name: "Explain with AI" }),
    ).toBeEnabled();
  });
});
