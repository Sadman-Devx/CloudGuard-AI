import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch } from "../test/mockFetch.js";
import StatusPage from "./StatusPage.jsx";

afterEach(() => vi.unstubAllGlobals());

const HEALTHY = { status: "ok", service: "cloudguard-api", version: "0.2.0", database: "ok" };

describe("StatusPage", () => {
  it("shows a loading state, then the healthy backend details", async () => {
    mockFetch({ "GET /api/health/": () => ({ body: HEALTHY }) });
    render(<StatusPage />);
    expect(screen.getByRole("status")).toHaveTextContent("Contacting the API");
    await waitFor(() => expect(screen.getByTestId("status-badge")).toHaveTextContent("Operational"));
    expect(screen.getByText("cloudguard-api")).toBeInTheDocument();
    expect(screen.getByText("0.2.0")).toBeInTheDocument();
  });

  it("shows a degraded warning when the database check fails (HTTP 503)", async () => {
    mockFetch({
      "GET /api/health/": () => ({ status: 503, body: { ...HEALTHY, status: "degraded", database: "error" } }),
    });
    render(<StatusPage />);
    await waitFor(() => expect(screen.getByTestId("status-badge")).toHaveTextContent("Degraded"));
    expect(screen.getByText(/dependency is failing/i)).toBeInTheDocument();
  });

  it("shows an actionable error when the API cannot be reached, and can retry", async () => {
    let healthy = false;
    mockFetch({
      "GET /api/health/": () => {
        if (!healthy) throw new TypeError("Failed to fetch");
        return { body: HEALTHY };
      },
    });
    render(<StatusPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Is the backend running?");
    expect(screen.getByTestId("status-badge")).toHaveTextContent("Unreachable");

    healthy = true;
    await userEvent.click(screen.getByRole("button", { name: "Re-check" }));
    await waitFor(() => expect(screen.getByTestId("status-badge")).toHaveTextContent("Operational"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
