import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { mockFetch } from "../test/mockFetch.js";
import ImportPage from "./ImportPage.jsx";

afterEach(() => vi.unstubAllGlobals());

const PROJECT = { id: 1, name: "Demo", description: "", created_at: "2026-10-27T00:00:00Z" };
const FIXTURES = [
  { name: "safe_network", title: "Safe network" },
  { name: "exposed_database", title: "Exposed database rules" },
];
const SNAPSHOT = {
  id: 10,
  project: 1,
  version: 1,
  name: "Exposed database rules",
  region: "us-east-1",
  relationship_count: 19,
  warnings: [],
  resource_counts: { vpc: 1, subnet: 2, internet_gateway: 1, route_table: 2, security_group: 3, network_acl: 0, instance: 3 },
};

const base = (extra = {}) => ({
  "GET /api/projects/": () => ({ body: { count: 1, results: [PROJECT] } }),
  "GET /api/fixtures/": () => ({ body: { results: FIXTURES } }),
  ...extra,
});

describe("ImportPage", () => {
  it("imports a sample fixture and shows the validated inventory counts", async () => {
    const { calls } = mockFetch(
      base({ "POST /api/projects/1/snapshots/from-fixture/": () => ({ status: 201, body: SNAPSHOT }) }),
    );
    render(<ImportPage />);
    await userEvent.selectOptions(await screen.findByLabelText("Sample configuration"), "exposed_database");
    await userEvent.click(screen.getByRole("button", { name: "Import sample" }));

    const summary = await screen.findByRole("region", { name: "Imported snapshot" });
    expect(within(summary).getByText(/Snapshot v1 saved and validated/)).toBeInTheDocument();
    expect(within(summary).getByTestId("count-security_group")).toHaveTextContent("3");
    expect(within(summary).getByTestId("count-instance")).toHaveTextContent("3");
    expect(calls.at(-1).body).toEqual({ fixture: "exposed_database" });
  });

  it("lists every validation problem when the backend rejects a configuration", async () => {
    mockFetch(
      base({
        "POST /api/projects/1/snapshots/from-fixture/": () => ({
          status: 422,
          body: {
            error: {
              code: "invalid_configuration",
              message: "The uploaded configuration is invalid.",
              details: [
                { path: "vpcs[0].cidr", code: "invalid_cidr", message: "Invalid CIDR 'x'" },
                { path: "instances[0].private_ip", code: "invalid_ip", message: "bad ip" },
              ],
              request_id: "req-12345678",
            },
          },
        }),
      }),
    );
    render(<ImportPage />);
    await userEvent.selectOptions(await screen.findByLabelText("Sample configuration"), "safe_network");
    await userEvent.click(screen.getByRole("button", { name: "Import sample" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("2 problem(s). Nothing was saved.");
    expect(alert).toHaveTextContent("vpcs[0].cidr");
    expect(alert).toHaveTextContent("invalid_ip");
    expect(alert).toHaveTextContent("req-12345678");
    expect(screen.queryByRole("region", { name: "Imported snapshot" })).not.toBeInTheDocument();
  });

  it("uploads a chosen JSON file with its file name", async () => {
    const { calls } = mockFetch(base({ "POST /api/projects/1/snapshots/": () => ({ status: 201, body: SNAPSHOT }) }));
    render(<ImportPage />);
    const file = new File([JSON.stringify({ schema_version: "1.0", vpcs: [] })], "net.json", {
      type: "application/json",
    });
    await userEvent.upload(await screen.findByLabelText(/upload a configuration/i), file);
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));

    await screen.findByRole("region", { name: "Imported snapshot" });
    expect(calls.at(-1).body).toEqual({ schema_version: "1.0", vpcs: [] });
    expect(calls.at(-1).headers["X-Source-Name"]).toBe("net.json");
  });

  it("rejects non-JSON files in the browser without calling the API", async () => {
    const { calls } = mockFetch(base());
    render(<ImportPage />);
    const file = new File(["{not json"], "bad.json", { type: "application/json" });
    await userEvent.upload(await screen.findByLabelText(/upload a configuration/i), file);
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("not valid JSON");
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("asks for a file when Upload is pressed with none selected", async () => {
    mockFetch(base());
    render(<ImportPage />);
    await userEvent.click(await screen.findByRole("button", { name: "Upload" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Choose a .json file first.");
  });

  it("creates a project and selects it", async () => {
    mockFetch({
      "GET /api/projects/": () => ({ body: { count: 0, results: [] } }),
      "GET /api/fixtures/": () => ({ body: { results: FIXTURES } }),
      "POST /api/projects/": ({ body }) => ({ status: 201, body: { ...PROJECT, id: 7, name: body.name } }),
    });
    render(<ImportPage />);
    expect(await screen.findByText(/Create or select a project/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import sample" })).toBeDisabled();

    await userEvent.type(screen.getByLabelText("New project name"), "Hackathon");
    await userEvent.click(screen.getByRole("button", { name: "Create project" }));

    await waitFor(() => expect(screen.getByLabelText("Project")).toHaveValue("7"));
    expect(screen.getByRole("option", { name: "Hackathon" })).toBeInTheDocument();
  });

  it("shows a clear error if projects cannot be loaded", async () => {
    mockFetch({
      "GET /api/projects/": () => {
        throw new TypeError("Failed to fetch");
      },
      "GET /api/fixtures/": () => ({ body: { results: [] } }),
    });
    render(<ImportPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not load projects");
  });
});
