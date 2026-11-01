import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { TOPOLOGY } from "../../test/topologyFixture.js";
import DetailPanel from "./DetailPanel.jsx";

const renderPanel = (selection, extra = {}) => {
  const onSelect = vi.fn();
  const onClear = vi.fn();
  render(<DetailPanel topology={TOPOLOGY} selection={selection} onSelect={onSelect} onClear={onClear} {...extra} />);
  return { onSelect, onClear };
};

describe("DetailPanel", () => {
  it("prompts to select something when nothing is selected", () => {
    renderPanel(null);
    expect(screen.getByText(/Select a resource or connection/)).toBeInTheDocument();
  });

  it("shows facts and connections for a node, and navigates to a neighbour", async () => {
    const { onSelect } = renderPanel({ kind: "node", id: "i-web-1" });
    const panel = screen.getByRole("complementary", { name: "Resource details" });
    expect(within(panel).getByRole("heading", { name: "web-1" })).toBeInTheDocument();
    expect(within(panel).getByText("203.0.113.10")).toBeInTheDocument();
    expect(within(panel).getByText(/is in subnet/)).toBeInTheDocument();

    await userEvent.click(within(panel).getByRole("button", { name: "public" }));
    expect(onSelect).toHaveBeenCalledWith({ kind: "node", id: "subnet-public" });
  });

  it("explains a one-sided security group flow in plain language", () => {
    renderPanel({ kind: "edge", id: "sg_traffic:sg-app->sg-db" });
    expect(screen.getByRole("heading", { name: "app → db" })).toBeInTheDocument();
    expect(screen.getByText(/target has no ingress rule that names the source group/)).toBeInTheDocument();
    expect(screen.getByText(/Egress on app/)).toBeInTheDocument();
    expect(screen.queryByText(/Ingress on db/)).not.toBeInTheDocument();
  });

  it("shows both rule lists for an agreed flow", () => {
    renderPanel({ kind: "edge", id: "sg_traffic:sg-web->sg-db" });
    expect(screen.getByText(/Both sides declare this rule/)).toBeInTheDocument();
    expect(screen.getByText("Ingress on db")).toBeInTheDocument();
    expect(screen.getByText("Egress on web")).toBeInTheDocument();
  });

  it("lets the user clear the selection", async () => {
    const { onClear } = renderPanel({ kind: "node", id: "sg-web" });
    await userEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(onClear).toHaveBeenCalled();
  });

  it("falls back gracefully when the selected id no longer exists", () => {
    renderPanel({ kind: "node", id: "gone" });
    expect(screen.getByText(/Select a resource or connection/)).toBeInTheDocument();
  });
});