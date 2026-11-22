import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import BeforeAfterView from "./BeforeAfterView.jsx";
import { describeRule } from "./describeRule.js";

const result = {
  modifications: [
    {
      security_group: "sg-db",
      index: 0,
      before: { protocol: "tcp", from_port: 5432, to_port: 5432, cidr: "0.0.0.0/0", peer_security_group_id: null },
      after: { protocol: "tcp", from_port: 5432, to_port: 5432, cidr: null, peer_security_group_id: "sg-app" },
      note: null,
    },
  ],
  findings: { before_summary: { total: 4 }, after_summary: { total: 2 } },
  connectivity: [
    { key: "a", label: "i-app-1 -> i-db-1 tcp/5432", change: "preserved", required: true },
    { key: "b", label: "internet -> i-db-1 tcp/5432", change: "lost", required: false },
    { key: "c", label: "i-web-1 -> i-app-1 tcp/22", change: "still_blocked", required: false },
  ],
};

describe("BeforeAfterView", () => {
  it("shows the old rule and the new rule side by side", () => {
    render(<BeforeAfterView result={result} score={null} />);
    expect(screen.getByText("tcp/5432 · 0.0.0.0/0")).toBeInTheDocument();
    expect(screen.getByText("tcp/5432 · sg-app")).toBeInTheDocument();
    expect(screen.getByText("Before this change")).toBeInTheDocument();
    expect(screen.getByText("After this change")).toBeInTheDocument();
  });

  it("lists only the paths whose verdict flips or that are required", () => {
    render(<BeforeAfterView result={result} score={null} />);
    expect(screen.getByText(/internet -> i-db-1 tcp\/5432/)).toBeInTheDocument();
    expect(screen.getByText(/i-app-1 -> i-db-1 tcp\/5432/)).toBeInTheDocument();
    expect(screen.queryByText(/tcp\/22/)).not.toBeInTheDocument();
  });

  it("renders nothing when the result has no changes", () => {
    const { container } = render(<BeforeAfterView result={{ modifications: [], connectivity: [] }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("describes network ACL entries", () => {
    expect(
      describeRule({ rule_number: 90, action: "deny", protocol: "tcp", cidr: "10.0.0.0/8", from_port: 5432, to_port: 5432 }),
    ).toBe("#90 deny tcp/5432 · 10.0.0.0/8");
  });
});
