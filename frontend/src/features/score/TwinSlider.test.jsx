import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import ScoreGauge from "./ScoreGauge.jsx";
import TwinSlider from "./TwinSlider.jsx";

const SCORE = {
  before: { value: 60, max: 100, grade: "C" },
  after: { value: 85, max: 100, grade: "B" },
  delta: 25,
};

const FINDINGS = {
  resolved: [
    { rule_id: "SG-003", resource_id: "sg-db", severity: "high", title: "Open database port" },
  ],
  remaining: [
    { rule_id: "SG-006", resource_id: "sg-app", severity: "medium", title: "Unused group" },
  ],
  introduced: [
    { rule_id: "SG-004", resource_id: "sg-app", severity: "low", title: "Broad egress" },
  ],
};

describe("ScoreGauge", () => {
  it("exposes the score and grade to assistive tech", () => {
    render(<ScoreGauge value={72} grade="C" />);
    expect(
      screen.getByRole("img", { name: "Security score: 72 out of 100, grade C" }),
    ).toBeInTheDocument();
  });

  it("clamps out-of-range values", () => {
    render(<ScoreGauge value={140} grade="A" />);
    expect(screen.getByRole("img", { name: /100 out of 100/ })).toBeInTheDocument();
  });
});

describe("TwinSlider", () => {
  it("renders nothing without a score", () => {
    const { container } = render(<TwinSlider score={null} findings={FINDINGS} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("starts on the before side and lists fixed findings", () => {
    render(<TwinSlider score={SCORE} findings={FINDINGS} />);
    expect(screen.getByText(/60 → 85/)).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Findings before" })).toBeInTheDocument();
    expect(screen.getByText(/Open database port/)).toBeInTheDocument();
    expect(screen.queryByText(/Broad egress/)).not.toBeInTheDocument();
  });

  it("switches to the after side when the slider passes halfway", () => {
    render(<TwinSlider score={SCORE} findings={FINDINGS} />);
    fireEvent.change(screen.getByLabelText("Before and after slider"), {
      target: { value: "100" },
    });
    expect(screen.getByRole("list", { name: "Findings after" })).toBeInTheDocument();
    expect(screen.queryByText(/Open database port/)).not.toBeInTheDocument();
    expect(screen.getByText(/Broad egress/)).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: "Score after the change: 85 out of 100, grade B" }),
    ).toBeInTheDocument();
  });

  it("interpolates the displayed score while dragging", () => {
    render(<TwinSlider score={SCORE} findings={FINDINGS} />);
    fireEvent.change(screen.getByLabelText("Before and after slider"), {
      target: { value: "40" },
    });
    // 60 + 25 * 0.4 = 70, still the "before" side
    expect(
      screen.getByRole("img", { name: "Score before the change: 70 out of 100, grade C" }),
    ).toBeInTheDocument();
  });

  it("has Before and After buttons that move the slider", async () => {
    render(<TwinSlider score={SCORE} findings={FINDINGS} />);
    await userEvent.click(screen.getByRole("button", { name: "After" }));
    expect(screen.getByLabelText("Before and after slider")).toHaveValue("100");
    await userEvent.click(screen.getByRole("button", { name: "Before" }));
    expect(screen.getByLabelText("Before and after slider")).toHaveValue("0");
  });

  it("describes a regression honestly", () => {
    const worse = {
      before: { value: 100, max: 100, grade: "A" },
      after: { value: 75, max: 100, grade: "B" },
      delta: -25,
    };
    render(<TwinSlider score={worse} findings={{ resolved: [], remaining: [], introduced: [] }} />);
    expect(screen.getByText(/-25 points riskier/)).toBeInTheDocument();
    expect(screen.getByText("No findings on this side.")).toBeInTheDocument();
  });
});