import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ScoreRing from "./ScoreRing.jsx";
import SeverityBars from "./SeverityBars.jsx";
import TrendChart from "./TrendChart.jsx";

const point = (version, score) => ({
  snapshot_id: version,
  version,
  score,
  grade: score >= 80 ? "A" : "C",
  total: 3,
});

describe("dashboard charts", () => {
  it("draws one point per analysed snapshot", () => {
    const { container } = render(<TrendChart points={[point(1, 40), point(2, 70), point(3, 90)]} />);
    expect(screen.getByRole("img", { name: "Score trend over 3 snapshots" })).toBeInTheDocument();
    expect(container.querySelectorAll("circle")).toHaveLength(3);
  });

  it("says so when there is nothing to draw", () => {
    render(<TrendChart points={[]} />);
    expect(screen.getByText(/no trend to draw/i)).toBeInTheDocument();
  });

  it("shows the score and grade of the ring", () => {
    render(<ScoreRing value={73} grade="C" />);
    expect(screen.getByRole("img", { name: "Score 73 out of 100, grade C" })).toBeInTheDocument();
  });

  it("summarises findings by severity", () => {
    render(<SeverityBars bySeverity={{ critical: 0, high: 2, medium: 1, low: 0, info: 0 }} />);
    expect(
      screen.getByRole("img", { name: "Findings by severity: 2 high, 1 medium" }),
    ).toBeInTheDocument();
  });

  it("has a calm message when there are no findings", () => {
    render(<SeverityBars bySeverity={{}} />);
    expect(screen.getByText(/no findings/i)).toBeInTheDocument();
  });
});
