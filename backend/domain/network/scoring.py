"""Deterministic security score (0-100) derived from finding severity counts.

Pure Python (no Django). The score is a plain, explainable function of the findings the rule engine
produced: start at 100 and subtract a fixed penalty per finding, by severity. It is *not* a risk
probability, and 100 does not mean "secure": only the modelled rules (SG-001..SG-006) are counted.

Because it only needs the per-severity counts (``summarize(...)["by_severity"]``), the same function
scores a stored analysis, the "before" side of a simulation and the "after" side of a simulation, so
the two sides are always comparable.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SCORING_VERSION = "1.0"

MAX_SCORE = 100

# Points removed from 100 for each finding of that severity.
SEVERITY_PENALTY: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}

# (minimum score, grade), checked from the top.
GRADES: tuple[tuple[int, str], ...] = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))


def _count(value: Any) -> int:
    """Counts come from stored JSON, so be strict: anything that is not a non-negative int is 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def grade_for(value: int) -> str:
    for minimum, grade in GRADES:
        if value >= minimum:
            return grade
    return GRADES[-1][1]


def compute_score(by_severity: Mapping[str, Any] | None) -> dict[str, Any]:
    """Score a set of findings given as ``{"critical": 1, "high": 2, ...}``."""
    counts = by_severity or {}
    breakdown = []
    penalty = 0
    for severity, weight in SEVERITY_PENALTY.items():
        count = _count(counts.get(severity))
        points = count * weight
        penalty += points
        breakdown.append({"severity": severity, "count": count, "weight": weight, "points": points})
    value = max(0, MAX_SCORE - penalty)
    return {
        "value": value,
        "max": MAX_SCORE,
        "grade": grade_for(value),
        "penalty": penalty,
        "breakdown": breakdown,
        "scoring_version": SCORING_VERSION,
    }


def compare_scores(
    before_by_severity: Mapping[str, Any] | None, after_by_severity: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Score both sides of a change and report the difference (``delta`` > 0 means it got safer)."""
    before = compute_score(before_by_severity)
    after = compute_score(after_by_severity)
    return {"before": before, "after": after, "delta": after["value"] - before["value"]}


__all__ = [
    "GRADES",
    "MAX_SCORE",
    "SCORING_VERSION",
    "SEVERITY_PENALTY",
    "compare_scores",
    "compute_score",
    "grade_for",
]
