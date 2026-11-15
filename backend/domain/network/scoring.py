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
# Version of the summary-based score (per-resource dedupe + size normalisation).
SUMMARY_SCORING_VERSION = "1.1"

# Findings on the same resource after the first (worst) one count for this share of their weight.
EXTRA_FINDING_WEIGHT = 0.5
# Up to this many evaluated resources the penalty is not scaled; above it the penalty is divided
# by sqrt(resources / SCALE_FREE_RESOURCES) so a big environment is not always 0.
SCALE_FREE_RESOURCES = 5

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


def compute_score_from_summary(summary: Mapping[str, Any] | None) -> dict[str, Any]:
    """Score a ``rules.summarize(..., resource_count=N)`` summary.

    * per resource only the worst finding counts in full; additional findings on the same resource
      count for ``EXTRA_FINDING_WEIGHT`` of their weight;
    * the total penalty is divided by ``max(1, sqrt(resources / 5))``.

    Summaries without a ``scoring`` block (older analyses and simulations) fall back to
    ``compute_score`` so stored data keeps scoring exactly as before.
    """
    summary = summary or {}
    scoring = summary.get("scoring")
    if not isinstance(scoring, Mapping):
        return compute_score(summary.get("by_severity"))

    worst = scoring.get("worst_by_resource") or {}
    extra = scoring.get("additional_findings") or {}
    resources = _count(scoring.get("resource_count"))
    scale = max(1.0, (resources / SCALE_FREE_RESOURCES) ** 0.5)

    breakdown = []
    raw_penalty = 0.0
    for severity, weight in SEVERITY_PENALTY.items():
        full = _count(worst.get(severity))
        more = _count(extra.get(severity))
        points = full * weight + more * weight * EXTRA_FINDING_WEIGHT
        raw_penalty += points
        breakdown.append(
            {
                "severity": severity,
                "count": full + more,
                "weight": weight,
                "points": round(points, 2),
            }
        )
    penalty = round(raw_penalty / scale)
    value = max(0, MAX_SCORE - penalty)
    return {
        "value": value,
        "max": MAX_SCORE,
        "grade": grade_for(value),
        "penalty": penalty,
        "breakdown": breakdown,
        "scoring_version": SUMMARY_SCORING_VERSION,
        "normalization": {
            "resource_count": resources,
            "scale": round(scale, 2),
            "extra_finding_weight": EXTRA_FINDING_WEIGHT,
        },
    }


def compare_summaries(
    before_summary: Mapping[str, Any] | None, after_summary: Mapping[str, Any] | None
) -> dict[str, Any]:
    """Like ``compare_scores`` but for full summaries (``delta`` > 0 means it got safer)."""
    before = compute_score_from_summary(before_summary)
    after = compute_score_from_summary(after_summary)
    return {"before": before, "after": after, "delta": after["value"] - before["value"]}


__all__ = [
    "EXTRA_FINDING_WEIGHT",
    "GRADES",
    "MAX_SCORE",
    "SCALE_FREE_RESOURCES",
    "SCORING_VERSION",
    "SEVERITY_PENALTY",
    "SUMMARY_SCORING_VERSION",
    "compare_scores",
    "compare_summaries",
    "compute_score",
    "compute_score_from_summary",
    "grade_for",
]
