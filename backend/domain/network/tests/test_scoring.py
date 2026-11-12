from domain.network.scoring import (
    SEVERITY_PENALTY,
    compare_scores,
    compute_score,
    grade_for,
)


def test_no_findings_scores_100():
    score = compute_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    assert score["value"] == 100
    assert score["grade"] == "A"
    assert score["penalty"] == 0


def test_penalties_are_applied_per_severity():
    score = compute_score({"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1})
    assert score["penalty"] == sum(SEVERITY_PENALTY.values())
    assert score["value"] == 100 - sum(SEVERITY_PENALTY.values())
    by_severity = {row["severity"]: row for row in score["breakdown"]}
    assert by_severity["critical"]["points"] == 25
    assert by_severity["info"]["points"] == 1


def test_score_never_goes_below_zero():
    score = compute_score({"critical": 10})
    assert score["value"] == 0
    assert score["grade"] == "F"


def test_missing_and_invalid_counts_are_treated_as_zero():
    assert compute_score(None)["value"] == 100
    assert compute_score({})["value"] == 100
    assert compute_score({"high": "3", "medium": -2, "low": True, "bogus": 5})["value"] == 100


def test_grade_boundaries():
    assert grade_for(100) == "A"
    assert grade_for(90) == "A"
    assert grade_for(89) == "B"
    assert grade_for(75) == "B"
    assert grade_for(74) == "C"
    assert grade_for(60) == "C"
    assert grade_for(59) == "D"
    assert grade_for(40) == "D"
    assert grade_for(39) == "F"
    assert grade_for(0) == "F"


def test_compare_scores_reports_improvement():
    result = compare_scores({"critical": 1, "high": 1}, {"high": 1})
    assert result["before"]["value"] == 60
    assert result["after"]["value"] == 85
    assert result["delta"] == 25


def test_compare_scores_reports_regression():
    assert compare_scores({}, {"critical": 1})["delta"] == -25