"""Day 7 tests: pure-Python, run with `pytest backend/tests/test_day7_workflow.py`.
Uses an in-memory fake network so no DB/Django is needed."""
import copy
import pytest

from apps.simulations.adapters import Adapters
from apps.simulations.services.workflow import run_for_finding
from domain.network.dashboard import build_dashboard
from domain.network.diff import compare
from domain.network.proposal import ProposalError, validate_proposal

SG = {"sg-db", "sg-app"}

GOOD = {"action": "replace_ingress_source", "security_group_id": "sg-db",
        "protocol": "tcp", "port": 5432, "new_source_security_group_id": "sg-app"}

FIXTURE = {"sgs": {"sg-db": {"ingress": [{"port": 5432, "source": "0.0.0.0/0"}]},
                   "sg-app": {"ingress": []}}}


def fake_evaluate(cfg):
    src = cfg["sgs"]["sg-db"]["ingress"][0]["source"] if cfg["sgs"]["sg-db"]["ingress"] else None
    findings = [{"rule_id": "SG-003", "resource_ref": "sg-db"}] if src == "0.0.0.0/0" else []
    allow_app = src in ("0.0.0.0/0", "sg-app")
    return {"findings": findings, "paths": [
        {"id": "app->db:5432", "result": "allowed" if allow_app else "blocked"},
        {"id": "internet->db:5432", "result": "allowed" if src == "0.0.0.0/0" else "blocked"}]}


def fake_apply(cfg, p):
    cfg["sgs"][p["security_group_id"]]["ingress"][0]["source"] = p.get("new_source_security_group_id", "none")
    return cfg


def make_adapters(saved):
    return Adapters(
        load_finding=lambda i: {"id": i, "snapshot_id": 1} if i == 1 else None,
        load_config=lambda s: FIXTURE,
        sg_ids=lambda c: set(c["sgs"]),
        get_ai_proposal=lambda i: GOOD,
        apply_change=fake_apply, evaluate=fake_evaluate,
        required_paths=lambda c: {"app->db:5432"},
        save_simulation=lambda *a: saved.append(a) or 42,
        project_state=lambda p: {})


# ---- proposal validation (positive + negative) ----
def test_valid_proposal_passes():
    assert validate_proposal(GOOD, SG)["new_source_security_group_id"] == "sg-app"

@pytest.mark.parametrize("bad", [
    "not a dict",
    {**GOOD, "action": "delete_security_group"},
    {**GOOD, "security_group_id": "sg-ghost"},
    {**GOOD, "port": 70000},
    {**GOOD, "port": True},
    {**GOOD, "protocol": "gre"},
    {**GOOD, "new_source_security_group_id": "sg-ghost"},
    {**GOOD, "shell_command": "rm -rf /"},
])
def test_invalid_proposals_rejected(bad):
    with pytest.raises(ProposalError):
        validate_proposal(bad, SG)

def test_cidr_proposal_must_narrow():
    base = {"action": "restrict_ingress_cidr", "security_group_id": "sg-db", "protocol": "tcp", "port": 5432}
    assert validate_proposal({**base, "new_cidr": "10.0.1.0/24"}, SG)["new_cidr"] == "10.0.1.0/24"
    with pytest.raises(ProposalError):
        validate_proposal({**base, "new_cidr": "0.0.0.0/0"}, SG)
    with pytest.raises(ProposalError):
        validate_proposal({**base, "new_cidr": "nonsense"}, SG)


# ---- full flow: AI proposal -> simulate -> diff ----
def test_safe_fix_resolves_finding_and_keeps_app_path():
    saved = []
    original = copy.deepcopy(FIXTURE)
    r = run_for_finding(1, None, make_adapters(saved))
    assert r["verdict"] == "safe_improvement"
    assert [f["rule_id"] for f in r["resolved_findings"]] == ["SG-003"]
    app = next(c for c in r["path_changes"] if c["id"] == "app->db:5432")
    assert app["before"] == app["after"] == "allowed"
    net = next(c for c in r["path_changes"] if c["id"] == "internet->db:5432")
    assert (net["before"], net["after"]) == ("allowed", "blocked")
    assert r["simulation_id"] == 42 and r["read_only"] is True
    assert FIXTURE == original, "original snapshot must not be mutated"

def test_invalid_ai_output_never_reaches_simulator():
    a = make_adapters([])
    a.apply_change = lambda *x: pytest.fail("simulator must not run")
    with pytest.raises(ProposalError):
        run_for_finding(1, {**GOOD, "security_group_id": "sg-ghost"}, a)

def test_missing_finding():
    with pytest.raises(LookupError):
        run_for_finding(99, None, make_adapters([]))

def test_breaking_change_is_flagged():
    before = fake_evaluate(FIXTURE)
    after = {"findings": [], "paths": [{"id": "app->db:5432", "result": "blocked"},
                                       {"id": "internet->db:5432", "result": "blocked"}]}
    r = compare(before, after, {"app->db:5432"})
    assert r["verdict"] == "breaks_required_connectivity"
    assert r["warnings"][0]["code"] == "REQUIRED_PATH_BROKEN"

def test_unknown_required_path_needs_review():
    before = {"findings": [{"rule_id": "SG-003", "resource_ref": "x"}], "paths": [{"id": "p", "result": "allowed"}]}
    after = {"findings": [], "paths": [{"id": "p", "result": "unknown"}]}
    assert compare(before, after, {"p"})["verdict"] == "needs_review"

def test_new_finding_needs_review_and_no_change_detected():
    f = {"rule_id": "SG-001", "resource_ref": "sg-a"}
    same = {"findings": [f], "paths": []}
    assert compare(same, same)["verdict"] == "no_improvement"
    r = compare({"findings": [], "paths": []}, same)
    assert r["verdict"] == "needs_review" and r["warnings"][0]["code"] == "NEW_FINDING"


# ---- dashboard ----
def test_dashboard_stages_and_counts():
    d = build_dashboard({"project": {"id": 1}, "snapshot": {"version": 2}, "analyzed": True,
                         "findings": [{"severity": "high"}, {"severity": "high"}, {"severity": "low"}],
                         "ai_interactions": 1, "simulations": [{"verdict": "safe_improvement"}]})
    assert d["finding_counts"]["high"] == 2 and d["safe_fixes"] == 1
    assert d["next_step"] is None and all(s["done"] for s in d["stages"])

def test_empty_dashboard_points_to_upload():
    d = build_dashboard({"project": {"id": 1}, "snapshot": None, "findings": []})
    assert d["next_step"] == "Config uploaded" and d["snapshot_version"] is None
