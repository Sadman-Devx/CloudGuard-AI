import copy
import json

import pytest

from domain.network import simulation as sim_module
from domain.network.proposals import ProposedChange, validate_change
from domain.network.reachability import PathQuery
from domain.network.schema import parse_config
from domain.network.simulation import (
    MAX_REQUIRED_PATHS,
    SimulationError,
    apply_change,
    classify_change,
    parse_required_paths,
    probe_ports,
    simulate,
)

DB_FIX = {
    "action": "replace_ingress_source",
    "security_group_id": "sg-db",
    "protocol": "tcp",
    "port": 5432,
    "new_source_security_group_id": "sg-app",
}


def load_dict(fixture_dir, name):
    return json.loads((fixture_dir / f"{name}.json").read_text(encoding="utf-8"))


def load(fixture_dir, name):
    return parse_config(load_dict(fixture_dir, name))


def change_for(config, raw=None, group="sg-db"):
    return validate_change(raw or DB_FIX, config, group)


def by_key(result):
    return {c["key"]: c for c in result.connectivity}


# --------------------------------------------------------------------------
# apply_change
# --------------------------------------------------------------------------


def test_apply_change_returns_a_clone_and_never_touches_the_original(fixture_dir):
    config = load(fixture_dir, "public_database")
    before = copy.deepcopy(config)
    applied = apply_change(config, change_for(config))
    assert config == before  # frozen dataclasses: the original is unchanged
    assert applied.config is not config
    original_db = next(g for g in config.security_groups if g.id == "sg-db")
    changed_db = next(g for g in applied.config.security_groups if g.id == "sg-db")
    assert original_db.ingress[0].cidr == "0.0.0.0/0"
    assert changed_db.ingress[0].cidr is None
    assert changed_db.ingress[0].peer_security_group_id == "sg-app"
    assert changed_db.ingress[0].from_port == 5432


def test_apply_change_restrict_and_remove(fixture_dir):
    config = load(fixture_dir, "public_database")
    restrict = change_for(
        config,
        {
            "action": "restrict_ingress_cidr",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "port": 5432,
            "new_cidr": "203.0.113.0/24",
        },
    )
    group = next(g for g in apply_change(config, restrict).config.security_groups if g.id == "sg-db")
    assert [r.cidr for r in group.ingress] == ["203.0.113.0/24"]

    remove = change_for(
        config,
        {"action": "remove_ingress_rule", "security_group_id": "sg-db", "protocol": "tcp", "port": 5432},
    )
    applied = apply_change(config, remove)
    group = next(g for g in applied.config.security_groups if g.id == "sg-db")
    assert group.ingress == ()
    assert applied.modifications[0]["after"] is None


def test_a_replacement_identical_to_an_existing_rule_is_merged_not_duplicated(fixture_dir):
    data = load_dict(fixture_dir, "public_database")
    db = next(g for g in data["security_groups"] if g["id"] == "sg-db")
    db["ingress"].append(
        {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "source_security_group_id": "sg-app"}
    )
    config = parse_config(data)
    applied = apply_change(config, change_for(config))
    group = next(g for g in applied.config.security_groups if g.id == "sg-db")
    assert len(group.ingress) == 1
    assert applied.modifications[0]["note"] == "merged into an identical existing rule"


def test_a_rule_wider_than_the_proposal_is_changed_whole_and_flagged(fixture_dir):
    data = load_dict(fixture_dir, "public_database")
    db = next(g for g in data["security_groups"] if g["id"] == "sg-db")
    db["ingress"] = [{"protocol": "-1", "cidr": "0.0.0.0/0"}]
    config = parse_config(data)
    applied = apply_change(config, change_for(config))
    assert [w["code"] for w in applied.warnings] == ["RULE_BROADER_THAN_PROPOSAL"]
    group = next(g for g in applied.config.security_groups if g.id == "sg-db")
    assert group.ingress[0].protocol == "-1" and group.ingress[0].peer_security_group_id == "sg-app"


def test_apply_change_refuses_when_nothing_matches(fixture_dir):
    config = load(fixture_dir, "safe_network")  # sg-db has no world rule
    bogus = ProposedChange("remove_ingress_rule", "sg-db", "tcp", 5432, 5432)
    with pytest.raises(SimulationError, match="No ingress rule open to 0.0.0.0/0"):
        apply_change(config, bogus)
    with pytest.raises(SimulationError, match="does not exist"):
        apply_change(config, ProposedChange("remove_ingress_rule", "sg-nope", "tcp", 1, 1))


def test_probe_ports():
    tcp_one = ProposedChange("remove_ingress_rule", "sg", "tcp", 5432, 5432)
    tcp_range = ProposedChange("remove_ingress_rule", "sg", "tcp", 5000, 5001)
    everything = ProposedChange("remove_ingress_rule", "sg", "-1", None, None)
    assert probe_ports(tcp_one) == (("tcp", 5432),)
    assert probe_ports(tcp_range) == (("tcp", 5000), ("tcp", 5001))
    assert probe_ports(everything) == (("tcp", 22), ("tcp", 3306), ("tcp", 3389), ("tcp", 5432))


@pytest.mark.parametrize(
    "before, after, expected",
    [
        ("allowed", "allowed", "preserved"),
        ("allowed", "blocked", "lost"),
        ("blocked", "allowed", "newly_allowed"),
        ("blocked", "blocked", "still_blocked"),
        ("unknown", "blocked", "inconclusive"),
        ("allowed", "unknown", "inconclusive"),
        ("unknown", "unknown", "inconclusive"),
    ],
)
def test_classify_change(before, after, expected):
    assert classify_change(before, after) == expected


# --------------------------------------------------------------------------
# simulate: the headline scenarios
# --------------------------------------------------------------------------


def test_fixing_a_verified_exposure_closes_the_internet_path_and_keeps_the_app_path(fixture_dir):
    """The Day 6 'done when': a fix reduces broad access without breaking app -> db."""
    config = load(fixture_dir, "public_database")
    result = simulate(config, change_for(config))

    paths = by_key(result)
    internet = paths["internet>i-db-1:tcp/5432"]
    assert (internet["before"], internet["after"], internet["change"]) == ("allowed", "blocked", "lost")
    assert internet["role"] == "exposure" and not internet["required"]
    assert internet["after_reason_codes"] == ["SG_INGRESS_DENIED"]

    app = paths["i-app-1>i-db-1:tcp/5432"]
    assert (app["before"], app["after"], app["change"]) == ("allowed", "allowed", "preserved")
    assert app["required"]

    assert [f["rule_id"] for f in result.findings["resolved"]] == ["SG-003"]
    assert result.findings["introduced"] == []
    assert result.outcome == "improves_security"
    assert result.recommended is True
    assert result.required_source == "inferred"
    assert "Resolves SG-003 on sg-db." in result.summary_lines


def test_fixing_a_risky_rule_that_was_never_reachable_still_resolves_the_finding(fixture_dir):
    config = load(fixture_dir, "exposed_database")
    result = simulate(config, change_for(config))
    internet = by_key(result)["internet>i-db-1:tcp/5432"]
    assert (internet["before"], internet["after"], internet["change"]) == (
        "blocked",
        "blocked",
        "still_blocked",
    )
    assert [f["rule_id"] for f in result.findings["resolved"]] == ["SG-003"]
    assert result.recommended is True


def test_the_original_configuration_is_unchanged_by_a_simulation(fixture_dir):
    config = load(fixture_dir, "public_database")
    snapshot = copy.deepcopy(config)
    simulate(config, change_for(config))
    assert config == snapshot


def test_the_output_is_deterministic_and_json_serialisable(fixture_dir):
    config = load(fixture_dir, "public_database")
    first, second = simulate(config, change_for(config)), simulate(config, change_for(config))
    assert first.as_dict() == second.as_dict()
    assert first.before == second.before and first.after == second.after
    json.dumps([first.as_dict(), first.before, first.after])


def test_restricting_to_a_trusted_public_range_keeps_that_range_working(fixture_dir):
    config = load(fixture_dir, "public_database")
    change = change_for(
        config,
        {
            "action": "restrict_ingress_cidr",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "port": 5432,
            "new_cidr": "203.0.113.0/24",
        },
    )
    result = simulate(config, change)
    paths = by_key(result)
    assert paths["internet>i-db-1:tcp/5432"]["change"] == "lost"  # anonymous internet is shut out
    trusted = paths["internet@203.0.113.1>i-db-1:tcp/5432"]
    assert trusted["required"] and trusted["change"] == "preserved"  # the trusted range still works
    assert result.recommended is True


def test_restricting_to_a_private_cidr_only_requires_hosts_that_worked_before(fixture_dir):
    config = load(fixture_dir, "public_database")
    change = change_for(
        config,
        {
            "action": "restrict_ingress_cidr",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "port": 5432,
            "new_cidr": "10.0.0.0/16",
        },
    )
    result = simulate(config, change)
    required = {c["key"] for c in result.connectivity if c["required"]}
    # app -> db worked and stays required; web -> db never worked, so it is not demanded now.
    assert required == {"i-app-1>i-db-1:tcp/5432"}
    assert result.outcome == "improves_security"


# --------------------------------------------------------------------------
# simulate: safety properties (a fix must never be wrongly recommended)
# --------------------------------------------------------------------------


def test_a_change_that_breaks_a_required_path_is_never_recommended(fixture_dir):
    config = load(fixture_dir, "public_database")
    remove = change_for(
        config,
        {"action": "remove_ingress_rule", "security_group_id": "sg-db", "protocol": "tcp", "port": 5432},
    )
    required = [PathQuery("i-app-1", "i-db-1", "tcp", 5432)]
    result = simulate(config, remove, required)
    assert result.required_source == "explicit"
    assert result.outcome == "breaks_required_connectivity"
    assert result.recommended is False
    assert "Required path i-app-1 -> i-db-1 tcp/5432 is blocked after the change." in result.summary_lines


def test_a_change_with_nothing_to_verify_reduces_exposure_but_is_not_recommended(fixture_dir):
    config = load(fixture_dir, "public_database")
    remove = change_for(
        config,
        {"action": "remove_ingress_rule", "security_group_id": "sg-db", "protocol": "tcp", "port": 5432},
    )
    result = simulate(config, remove)  # removal infers no required paths
    assert result.required_source == "none"
    assert result.outcome == "improves_security"
    assert result.recommended is False
    assert "NO_REQUIRED_PATHS" in {w["code"] for w in result.warnings}
    assert "Also removes access: i-app-1 -> i-db-1 tcp/5432." in result.summary_lines


def test_a_proposed_source_group_with_no_members_cannot_be_verified(fixture_dir):
    data = load_dict(fixture_dir, "public_database")
    data["security_groups"].append(
        {"id": "sg-orphan", "vpc_id": "vpc-main", "name": "orphan", "ingress": [], "egress": []}
    )
    config = parse_config(data)
    raw = {**DB_FIX, "new_source_security_group_id": "sg-orphan"}
    result = simulate(config, change_for(config, raw))
    assert result.required_source == "none"
    assert result.recommended is False


def test_a_required_path_that_was_never_working_is_reported_not_hidden(fixture_dir):
    config = load(fixture_dir, "public_database")
    result = simulate(config, change_for(config), [PathQuery("i-web-1", "i-db-1", "tcp", 5432)])
    assert result.outcome == "required_connectivity_unmet"
    assert result.recommended is False
    assert "REQUIRED_PATH_BLOCKED" in {w["code"] for w in result.warnings}


def test_unverifiable_required_paths_make_the_result_inconclusive(fixture_dir):
    data = load_dict(fixture_dir, "public_database")
    # Allow only part of the ephemeral range back out: internet replies become 'unknown'.
    data["network_acls"][0]["egress"][0].update(from_port=1024, to_port=32767)
    config = parse_config(data)
    required = [PathQuery("internet", "i-db-1", "tcp", 5432, "203.0.113.9")]
    result = simulate(config, change_for(config), required)
    only = by_key(result)["internet@203.0.113.9>i-db-1:tcp/5432"]
    assert only["before"] == "unknown"
    assert result.outcome == "inconclusive"
    assert result.recommended is False


def test_introduced_findings_are_flagged_as_new_risk(fixture_dir, monkeypatch):
    """Defensive branch: the three supported actions only narrow access, so force a regression."""
    config = load(fixture_dir, "public_database")
    real = sim_module.evaluate_rules
    calls = []

    def fake(cfg):
        calls.append(1)
        found = real(cfg)
        if len(calls) == 2:  # the 'after' evaluation
            extra = copy.copy(found[0]) if found else real(load(fixture_dir, "exposed_database"))[0]
            object.__setattr__(extra, "rule_id", "SG-999")
            object.__setattr__(extra, "resource_id", "sg-new")
            found = [*found, extra]
        return found

    monkeypatch.setattr(sim_module, "evaluate_rules", fake)
    result = simulate(config, change_for(config))
    assert result.outcome == "introduces_new_risk"
    assert result.recommended is False
    assert [f["rule_id"] for f in result.findings["introduced"]] == ["SG-999"]


def test_default_nacl_assumption_is_surfaced_as_a_warning(fixture_dir):
    config = load(fixture_dir, "public_database")  # the private subnet has no ACL
    warning = next(
        w for w in simulate(config, change_for(config)).warnings if w["code"] == "DEFAULT_NACL_ASSUMED"
    )
    assert "subnet-private" in warning["message"]


def test_traces_explain_why_the_path_changed(fixture_dir):
    config = load(fixture_dir, "public_database")
    result = simulate(config, change_for(config))
    after = next(p for p in result.after["paths"] if p["key"] == "internet>i-db-1:tcp/5432")
    sg_step = next(s for s in after["trace"] if s["check"] == "sg_ingress")
    assert sg_step["status"] == "fail" and sg_step["code"] == "SG_INGRESS_DENIED"
    before = next(p for p in result.before["paths"] if p["key"] == "internet>i-db-1:tcp/5432")
    assert before["result"] == "allowed" and before["security_group_risk"] == "OVERLY_BROAD_INGRESS"


# --------------------------------------------------------------------------
# parse_required_paths
# --------------------------------------------------------------------------


def test_parse_required_paths_accepts_none_and_good_lists(fixture_dir):
    config = load(fixture_dir, "public_database")
    assert parse_required_paths(None, config) == []
    parsed = parse_required_paths(
        [{"source": "i-app-1", "destination": "i-db-1", "protocol": "tcp", "port": 5432}], config
    )
    assert parsed[0].key == "i-app-1>i-db-1:tcp/5432"


def test_parse_required_paths_reports_all_problems(fixture_dir):
    config = load(fixture_dir, "public_database")
    with pytest.raises(SimulationError) as exc:
        parse_required_paths(
            [
                {"source": "nope", "destination": "i-db-1", "protocol": "tcp", "port": 1},
                {"source": "i-app-1", "destination": "i-db-1", "protocol": "icmp"},
            ],
            config,
        )
    assert any(e.startswith("required_paths[0]") for e in exc.value.errors)
    assert any("only tcp and udp" in e for e in exc.value.errors)


def test_parse_required_paths_rejects_non_lists_and_oversized_lists(fixture_dir):
    config = load(fixture_dir, "public_database")
    with pytest.raises(SimulationError, match="must be a list"):
        parse_required_paths({"a": 1}, config)
    too_many = [{"source": "i-app-1", "destination": "i-db-1", "protocol": "tcp", "port": 5432}] * (
        MAX_REQUIRED_PATHS + 1
    )
    with pytest.raises(SimulationError, match="At most"):
        parse_required_paths(too_many, config)


# --------------------------------------------------------------------------
# every action on every fixture that offers something to fix
# --------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["replace_ingress_source", "restrict_ingress_cidr", "remove_ingress_rule"])
def test_each_action_simulates_cleanly_on_the_risky_fixtures(fixture_dir, action):
    for name in ("exposed_database", "public_database"):
        config = load(fixture_dir, name)
        raw = {"action": action, "security_group_id": "sg-db", "protocol": "tcp", "port": 5432}
        if action == "replace_ingress_source":
            raw["new_source_security_group_id"] = "sg-app"
        if action == "restrict_ingress_cidr":
            raw["new_cidr"] = "203.0.113.0/24"
        before = copy.deepcopy(config)
        result = simulate(config, validate_change(raw, config, "sg-db"))
        assert config == before
        assert result.findings["resolved"], (name, action)
        json.dumps([result.as_dict(), result.before, result.after])