import copy
import json

import pytest

from domain.network.proposals import ProposalError, parse_answer, validate_change
from domain.network.schema import parse_config


@pytest.fixture
def config(fixture_dir):
    return parse_config(json.loads((fixture_dir / "exposed_database.json").read_text()))


def good(**overrides):
    change = {
        "action": "replace_ingress_source",
        "security_group_id": "sg-db",
        "protocol": "tcp",
        "from_port": 5432,
        "to_port": 5432,
        "new_source_security_group_id": "sg-app",
        "new_cidr": None,
    }
    change.update(overrides)
    return change


def errors_for(raw, config, sg="sg-db"):
    with pytest.raises(ProposalError) as exc:
        validate_change(raw, config, sg)
    return exc.value.errors


def test_valid_replace_source(config):
    change = validate_change(good(), config, "sg-db")
    assert change.action == "replace_ingress_source"
    assert change.new_source_security_group_id == "sg-app"
    assert change.as_dict()["from_port"] == 5432


def test_port_shorthand_is_accepted(config):
    raw = good()
    del raw["from_port"], raw["to_port"]
    raw["port"] = 5432
    assert validate_change(raw, config, "sg-db").to_port == 5432


def test_valid_remove_and_restrict(config):
    remove = validate_change(
        good(action="remove_ingress_rule", new_source_security_group_id=None, port=None), config, "sg-db"
    )
    assert remove.new_source_security_group_id is None and remove.new_cidr is None
    restrict = validate_change(
        good(action="restrict_ingress_cidr", new_source_security_group_id=None, new_cidr="203.0.113.0/24"),
        config,
        "sg-db",
    )
    assert restrict.new_cidr == "203.0.113.0/24"


@pytest.mark.parametrize("raw", [None, [], "x", 5])
def test_non_object_rejected(config, raw):
    assert "must be an object" in errors_for(raw, config)[0]


def test_unsupported_action_rejected(config):
    assert any("action must be one of" in e for e in errors_for(good(action="delete_security_group"), config))


def test_unknown_security_group_rejected(config):
    assert any(
        "does not exist" in e for e in errors_for(good(security_group_id="sg-nope"), config, "sg-nope")
    )


def test_cannot_change_a_different_group_than_the_finding(config):
    assert any("may only change sg-db" in e for e in errors_for(good(security_group_id="sg-web"), config))


def test_new_source_must_exist_same_vpc_and_differ(config):
    assert any(
        "does not exist" in e for e in errors_for(good(new_source_security_group_id="sg-ghost"), config)
    )
    assert any("differ" in e for e in errors_for(good(new_source_security_group_id="sg-db"), config))


def test_new_source_in_other_vpc_rejected(fixture_dir):
    data = json.loads((fixture_dir / "exposed_database.json").read_text())
    data = copy.deepcopy(data)
    data["vpcs"].append({"id": "vpc-2", "cidr": "10.9.0.0/16", "name": "other"})
    data["security_groups"].append(
        {"id": "sg-other", "vpc_id": "vpc-2", "name": "other", "ingress": [], "egress": []}
    )
    config = parse_config(data)
    assert any("same VPC" in e for e in errors_for(good(new_source_security_group_id="sg-other"), config))


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "0.0.0.0/4", "banana", "::/0", None, "10.0.0.0/7"])
def test_restrict_cidr_must_be_narrow_ipv4(config, cidr):
    raw = good(action="restrict_ingress_cidr", new_source_security_group_id=None, new_cidr=cidr)
    assert any("new_cidr must be" in e for e in errors_for(raw, config))


def test_wrong_fields_for_action_rejected(config):
    assert any("must not set new_cidr" in e for e in errors_for(good(new_cidr="10.0.0.0/8"), config))
    raw = good(action="remove_ingress_rule")
    assert any("must not set a new source" in e for e in errors_for(raw, config))


@pytest.mark.parametrize("port", [-1, 70000, "5432", True, None])
def test_bad_ports_rejected(config, port):
    assert errors_for(good(from_port=port, to_port=port), config)


def test_reversed_port_range_rejected(config):
    assert errors_for(good(from_port=5440, to_port=5432), config)


def test_bad_protocol_rejected(config):
    assert any("protocol must be" in e for e in errors_for(good(protocol="icmp"), config))


def test_must_target_an_existing_world_open_rule(config):
    # 5432 is world-open on sg-db, 8080 is not.
    assert any("nothing to replace" in e for e in errors_for(good(from_port=8080, to_port=8080), config))
    # sg-app has no world-open ingress at all
    raw = good(security_group_id="sg-app", new_source_security_group_id="sg-web")
    assert any("nothing to replace" in e for e in errors_for(raw, config, "sg-app"))


def test_all_problems_are_reported_together(config):
    errors = errors_for(good(action="nope", protocol="gre", security_group_id="x"), config)
    assert len(errors) >= 3


# ---------------------------------------------------------------- whole answers


def answer(**overrides):
    base = {
        "explanation": "The database allows anyone to connect.",
        "proposed_change": good(),
        "assumptions": ["App traffic comes from sg-app."],
        "uncertainty": "Routes were not evaluated.",
    }
    base.update(overrides)
    return base


def test_valid_answer_always_requires_simulation(config):
    result = parse_answer(answer(requires_simulation=False), config, "sg-db").as_dict()
    assert result["requires_simulation"] is True
    assert result["proposed_change"]["new_source_security_group_id"] == "sg-app"


def test_null_proposal_is_allowed(config):
    assert parse_answer(answer(proposed_change=None), config, "sg-db").proposed_change is None


def test_explanation_required(config):
    with pytest.raises(ProposalError):
        parse_answer(answer(explanation="   "), config, "sg-db")


def test_text_is_sanitised_and_capped(config):
    result = parse_answer(answer(explanation="a\x00b" + "x" * 5000), config, "sg-db")
    assert "\x00" not in result.explanation and len(result.explanation) <= 1500


def test_assumptions_validated(config):
    for bad in ("text", [1], ["x"] * 20):
        with pytest.raises(ProposalError):
            parse_answer(answer(assumptions=bad), config, "sg-db")


def test_invalid_proposal_fails_whole_answer_with_prefix(config):
    with pytest.raises(ProposalError) as exc:
        parse_answer(answer(proposed_change=good(action="drop_table")), config, "sg-db")
    assert exc.value.errors[0].startswith("proposed_change:")


def test_non_object_answer_rejected(config):
    with pytest.raises(ProposalError):
        parse_answer([], config, "sg-db")