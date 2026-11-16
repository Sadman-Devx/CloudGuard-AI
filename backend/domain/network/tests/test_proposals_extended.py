"""Egress, added-rule and network-ACL changes: validation and simulation."""

import copy
import json
from pathlib import Path

import pytest

from domain.network.proposals import ACTIONS, ALL_ACTIONS, ProposalError, validate_change
from domain.network.schema import parse_config, validate_config
from domain.network.simulation import simulate

SAMPLES = Path(__file__).resolve().parents[4] / "sample_data" / "aws"


@pytest.fixture
def raw():
    raw = json.loads((SAMPLES / "exposed_database.json").read_text())
    db = next(i for i in raw["instances"] if i["id"] == "i-db-1")
    raw["network_acls"] = [
        {
            "id": "acl-db",
            "vpc_id": raw["vpcs"][0]["id"],
            "subnet_ids": [db["subnet_id"]],
            "ingress": [
                {
                    "rule_number": 90,
                    "action": "deny",
                    "protocol": "tcp",
                    "cidr": "10.0.0.0/8",
                    "from_port": 5432,
                    "to_port": 5432,
                },
                {"rule_number": 100, "action": "allow", "protocol": "-1", "cidr": "0.0.0.0/0"},
            ],
            "egress": [{"rule_number": 100, "action": "allow", "protocol": "-1", "cidr": "0.0.0.0/0"}],
        }
    ]
    return raw


@pytest.fixture
def config(raw):
    assert validate_config(raw).ok
    return parse_config(raw)


def check(config, body):
    return validate_change(body, config, body["security_group_id"], allowed=ALL_ACTIONS)


def test_the_model_cannot_use_the_extra_actions(config):
    body = {
        "action": "add_ingress_rule",
        "security_group_id": "sg-db",
        "protocol": "tcp",
        "port": 5433,
        "new_source_security_group_id": "sg-app",
    }
    with pytest.raises(ProposalError):
        validate_change(body, config, "sg-db", allowed=ACTIONS)


def test_add_ingress_rule_fixes_connectivity(config):
    change = check(
        config,
        {
            "action": "add_ingress_rule",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "port": 5433,
            "new_source_security_group_id": "sg-app",
        },
    )
    result = simulate(config, change)
    assert result.outcome == "fixes_connectivity" and result.recommended
    assert result.modifications[0]["note"] == "rule added"
    assert change.as_dict()["new_source_security_group_id"] == "sg-app"


@pytest.mark.parametrize(
    "extra",
    [
        {"new_cidr": "0.0.0.0/0"},  # never open the world
        {"new_cidr": "10.0.0.0/16", "new_source_security_group_id": "sg-app"},  # both
        {},  # neither
        {"new_source_security_group_id": "sg-missing"},
    ],
)
def test_add_ingress_rule_rejects_bad_sources(config, extra):
    body = {
        "action": "add_ingress_rule",
        "security_group_id": "sg-db",
        "protocol": "tcp",
        "port": 5433,
        **extra,
    }
    with pytest.raises(ProposalError):
        check(config, body)


def test_restrict_egress_rule_resolves_the_open_egress_finding(config):
    change = check(
        config,
        {
            "action": "restrict_egress_rule",
            "security_group_id": "sg-app",
            "protocol": "-1",
            "allow_protocol": "tcp",
            "allow_port": 5432,
            "new_source_security_group_id": "sg-db",
        },
    )
    result = simulate(config, change)
    assert result.outcome == "improves_security" and result.recommended
    assert {"rule_id": "SG-006", "resource_id": "sg-app"} == {
        k: result.findings["resolved"][0][k] for k in ("rule_id", "resource_id")
    }
    assert result.modifications[0]["direction"] == "egress"


def test_restrict_egress_rule_needs_an_open_egress_rule(config):
    with pytest.raises(ProposalError):
        check(
            config,
            {
                "action": "restrict_egress_rule",
                "security_group_id": "sg-db",
                "protocol": "-1",
                "allow_protocol": "tcp",
                "allow_port": 5432,
                "new_cidr": "10.0.0.0/16",
            },
        )


def test_remove_nacl_rule_only_removes_deny_entries(config):
    ok = check(
        config,
        {
            "action": "remove_nacl_rule",
            "security_group_id": "sg-db",
            "acl_id": "acl-db",
            "direction": "ingress",
            "rule_number": 90,
        },
    )
    assert (ok.protocol, ok.from_port) == ("tcp", 5432)  # filled in from the entry
    with pytest.raises(ProposalError):
        check(
            config,
            {
                "action": "remove_nacl_rule",
                "security_group_id": "sg-db",
                "acl_id": "acl-db",
                "direction": "ingress",
                "rule_number": 100,
            },
        )  # an allow entry


def test_nacl_changes_are_limited_to_acls_covering_the_groups_instances(config, raw):
    other = copy.deepcopy(raw)
    other["network_acls"][0]["id"] = "acl-other"
    other["network_acls"][0]["subnet_ids"] = [
        next(i for i in raw["instances"] if i["id"] == "i-web-1")["subnet_id"]
    ]
    cfg = parse_config(other)
    with pytest.raises(ProposalError):
        check(
            cfg,
            {
                "action": "remove_nacl_rule",
                "security_group_id": "sg-db",
                "acl_id": "acl-other",
                "direction": "ingress",
                "rule_number": 90,
            },
        )


def test_remove_nacl_deny_is_simulated_without_touching_the_original(config):
    change = check(
        config,
        {
            "action": "remove_nacl_rule",
            "security_group_id": "sg-db",
            "acl_id": "acl-db",
            "direction": "ingress",
            "rule_number": 90,
        },
    )
    result = simulate(config, change)
    assert result.modifications[0]["network_acl"] == "acl-db"
    assert any(e.rule_number == 90 for e in config.network_acls[0].ingress)  # original unchanged


def test_add_nacl_allow_rule_rejects_taken_numbers_and_the_world(config):
    base = {
        "action": "add_nacl_allow_rule",
        "security_group_id": "sg-db",
        "acl_id": "acl-db",
        "direction": "ingress",
        "protocol": "tcp",
        "port": 5432,
        "new_cidr": "10.0.1.0/24",
    }
    check(config, {**base, "rule_number": 80})
    with pytest.raises(ProposalError):
        check(config, {**base, "rule_number": 90})  # already used
    with pytest.raises(ProposalError):
        check(config, {**base, "rule_number": 80, "new_cidr": "0.0.0.0/0"})
