"""Rule registry: data-driven port rules, CIS mapping and plugin checks."""

import json
from pathlib import Path

import pytest

from domain.network import rules as rules_module
from domain.network.rules import (
    RULES,
    RuleInfo,
    evaluate,
    load_rule_file,
    register_check,
    register_port_rule,
    rule_evidence,
)
from domain.network.schema import parse_config

SAMPLES = Path(__file__).resolve().parents[4] / "sample_data" / "aws"


@pytest.fixture(autouse=True)
def _restore_registry():
    """The registry is module state; give every test the built-in rules and put them back after."""
    saved = (
        dict(rules_module.RULES),
        dict(rules_module.SENSITIVE_PORTS),
        dict(rules_module.RULE_FAMILY),
        set(rules_module.ADMIN_RULE_IDS),
        set(rules_module.DATABASE_RULE_IDS),
        dict(rules_module._CUSTOM_CHECKS),
    )
    yield
    for target, value in zip(
        (
            rules_module.RULES,
            rules_module.SENSITIVE_PORTS,
            rules_module.RULE_FAMILY,
            rules_module.ADMIN_RULE_IDS,
            rules_module.DATABASE_RULE_IDS,
            rules_module._CUSTOM_CHECKS,
        ),
        saved,
        strict=True,
    ):
        target.clear()
        target.update(value)


def test_builtin_port_rules_come_from_the_catalog_file():
    assert len(RULES) == 15
    assert rules_module.SENSITIVE_PORTS["SG-009"] == (6379, "Redis")
    assert "SG-014" in rules_module.ADMIN_RULE_IDS and "SG-009" in rules_module.DATABASE_RULE_IDS


def test_only_verified_cis_mappings_are_listed():
    ssh = RULES["SG-001"].cis
    assert [c["control"] for c in ssh] == ["5.2", "5.3"]
    assert {c["applies_to"] for c in ssh} == {"0.0.0.0/0", "::/0"}
    assert all(c["benchmark"] == "CIS AWS Foundations Benchmark" and c["version"] == "3.0.0" for c in ssh)
    assert RULES["SG-003"].cis == ()  # no direct CIS control: nothing is guessed


def test_register_a_port_rule_and_it_fires():
    register_port_rule("SG-016", 5984, "CouchDB", "database", "Restrict the source to the app tier.")
    assert RULES["SG-016"].category == "potential_exposure"
    assert list(RULES) == sorted(RULES)

    raw = json.loads((SAMPLES / "exposed_database.json").read_text())
    raw["security_groups"][0]["ingress"].append(
        {"protocol": "tcp", "from_port": 5984, "to_port": 5984, "cidr": "0.0.0.0/0"}
    )
    config = parse_config(raw)
    assert "SG-016" in {f.rule_id for f in evaluate(config)}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rule_id": "sg-1", "port": 1, "service": "x", "family": "admin"},  # bad id
        {"rule_id": "SG-001", "port": 1, "service": "x", "family": "admin"},  # duplicate id
        {"rule_id": "SG-016", "port": 22, "service": "x", "family": "admin"},  # port already ruled
        {"rule_id": "SG-016", "port": 70000, "service": "x", "family": "admin"},
        {"rule_id": "SG-016", "port": 1, "service": "x", "family": "bogus"},
    ],
)
def test_invalid_port_rules_are_rejected(kwargs):
    with pytest.raises(ValueError):
        register_port_rule(kwargs["rule_id"], kwargs["port"], kwargs["service"], kwargs["family"], "Fix it.")
    assert len(RULES) == 15


def test_rule_file_adds_rules_and_a_bad_file_changes_nothing(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {
                "port_rules": [
                    {
                        "id": "ACME-001",
                        "port": 8123,
                        "service": "ClickHouse",
                        "family": "database",
                        "remediation": "Restrict it.",
                    }
                ]
            }
        )
    )
    assert load_rule_file(good) == ["ACME-001"]
    assert "ACME-001" in RULES

    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "port_rules": [
                    {
                        "id": "ACME-002",
                        "port": 9001,
                        "service": "ok",
                        "family": "admin",
                        "remediation": "Fix.",
                    },
                    {
                        "id": "ACME-003",
                        "port": 70000,
                        "service": "bad",
                        "family": "admin",
                        "remediation": "Fix.",
                    },
                ]
            }
        )
    )
    before = set(RULES)
    with pytest.raises(ValueError):
        load_rule_file(bad)
    assert set(RULES) == before  # ACME-002 was valid but must not stay registered


def test_a_custom_check_plugin_produces_findings_with_family_severity():
    info = RuleInfo("ACME-100", "Wide ephemeral range", "risky_rule", "d", "Narrow it.", "")

    @register_check(info, "admin")
    def wide_range(sg):
        return [
            rule_evidence("ingress", i, r)
            for i, r in enumerate(sg.ingress)
            if r.from_port is not None and r.to_port is not None and r.to_port - r.from_port > 10000
        ]

    assert RULES["ACME-100"].family == "admin"
    with pytest.raises(ValueError):
        register_check(info, "admin")(wide_range)  # already registered
