"""SG-007..SG-015, split-CIDR detection, summary scoring, wide-CIDR warnings, extensions schema."""

import copy
import json
from pathlib import Path

from domain.network.extensions import parse_extensions
from domain.network.proposals import ProposedChange, wide_cidr_warning
from domain.network.rules import evaluate, summarize, world_rule_indexes
from domain.network.schema import SecurityGroupRule, parse_config, validate_config
from domain.network.scoring import compute_score, compute_score_from_summary

SAMPLES = Path(__file__).resolve().parents[4] / "sample_data" / "aws"


def _raw(name="exposed_database"):
    return json.loads((SAMPLES / f"{name}.json").read_text())


def _with_ingress(extra):
    raw = _raw()
    for sg in raw["security_groups"]:
        if sg["id"] == "sg-web":
            sg["ingress"].extend(extra)
    return parse_config(raw)


def _rule(cidr, port=6379, protocol="tcp"):
    return SecurityGroupRule(protocol, port, port, cidr)


def _tcp(port, cidr):
    return {"protocol": "tcp", "from_port": port, "to_port": port, "cidr": cidr}


# ---- detection --------------------------------------------------------------------------------


def test_new_ports_are_detected():
    config = _with_ingress([_tcp(p, "0.0.0.0/0") for p in (6379, 27017, 2375, 445)])
    ids = {f.rule_id for f in evaluate(config) if f.resource_id == "sg-web"}
    assert {"SG-009", "SG-008", "SG-014", "SG-011"} <= ids


def test_docker_api_is_critical_when_internet_facing():
    config = _with_ingress([_tcp(2375, "0.0.0.0/0")])
    finding = next(f for f in evaluate(config) if f.rule_id == "SG-014")
    assert finding.severity == "critical"


def test_split_world_rule_is_detected_and_marked():
    config = _with_ingress([_tcp(6379, "0.0.0.0/1"), _tcp(6379, "128.0.0.0/1")])
    finding = next(f for f in evaluate(config) if f.rule_id == "SG-009")
    assert all(m.get("split_cidr") for m in finding.evidence["matching_rules"])


def test_half_of_the_internet_is_not_world():
    assert world_rule_indexes([_rule("0.0.0.0/1")], lambda r: True) == []


def test_exact_and_ipv6_world_are_world():
    assert world_rule_indexes([_rule("0.0.0.0/0")], lambda r: True) == [0]
    assert world_rule_indexes([_rule("::/0")], lambda r: True) == [0]


def test_split_rules_for_different_ports_do_not_combine():
    rules = [_rule("0.0.0.0/1", 6379), _rule("128.0.0.0/1", 22)]
    assert world_rule_indexes(rules, lambda r: r.from_port == 6379) == []


# ---- scoring ----------------------------------------------------------------------------------


def _scoring(resources, worst_high, extra_high):
    return {
        "by_severity": {"high": worst_high + extra_high},
        "scoring": {
            "resource_count": resources,
            "worst_by_resource": {"critical": 0, "high": worst_high, "medium": 0, "low": 0, "info": 0},
            "additional_findings": {"critical": 0, "high": extra_high, "medium": 0, "low": 0, "info": 0},
        },
    }


def test_two_findings_on_one_group_count_less_than_two_groups():
    one_group = compute_score_from_summary(_scoring(2, 1, 1))["value"]
    two_groups = compute_score_from_summary(_scoring(2, 2, 0))["value"]
    assert one_group > two_groups


def test_large_environment_is_not_always_zero():
    assert compute_score_from_summary(_scoring(80, 8, 0))["value"] > 0
    assert compute_score({"high": 8})["value"] == 0  # the old flat penalty


def test_summary_without_scoring_block_falls_back_to_old_score():
    summary = {"by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}}
    assert compute_score_from_summary(summary) == compute_score(summary["by_severity"])


def test_summarize_adds_scoring_only_when_asked():
    findings = evaluate(parse_config(_raw()))
    assert "scoring" not in summarize(findings)
    assert summarize(findings, 3)["scoring"]["resource_count"] == 3


# ---- proposals --------------------------------------------------------------------------------


def _change(cidr):
    return ProposedChange("restrict_ingress_cidr", "sg-db", "tcp", 5432, 5432, None, cidr)


def test_wide_cidr_warns_below_slash_16():
    assert wide_cidr_warning(_change("10.0.0.0/8")) is not None
    assert wide_cidr_warning(_change("10.0.0.0/16")) is None
    assert wide_cidr_warning(_change("10.0.1.0/24")) is None


# ---- extensions schema ------------------------------------------------------------------------


def test_fixture_with_extensions_is_valid():
    assert validate_config(_raw("attack_path_demo")).ok


def test_unknown_reference_in_extensions_is_reported_with_path():
    raw = copy.deepcopy(_raw("attack_path_demo"))
    raw["extensions"]["databases"][0]["security_group_ids"] = ["sg-missing"]
    result = validate_config(raw)
    assert not result.ok
    assert any(
        e.path == "extensions.databases[0].security_group_ids[0]" and e.code == "unknown_reference"
        for e in result.errors
    )


def test_unknown_extension_field_is_rejected():
    raw = _raw("attack_path_demo")
    raw["extensions"]["lambdas"] = []
    assert any(e.code == "unknown_field" for e in validate_config(raw).errors)


def test_extension_id_cannot_reuse_a_core_id():
    raw = _raw("attack_path_demo")
    raw["extensions"]["buckets"][0]["id"] = "sg-web"
    assert any(e.code == "duplicate_id" for e in validate_config(raw).errors)


def test_role_permission_must_point_at_a_data_resource():
    ext, issues = parse_extensions(
        {"iam_roles": [{"id": "r1", "permissions": [{"access": "read", "resource_ids": ["nope"]}]}]},
        instance_ids=set(),
        subnet_ids=set(),
        security_group_ids=set(),
        vpc_ids=set(),
    )
    assert issues and not ext.iam_roles[0].permissions
