import json

import pytest

from domain.network.rules import (
    RULES,
    SEVERITIES,
    evaluate,
    summarize,
)
from domain.network.schema import parse_config


def run(data):
    return evaluate(parse_config(data))


def ids(findings):
    return [(f.rule_id, f.resource_id) for f in findings]


def load(fixture_dir, name):
    return json.loads((fixture_dir / f"{name}.json").read_text())


def tcp(port, cidr="0.0.0.0/0", to_port=None):
    return {"protocol": "tcp", "from_port": port, "to_port": to_port or port, "cidr": cidr}


def set_ingress(data, sg_id, rules):
    sg = next(s for s in data["security_groups"] if s["id"] == sg_id)
    sg["ingress"] = rules


def set_egress(data, sg_id, rules):
    sg = next(s for s in data["security_groups"] if s["id"] == sg_id)
    sg["egress"] = rules


# ------------------------------------------------------------------ catalogue


def test_catalogue_has_all_six_rules_with_remediation_and_limitations():
    assert sorted(RULES) == [f"SG-00{i}" for i in range(1, 7)]
    for info in RULES.values():
        assert info.title and info.description and info.remediation and info.limitations


# ------------------------------------------------------------------ safe fixtures


def test_safe_network_has_no_findings(fixture_dir):
    assert run(load(fixture_dir, "safe_network")) == []


def test_broken_app_connectivity_has_no_findings(fixture_dir):
    # Its problem is a missing allow-rule (connectivity), not an over-broad one.
    assert run(load(fixture_dir, "broken_app_connectivity")) == []


# ------------------------------------------------------------------ seeded risky fixture


def test_exposed_database_fixture_findings(fixture_dir):
    findings = run(load(fixture_dir, "exposed_database"))
    assert ids(findings) == [
        ("SG-001", "sg-web"),
        ("SG-003", "sg-db"),
        ("SG-004", "sg-db"),
        ("SG-006", "sg-app"),
    ]
    by_rule = {f.rule_id: f for f in findings}
    # sg-web has a public instance in a public subnet -> internet-facing candidate -> high
    assert by_rule["SG-001"].severity == "high"
    assert by_rule["SG-001"].evidence["context"]["exposure"] == "internet_facing_candidate"
    # sg-db instance is private with no public IP -> no public path -> medium
    assert by_rule["SG-003"].severity == "medium"
    assert by_rule["SG-003"].evidence["context"]["exposure"] == "no_public_path"
    assert by_rule["SG-006"].severity == "low"


def test_findings_are_deterministic(fixture_dir):
    data = load(fixture_dir, "exposed_database")
    assert [f.as_dict() for f in run(data)] == [f.as_dict() for f in run(data)]


def test_findings_sorted_by_severity_then_rule(fixture_dir):
    findings = run(load(fixture_dir, "exposed_database"))
    ranks = [SEVERITIES.index(f.severity) for f in findings]
    assert ranks == sorted(ranks)


# ------------------------------------------------------------------ each rule: positive + negative


@pytest.mark.parametrize(
    ("rule_id", "port"), [("SG-001", 22), ("SG-002", 3389), ("SG-003", 5432), ("SG-004", 3306)]
)
def test_port_rules_positive(valid_config, rule_id, port):
    set_ingress(valid_config, "sg-1", [tcp(port)])
    findings = [f for f in run(valid_config) if f.rule_id == rule_id]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_id == "sg-1"
    assert finding.evidence["matching_rules"][0]["from_port"] == port
    assert finding.evidence["matching_rules"][0]["direction"] == "ingress"
    assert finding.remediation


@pytest.mark.parametrize("rule_id", ["SG-001", "SG-002", "SG-003", "SG-004"])
def test_port_rules_negative_other_port(valid_config, rule_id):
    set_ingress(valid_config, "sg-1", [tcp(8080)])
    assert not [f for f in run(valid_config) if f.rule_id == rule_id]


@pytest.mark.parametrize("port", [22, 3389, 5432, 3306])
def test_port_rules_negative_restricted_source(valid_config, port):
    set_ingress(valid_config, "sg-1", [tcp(port, cidr="203.0.113.0/24")])
    assert run(valid_config) == [f for f in run(valid_config) if f.rule_id == "SG-006"]


def test_port_rule_negative_security_group_source(valid_config):
    set_ingress(
        valid_config,
        "sg-1",
        [{"protocol": "tcp", "from_port": 22, "to_port": 22, "source_security_group_id": "sg-2"}],
    )
    assert not [f for f in run(valid_config) if f.rule_id == "SG-001"]


def test_port_inside_range_is_detected(valid_config):
    set_ingress(valid_config, "sg-1", [tcp(20, to_port=30)])
    findings = [f for f in run(valid_config) if f.rule_id == "SG-001"]
    assert len(findings) == 1
    assert findings[0].evidence["matching_rules"][0]["to_port"] == 30


def test_udp_on_ssh_port_is_not_ssh(valid_config):
    set_ingress(
        valid_config, "sg-1", [{"protocol": "udp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}]
    )
    assert not [f for f in run(valid_config) if f.rule_id == "SG-001"]


def test_multiple_matching_rules_are_one_finding(valid_config):
    set_ingress(valid_config, "sg-1", [tcp(22), tcp(20, to_port=25)])
    findings = [f for f in run(valid_config) if f.rule_id == "SG-001"]
    assert len(findings) == 1
    assert [m["index"] for m in findings[0].evidence["matching_rules"]] == [0, 1]


def test_all_traffic_ingress_is_sg005_and_suppresses_port_findings(valid_config):
    set_ingress(valid_config, "sg-1", [{"protocol": "-1", "cidr": "0.0.0.0/0"}])
    findings = run(valid_config)
    assert [f.rule_id for f in findings if f.resource_id == "sg-1" and f.rule_id != "SG-006"] == ["SG-005"]
    sg005 = next(f for f in findings if f.rule_id == "SG-005")
    assert sg005.evidence["also_covers"] == {"SG-001": 22, "SG-002": 3389, "SG-003": 5432, "SG-004": 3306}
    assert sg005.severity == "critical"  # internet-facing candidate


def test_full_tcp_range_counts_as_all_ports(valid_config):
    set_ingress(valid_config, "sg-1", [tcp(0, to_port=65535)])
    assert "SG-005" in {f.rule_id for f in run(valid_config)}


def test_all_traffic_from_private_cidr_is_not_flagged(valid_config):
    set_ingress(valid_config, "sg-1", [{"protocol": "-1", "cidr": "10.0.0.0/16"}])
    assert "SG-005" not in {f.rule_id for f in run(valid_config)}


def test_port_rule_and_all_traffic_rule_both_reported(valid_config):
    set_ingress(valid_config, "sg-1", [tcp(22), {"protocol": "-1", "cidr": "0.0.0.0/0"}])
    rules = {f.rule_id for f in run(valid_config) if f.resource_id == "sg-1"}
    assert {"SG-001", "SG-005"} <= rules


def test_unrestricted_egress_sg006(valid_config):
    findings = [f for f in run(valid_config) if f.rule_id == "SG-006"]
    assert [f.resource_id for f in findings] == ["sg-1"]  # sg-1 has -1 -> 0.0.0.0/0 egress
    assert findings[0].severity == "low"
    assert findings[0].evidence["matching_rules"][0]["direction"] == "egress"


def test_restricted_egress_is_clean(valid_config):
    set_egress(valid_config, "sg-1", [tcp(8000, cidr="10.0.0.0/16")])
    assert not [f for f in run(valid_config) if f.rule_id == "SG-006"]


# ------------------------------------------------------------------ severity depends on context


def test_severity_internet_facing(valid_config):
    set_ingress(valid_config, "sg-1", [tcp(22)])
    assert next(f for f in run(valid_config) if f.rule_id == "SG-001").severity == "high"


def test_severity_no_public_ip_is_medium(valid_config):
    valid_config["instances"][0].pop("public_ip")
    set_ingress(valid_config, "sg-1", [tcp(22)])
    finding = next(f for f in run(valid_config) if f.rule_id == "SG-001")
    assert finding.severity == "medium"
    assert finding.evidence["context"]["exposure"] == "no_public_path"


def test_severity_public_ip_but_private_subnet_is_not_a_candidate(valid_config):
    valid_config["route_tables"][0]["routes"] = [{"destination_cidr": "10.0.0.0/16", "target": "local"}]
    set_ingress(valid_config, "sg-1", [tcp(22)])
    finding = next(f for f in run(valid_config) if f.rule_id == "SG-001")
    assert finding.evidence["context"]["exposure"] == "no_public_path"
    assert finding.severity == "medium"


def test_severity_unattached_group_is_low(valid_config):
    valid_config["instances"][0]["security_group_ids"] = ["sg-2"]
    set_ingress(valid_config, "sg-1", [tcp(22)])
    finding = next(f for f in run(valid_config) if f.rule_id == "SG-001")
    assert finding.severity == "low"
    assert finding.evidence["context"]["exposure"] == "unattached"
    assert finding.evidence["context"]["attached_instances"] == []


def test_sg005_severity_scale(valid_config):
    set_ingress(valid_config, "sg-1", [{"protocol": "-1", "cidr": "0.0.0.0/0"}])
    assert next(f for f in run(valid_config) if f.rule_id == "SG-005").severity == "critical"
    valid_config["instances"][0].pop("public_ip")
    assert next(f for f in run(valid_config) if f.rule_id == "SG-005").severity == "high"
    valid_config["instances"][0]["security_group_ids"] = ["sg-2"]
    assert next(f for f in run(valid_config) if f.rule_id == "SG-005").severity == "medium"


def test_summaries_do_not_claim_exploitability(fixture_dir):
    for finding in run(load(fixture_dir, "exposed_database")):
        text = finding.summary.lower()
        assert "exploit" not in text and "vulnerab" not in text


def test_summarize_counts(fixture_dir):
    summary = summarize(run(load(fixture_dir, "exposed_database")))
    assert summary["total"] == 4
    assert summary["by_severity"] == {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 0}
    assert summary["by_rule"] == {"SG-001": 1, "SG-003": 1, "SG-004": 1, "SG-006": 1}


def test_evaluate_does_not_mutate_input(valid_config):
    before = json.dumps(valid_config, sort_keys=True)
    run(valid_config)
    assert json.dumps(valid_config, sort_keys=True) == before