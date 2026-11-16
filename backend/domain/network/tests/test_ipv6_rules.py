"""IPv6 sources in security-group rules and ACL entries: accepted, detected, never mistaken for IPv4."""

import json
from pathlib import Path

from domain.network.reachability import PathQuery, Reachability
from domain.network.rules import evaluate
from domain.network.schema import parse_config, validate_config

SAMPLES = Path(__file__).resolve().parents[4] / "sample_data" / "aws"


def _raw():
    return json.loads((SAMPLES / "exposed_database.json").read_text())


def test_ipv6_is_accepted_in_rules_but_still_rejected_for_vpcs():
    raw = _raw()
    raw["security_groups"][0]["ingress"].append(
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "::/0"}
    )
    assert validate_config(raw).ok

    raw["vpcs"][0]["cidr"] = "2001:db8::/56"
    assert any(e.code == "unsupported_ipv6" for e in validate_config(raw).errors)


def test_world_open_ipv6_ssh_is_a_finding():
    raw = _raw()
    raw["security_groups"][0]["ingress"] = [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "::/0"}
    ]
    findings = evaluate(parse_config(raw))
    ssh = [f for f in findings if f.rule_id == "SG-001"]
    assert ssh and ssh[0].evidence["matching_rules"][0]["cidr"] == "::/0"


def test_an_ipv6_only_rule_does_not_let_the_ipv4_internet_in():
    raw = _raw()
    target = next(i for i in raw["instances"] if i.get("public_ip"))
    for sg in raw["security_groups"]:
        if sg["id"] in target["security_group_ids"]:
            sg["ingress"] = [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "::/0"}]
    config = parse_config(raw)
    result = Reachability(config).evaluate(PathQuery("internet", target["id"], "tcp", 22))
    assert result.result == "blocked"
