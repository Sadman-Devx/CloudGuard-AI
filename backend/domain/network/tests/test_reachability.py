import json

import pytest

from domain.network.reachability import (
    ALLOWED,
    BLOCKED,
    CONFIDENCE_TYPE,
    UNKNOWN,
    PathQuery,
    QueryError,
    Reachability,
    evaluate_path,
    validate_query,
)
from domain.network.schema import parse_config

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def load(fixture_dir, name):
    return parse_config(json.loads((fixture_dir / f"{name}.json").read_text(encoding="utf-8")))


def ask(config, source, destination, protocol="tcp", port=443, source_ip=None):
    return evaluate_path(config, PathQuery(source, destination, protocol, port, source_ip))


def checks(result):
    return {s.check: s for s in result.steps}


def two_subnet_config(valid_config):
    """valid_config plus a private subnet (10.0.2.0/24) holding i-2, which sg-2 protects."""
    valid_config["route_tables"].append(
        {"id": "rtb-2", "vpc_id": "vpc-1", "routes": [{"destination_cidr": "10.0.0.0/16", "target": "local"}]}
    )
    valid_config["subnets"].append(
        {"id": "subnet-2", "vpc_id": "vpc-1", "cidr": "10.0.2.0/24", "route_table_id": "rtb-2"}
    )
    valid_config["instances"].append(
        {"id": "i-2", "subnet_id": "subnet-2", "private_ip": "10.0.2.10", "security_group_ids": ["sg-2"]}
    )
    return valid_config


def set_acl(valid_config, ingress=None, egress=None):
    acl = valid_config["network_acls"][0]
    if ingress is not None:
        acl["ingress"] = ingress
    if egress is not None:
        acl["egress"] = egress


def rule(number, action, protocol="tcp", cidr="0.0.0.0/0", low=None, high=None):
    out = {"rule_number": number, "action": action, "protocol": protocol, "cidr": cidr}
    if low is not None:
        out["from_port"], out["to_port"] = low, high
    return out


# --------------------------------------------------------------------------
# internet -> instance
# --------------------------------------------------------------------------


def test_internet_to_public_web_instance_is_allowed_with_a_full_passing_trace(valid_config):
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    assert result.result == ALLOWED
    assert result.reason_codes == ()
    assert [s.check for s in result.steps] == [
        "public_ip",
        "route_to_internet",
        "nacl_ingress",
        "nacl_reply_egress",
        "sg_ingress",
    ]
    assert all(s.status == "pass" for s in result.steps)
    as_dict = result.as_dict()
    assert as_dict["confidence_type"] == CONFIDENCE_TYPE
    assert as_dict["key"] == "internet>i-1:tcp/443"


def test_a_closed_port_is_blocked_by_every_layer_that_denies_it(valid_config):
    result = ask(parse_config(valid_config), "internet", "i-1", port=22)
    assert result.result == BLOCKED
    # The ACL and the security group both deny it; both are reported, not just the first.
    assert set(result.reason_codes) == {"NACL_INGRESS_DENIED", "SG_INGRESS_DENIED"}


def test_no_public_ip_and_no_public_route_are_both_reported(valid_config):
    del valid_config["instances"][0]["public_ip"]
    valid_config["route_tables"][0]["routes"] = [{"destination_cidr": "10.0.0.0/16", "target": "local"}]
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    assert result.result == BLOCKED
    assert result.reason_codes == ("NO_PUBLIC_IP", "NO_PUBLIC_ROUTE")
    # Everything else still passed: the trace shows exactly which layers are at fault.
    assert checks(result)["sg_ingress"].status == "pass"


def test_open_rule_in_a_private_subnet_is_risky_but_not_reachable(fixture_dir):
    """The core product distinction: risky rule != verified reachable path."""
    config = load(fixture_dir, "exposed_database")
    result = ask(config, "internet", "i-db-1", port=5432)
    assert result.result == BLOCKED
    assert result.reason_codes == ("NO_PUBLIC_IP", "NO_PUBLIC_ROUTE")
    assert result.security_group_risk == "OVERLY_BROAD_INGRESS"
    assert checks(result)["sg_ingress"].status == "pass"


def test_database_in_a_public_subnet_with_open_rule_is_verified_reachable(fixture_dir):
    result = ask(load(fixture_dir, "public_database"), "internet", "i-db-1", port=5432)
    assert result.result == ALLOWED
    assert result.security_group_risk == "OVERLY_BROAD_INGRESS"


def test_anonymous_client_is_not_covered_by_a_narrower_cidr(valid_config):
    valid_config["network_acls"] = []
    valid_config["security_groups"][0]["ingress"].append(
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "203.0.113.0/24"}
    )
    config = parse_config(valid_config)

    anonymous = ask(config, "internet", "i-1", port=22)
    inside = ask(config, "internet", "i-1", port=22, source_ip="203.0.113.7")
    outside = ask(config, "internet", "i-1", port=22, source_ip="198.51.100.9")
    assert anonymous.result == BLOCKED and anonymous.reason_codes == ("SG_INGRESS_DENIED",)
    assert inside.result == ALLOWED
    assert outside.result == BLOCKED


def test_default_route_is_required_for_an_anonymous_client_but_not_for_a_covered_one(valid_config):
    valid_config["network_acls"] = []
    valid_config["route_tables"][0]["routes"] = [
        {"destination_cidr": "10.0.0.0/16", "target": "local"},
        {"destination_cidr": "203.0.113.0/24", "target": "igw-1"},
    ]
    valid_config["security_groups"][0]["ingress"][0]["cidr"] = "0.0.0.0/0"
    config = parse_config(valid_config)
    assert ask(config, "internet", "i-1", port=443).reason_codes == ("NO_PUBLIC_ROUTE",)
    assert ask(config, "internet", "i-1", port=443, source_ip="203.0.113.7").result == ALLOWED


# ---- network ACL semantics ------------------------------------------------------------------


def test_nacl_is_stateless_so_a_blocked_reply_blocks_the_path(valid_config):
    set_acl(valid_config, egress=[rule(100, "allow", "tcp", low=80, high=80)])
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    assert result.result == BLOCKED
    assert result.reason_codes == ("NACL_REPLY_EGRESS_DENIED",)
    assert checks(result)["nacl_ingress"].status == "pass"  # the request itself got in


def test_a_partially_open_ephemeral_range_is_unknown_not_guessed(valid_config):
    set_acl(valid_config, egress=[rule(100, "allow", "tcp", low=1024, high=32767)])
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    assert result.result == UNKNOWN
    assert result.reason_codes == ("NACL_REPLY_PARTIAL",)


def test_lowest_rule_number_wins_deny_before_allow(valid_config):
    set_acl(
        valid_config,
        ingress=[rule(100, "allow", "tcp", low=443, high=443), rule(90, "deny", "tcp", low=443, high=443)],
    )
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    assert result.reason_codes == ("NACL_INGRESS_DENIED",)
    matched = checks(result)["nacl_ingress"].evidence["matching_rules"]
    assert matched[0]["rule_number"] == 90 and matched[0]["action"] == "deny"


def test_lowest_rule_number_wins_allow_before_deny(valid_config):
    set_acl(
        valid_config,
        ingress=[rule(90, "allow", "tcp", low=443, high=443), rule(100, "deny", "tcp", low=443, high=443)],
    )
    assert ask(parse_config(valid_config), "internet", "i-1", port=443).result == ALLOWED


def test_nacl_with_no_matching_rule_hits_the_implicit_deny(valid_config):
    set_acl(valid_config, ingress=[])
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    matched = checks(result)["nacl_ingress"].evidence["matching_rules"]
    assert result.reason_codes == ("NACL_INGRESS_DENIED",)
    assert matched[-1]["rule_number"] == "*"


def test_subnet_without_an_acl_is_evaluated_as_the_default_acl_and_says_so(valid_config):
    valid_config["network_acls"] = []
    result = ask(parse_config(valid_config), "internet", "i-1", port=443)
    assert result.result == ALLOWED
    assert result.assumptions == ("subnet-1:DEFAULT_NACL_ASSUMED",)
    assert checks(result)["nacl_ingress"].evidence["assumed"] is True


# --------------------------------------------------------------------------
# instance -> instance
# --------------------------------------------------------------------------


def test_three_tier_paths_in_the_safe_fixture(fixture_dir):
    config = load(fixture_dir, "safe_network")
    assert ask(config, "i-web-1", "i-app-1", port=8000).result == ALLOWED
    assert ask(config, "i-app-1", "i-db-1", port=5432).result == ALLOWED
    # Least privilege: the web tier cannot talk to the database, at either end.
    web_to_db = ask(config, "i-web-1", "i-db-1", port=5432)
    assert web_to_db.result == BLOCKED
    assert set(web_to_db.reason_codes) == {"SG_EGRESS_DENIED", "SG_INGRESS_DENIED"}
    # The database group has no egress rules, so it cannot initiate anything.
    assert ask(config, "i-db-1", "i-app-1", port=8000).reason_codes == (
        "SG_EGRESS_DENIED",
        "SG_INGRESS_DENIED",
    )
    assert ask(config, "internet", "i-app-1", port=8000).reason_codes[:2] == (
        "NO_PUBLIC_IP",
        "NO_PUBLIC_ROUTE",
    )


def test_broken_app_connectivity_is_diagnosed_to_the_destination_rule(fixture_dir):
    result = ask(load(fixture_dir, "broken_app_connectivity"), "i-app-1", "i-db-1", port=5432)
    assert result.result == BLOCKED
    assert result.reason_codes == ("SG_INGRESS_DENIED",)  # the app's egress is fine
    assert checks(result)["sg_egress"].status == "pass"


def test_security_groups_are_stateful_no_return_rule_is_needed(fixture_dir):
    # sg-db has no egress rules at all, yet app -> db works: the reply is implicitly allowed.
    assert ask(load(fixture_dir, "safe_network"), "i-app-1", "i-db-1", port=5432).result == ALLOWED


def test_traffic_inside_one_subnet_never_crosses_an_acl(valid_config):
    valid_config["instances"].append(
        {"id": "i-2", "subnet_id": "subnet-1", "private_ip": "10.0.1.11", "security_group_ids": ["sg-2"]}
    )
    config = parse_config(valid_config)  # acl-1 would deny tcp/8000 if it applied
    result = ask(config, "i-1", "i-2", port=8000)
    assert result.result == ALLOWED
    assert checks(result)["nacl_ingress"].status == "not_applicable"
    assert checks(result)["nacl_ingress"].code == "SAME_SUBNET"


def test_cross_subnet_traffic_is_checked_by_the_acl_at_every_boundary(valid_config):
    config_dict = two_subnet_config(valid_config)
    # i-1 (sg-1 egress: all) -> i-2 (sg-2 ingress 8000 from sg-1). subnet-1 has acl-1; subnet-2 has none.
    set_acl(
        config_dict,
        ingress=[rule(100, "allow", "tcp", low=443, high=443)],  # reply into subnet-1 is NOT allowed
        egress=[rule(100, "allow", "-1")],
    )
    result = ask(parse_config(config_dict), "i-1", "i-2", port=8000)
    assert result.result == BLOCKED
    assert result.reason_codes == ("NACL_REPLY_INGRESS_DENIED",)
    assert checks(result)["nacl_egress"].status == "pass"


def test_destination_subnet_acl_denying_the_request_is_reported(valid_config):
    config_dict = two_subnet_config(valid_config)
    # Move the ACL to the destination subnet and deny the request there.
    config_dict["network_acls"][0]["subnet_ids"] = ["subnet-2"]
    set_acl(config_dict, ingress=[rule(100, "deny", "-1")])
    result = ask(parse_config(config_dict), "i-1", "i-2", port=8000)
    assert result.reason_codes == ("NACL_INGRESS_DENIED",)


def test_missing_local_route_blocks_the_path(valid_config):
    config_dict = two_subnet_config(valid_config)
    config_dict["route_tables"][1]["routes"] = []  # rtb-2 can no longer deliver anything locally
    result = ask(parse_config(config_dict), "i-2", "i-1", port=443)
    assert "NO_LOCAL_ROUTE" in result.reason_codes
    assert checks(result)["route_forward"].status == "fail"


def test_paths_between_vpcs_are_unknown_not_guessed(valid_config):
    valid_config["vpcs"].append({"id": "vpc-2", "cidr": "10.1.0.0/16"})
    valid_config["route_tables"].append(
        {
            "id": "rtb-v2",
            "vpc_id": "vpc-2",
            "routes": [{"destination_cidr": "10.1.0.0/16", "target": "local"}],
        }
    )
    valid_config["subnets"].append(
        {"id": "subnet-v2", "vpc_id": "vpc-2", "cidr": "10.1.1.0/24", "route_table_id": "rtb-v2"}
    )
    valid_config["security_groups"].append(
        {"id": "sg-v2", "vpc_id": "vpc-2", "name": "other", "ingress": [], "egress": []}
    )
    valid_config["instances"].append(
        {"id": "i-v2", "subnet_id": "subnet-v2", "private_ip": "10.1.1.10", "security_group_ids": ["sg-v2"]}
    )
    result = ask(parse_config(valid_config), "i-1", "i-v2", port=443)
    assert result.result == UNKNOWN
    assert result.reason_codes == ("UNSUPPORTED_CROSS_VPC",)


def test_icmp_is_reported_unknown(valid_config):
    result = ask(parse_config(valid_config), "internet", "i-1", protocol="icmp", port=None)
    assert result.result == UNKNOWN
    assert result.reason_codes == ("UNSUPPORTED_PROTOCOL",)


def test_a_peer_security_group_rule_only_matches_members_of_that_group(valid_config):
    config_dict = two_subnet_config(valid_config)
    config_dict["network_acls"] = []
    # i-3 is in sg-2 only, so it is not in sg-1 and must not match sg-2's "from sg-1" rule.
    config_dict["instances"].append(
        {"id": "i-3", "subnet_id": "subnet-2", "private_ip": "10.0.2.11", "security_group_ids": ["sg-2"]}
    )
    config = parse_config(config_dict)
    assert ask(config, "i-1", "i-2", port=8000).result == ALLOWED  # i-1 is in sg-1
    # sg-2 has no egress rules, so i-3 cannot even leave; the ingress side is reported too.
    blocked = ask(config, "i-3", "i-2", port=8000)
    assert blocked.result == BLOCKED
    assert "SG_INGRESS_DENIED" in blocked.reason_codes


# --------------------------------------------------------------------------
# whole-engine properties
# --------------------------------------------------------------------------


def test_every_pair_in_every_fixture_is_deterministic_and_json_serialisable(sample_fixture):
    _, data = sample_fixture
    config = parse_config(data)
    engine = Reachability(config)
    sources = ["internet", *(i.id for i in config.instances)]
    for source in sources:
        for destination in (i.id for i in config.instances if i.id != source):
            for port in (22, 443, 5432, 8000):
                query = PathQuery(source, destination, "tcp", port)
                first, second = engine.evaluate(query), engine.evaluate(query)
                assert first.as_dict() == second.as_dict()
                json.dumps(first.as_dict())
                assert first.result in (ALLOWED, BLOCKED, UNKNOWN)
                # A verdict of "allowed" can never coexist with a failing step.
                if first.result == ALLOWED:
                    assert not first.reason_codes and all(s.status != "fail" for s in first.steps)


# --------------------------------------------------------------------------
# validate_query (untrusted input)
# --------------------------------------------------------------------------


def test_validate_query_accepts_a_good_question(valid_config):
    query = validate_query(
        {
            "source": "internet",
            "destination": "i-1",
            "protocol": "tcp",
            "port": 443,
            "source_ip": "203.0.113.7",
        },
        parse_config(valid_config),
    )
    assert query.key == "internet@203.0.113.7>i-1:tcp/443"


@pytest.mark.parametrize(
    "raw, fragment",
    [
        ("not an object", "must be an object"),
        ({"source": "nope", "destination": "i-1", "protocol": "tcp", "port": 1}, "source must be"),
        ({"source": "internet", "destination": "nope", "protocol": "tcp", "port": 1}, "destination must be"),
        ({"source": "i-1", "destination": "internet", "protocol": "tcp", "port": 1}, "not modelled"),
        ({"source": "i-1", "destination": "i-1", "protocol": "tcp", "port": 1}, "must be different"),
        ({"source": "internet", "destination": "i-1", "protocol": "-1", "port": 1}, "protocol must be"),
        ({"source": "internet", "destination": "i-1", "protocol": "tcp", "port": 70000}, "port must be"),
        ({"source": "internet", "destination": "i-1", "protocol": "tcp", "port": True}, "port must be"),
        ({"source": "internet", "destination": "i-1", "protocol": "tcp", "port": "80"}, "port must be"),
        ({"source": "internet", "destination": "i-1", "protocol": "tcp", "port": 1, "x": 1}, "unknown field"),
        (
            {
                "source": "internet",
                "destination": "i-1",
                "protocol": "tcp",
                "port": 1,
                "source_ip": "10.0.1.5",
            },
            "public internet address",
        ),
        (
            {"source": "internet", "destination": "i-1", "protocol": "tcp", "port": 1, "source_ip": "::1"},
            "IPv4",
        ),
        (
            {"source": "internet", "destination": "i-1", "protocol": "tcp", "port": 1, "source_ip": "banana"},
            "IPv4",
        ),
    ],
)
def test_validate_query_rejects_bad_input(valid_config, raw, fragment):
    with pytest.raises(QueryError) as exc:
        validate_query(raw, parse_config(valid_config))
    assert any(fragment in message for message in exc.value.errors), exc.value.errors


def test_validate_query_rejects_source_ip_for_an_instance_source(valid_config):
    config = parse_config(two_subnet_config(valid_config))
    raw = {"source": "i-2", "destination": "i-1", "protocol": "tcp", "port": 1, "source_ip": "203.0.113.7"}
    with pytest.raises(QueryError, match="only valid when the source is 'internet'"):
        validate_query(raw, config)


@pytest.mark.parametrize("bad", [[], {}, 5, None])
def test_validate_query_survives_unhashable_or_wrong_typed_ids(valid_config, bad):
    raw = {"source": bad, "destination": bad, "protocol": "tcp", "port": 1}
    with pytest.raises(QueryError):
        validate_query(raw, parse_config(valid_config))


def test_validate_query_reports_every_problem_at_once(valid_config):
    with pytest.raises(QueryError) as exc:
        validate_query(
            {"source": "x", "destination": "y", "protocol": "gre", "port": 1}, parse_config(valid_config)
        )
    assert len(exc.value.errors) == 3