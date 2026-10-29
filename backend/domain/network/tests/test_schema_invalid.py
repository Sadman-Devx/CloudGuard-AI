"""Invalid inputs: each case must be rejected with a specific, actionable error."""

import pytest

from domain.network import schema
from domain.network.schema import ConfigValidationError, parse_config, validate_config


def issues(result) -> set[tuple[str, str]]:
    return {(e.path, e.code) for e in result.errors}


def _mutate(path_fn):
    def apply(cfg):
        path_fn(cfg)
        return cfg

    return apply


CASES = {
    "top_level_not_object": (lambda cfg: [cfg], "", "invalid_type"),
    "missing_schema_version": (lambda cfg: cfg.pop("schema_version") and cfg, "schema_version", "required"),
    "unsupported_schema_version": (
        lambda cfg: cfg.update(schema_version="2.0") or cfg,
        "schema_version",
        "unsupported_schema_version",
    ),
    "unknown_top_level_field": (lambda cfg: cfg.update(lambdas=[]) or cfg, "lambdas", "unknown_field"),
    "missing_vpcs": (lambda cfg: cfg.pop("vpcs") and cfg, "vpcs", "required"),
    "empty_vpcs": (lambda cfg: cfg.update(vpcs=[]) or cfg, "vpcs", "required"),
    "vpcs_not_list": (lambda cfg: cfg.update(vpcs={}) or cfg, "vpcs", "invalid_type"),
    "bad_region": (lambda cfg: cfg.update(region="Mars") or cfg, "region", "invalid_region"),
    "vpc_cidr_prefix_out_of_range": (
        lambda cfg: cfg["vpcs"][0].update(cidr="10.0.0.0/33") or cfg,
        "vpcs[0].cidr",
        "invalid_cidr",
    ),
    "vpc_cidr_host_bits_set": (
        lambda cfg: cfg["vpcs"][0].update(cidr="10.0.0.1/16") or cfg,
        "vpcs[0].cidr",
        "invalid_cidr",
    ),
    "vpc_cidr_without_prefix": (
        lambda cfg: cfg["vpcs"][0].update(cidr="10.0.0.0") or cfg,
        "vpcs[0].cidr",
        "invalid_cidr",
    ),
    "vpc_cidr_ipv6": (
        lambda cfg: cfg["vpcs"][0].update(cidr="2001:db8::/32") or cfg,
        "vpcs[0].cidr",
        "unsupported_ipv6",
    ),
    "vpc_cidr_too_large": (
        lambda cfg: cfg["vpcs"][0].update(cidr="10.0.0.0/8") or cfg,
        "vpcs[0].cidr",
        "invalid_prefix_length",
    ),
    "vpc_cidr_not_string": (
        lambda cfg: cfg["vpcs"][0].update(cidr=10) or cfg,
        "vpcs[0].cidr",
        "invalid_type",
    ),
    "invalid_identifier": (
        lambda cfg: cfg["vpcs"][0].update(id="bad id!") or cfg,
        "vpcs[0].id",
        "invalid_id",
    ),
    "identifier_too_long": (
        lambda cfg: cfg["vpcs"][0].update(id="v" * 65) or cfg,
        "vpcs[0].id",
        "invalid_id",
    ),
    "duplicate_identifier_across_types": (
        lambda cfg: cfg["subnets"][0].update(id="vpc-1") or cfg,
        "subnets[0].id",
        "duplicate_id",
    ),
    "control_characters_in_text": (
        lambda cfg: cfg["vpcs"][0].update(name="bad\x00name") or cfg,
        "vpcs[0].name",
        "invalid_characters",
    ),
    "subnet_outside_vpc": (
        lambda cfg: cfg["subnets"][0].update(cidr="192.168.1.0/24") or cfg,
        "subnets[0].cidr",
        "subnet_outside_vpc",
    ),
    "overlapping_subnets": (
        lambda cfg: (
            cfg["subnets"].append(
                {"id": "subnet-2", "vpc_id": "vpc-1", "cidr": "10.0.1.128/25", "route_table_id": "rtb-1"}
            )
            or cfg
        ),
        "subnets[1].cidr",
        "overlapping_subnets",
    ),
    "subnet_unknown_route_table": (
        lambda cfg: cfg["subnets"][0].update(route_table_id="rtb-missing") or cfg,
        "subnets[0].route_table_id",
        "unknown_reference",
    ),
    "subnet_route_table_wrong_type": (
        lambda cfg: cfg["subnets"][0].update(route_table_id="vpc-1") or cfg,
        "subnets[0].route_table_id",
        "wrong_reference_type",
    ),
    "subnet_unknown_vpc": (
        lambda cfg: cfg["subnets"][0].update(vpc_id="vpc-missing") or cfg,
        "subnets[0].vpc_id",
        "unknown_reference",
    ),
    "route_unsupported_target": (
        lambda cfg: (
            cfg["route_tables"][0]["routes"].append(
                {"destination_cidr": "172.16.0.0/16", "target": "nat-0abc"}
            )
            or cfg
        ),
        "route_tables[0].routes[2].target",
        "unsupported_route_target",
    ),
    "route_unknown_igw": (
        lambda cfg: cfg["route_tables"][0]["routes"][1].update(target="igw-missing") or cfg,
        "route_tables[0].routes[1].target",
        "unknown_reference",
    ),
    "route_target_wrong_type": (
        lambda cfg: cfg["route_tables"][0]["routes"][1].update(target="subnet-1") or cfg,
        "route_tables[0].routes[1].target",
        "wrong_reference_type",
    ),
    "local_route_wrong_cidr": (
        lambda cfg: cfg["route_tables"][0]["routes"][0].update(destination_cidr="10.1.0.0/16") or cfg,
        "route_tables[0].routes[0].target",
        "invalid_local_route",
    ),
    "duplicate_route_destination": (
        lambda cfg: (
            cfg["route_tables"][0]["routes"].append({"destination_cidr": "0.0.0.0/0", "target": "igw-1"})
            or cfg
        ),
        "route_tables[0].routes[2].destination_cidr",
        "duplicate_route",
    ),
    "second_igw_for_vpc": (
        lambda cfg: cfg["internet_gateways"].append({"id": "igw-2", "vpc_id": "vpc-1"}) or cfg,
        "internet_gateways[1].vpc_id",
        "multiple_internet_gateways",
    ),
    "instance_ip_outside_subnet": (
        lambda cfg: cfg["instances"][0].update(private_ip="10.0.9.10") or cfg,
        "instances[0].private_ip",
        "ip_outside_subnet",
    ),
    "instance_reserved_ip": (
        lambda cfg: cfg["instances"][0].update(private_ip="10.0.1.2") or cfg,
        "instances[0].private_ip",
        "reserved_ip",
    ),
    "instance_broadcast_ip": (
        lambda cfg: cfg["instances"][0].update(private_ip="10.0.1.255") or cfg,
        "instances[0].private_ip",
        "reserved_ip",
    ),
    "instance_duplicate_private_ip": (
        lambda cfg: (
            cfg["instances"].append(
                {
                    "id": "i-2",
                    "subnet_id": "subnet-1",
                    "private_ip": "10.0.1.10",
                    "security_group_ids": ["sg-1"],
                }
            )
            or cfg
        ),
        "instances[1].private_ip",
        "duplicate_ip",
    ),
    "instance_public_ip_is_private": (
        lambda cfg: cfg["instances"][0].update(public_ip="10.0.1.5") or cfg,
        "instances[0].public_ip",
        "invalid_public_ip",
    ),
    "instance_invalid_ip": (
        lambda cfg: cfg["instances"][0].update(private_ip="999.1.1.1") or cfg,
        "instances[0].private_ip",
        "invalid_ip",
    ),
    "instance_unknown_security_group": (
        lambda cfg: cfg["instances"][0].update(security_group_ids=["sg-missing"]) or cfg,
        "instances[0].security_group_ids[0]",
        "unknown_reference",
    ),
    "instance_no_security_groups": (
        lambda cfg: cfg["instances"][0].update(security_group_ids=[]) or cfg,
        "instances[0].security_group_ids",
        "invalid_length",
    ),
    "instance_duplicate_security_group": (
        lambda cfg: cfg["instances"][0].update(security_group_ids=["sg-1", "sg-1"]) or cfg,
        "instances[0].security_group_ids[1]",
        "duplicate_reference",
    ),
    "instance_tag_not_string": (
        lambda cfg: cfg["instances"][0].update(tags={"tier": 1}) or cfg,
        "instances[0].tags.tier",
        "invalid_tag",
    ),
    "rule_port_range_reversed": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].update(from_port=500, to_port=100) or cfg,
        "security_groups[0].ingress[0].from_port",
        "invalid_port_range",
    ),
    "rule_port_out_of_range": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].update(to_port=70000) or cfg,
        "security_groups[0].ingress[0].to_port",
        "invalid_port",
    ),
    "rule_port_is_boolean": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].update(from_port=True) or cfg,
        "security_groups[0].ingress[0].from_port",
        "invalid_port",
    ),
    "rule_unsupported_protocol": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].update(protocol="sctp") or cfg,
        "security_groups[0].ingress[0].protocol",
        "invalid_protocol",
    ),
    "rule_all_protocols_with_ports": (
        lambda cfg: cfg["security_groups"][0]["egress"][0].update(from_port=1, to_port=2) or cfg,
        "security_groups[0].egress[0].from_port",
        "ports_not_allowed",
    ),
    "rule_tcp_missing_ports": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].pop("from_port") and cfg,
        "security_groups[0].ingress[0].from_port",
        "required",
    ),
    "rule_cidr_and_peer": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].update(source_security_group_id="sg-2") or cfg,
        "security_groups[0].ingress[0]",
        "invalid_rule_target",
    ),
    "rule_neither_cidr_nor_peer": (
        lambda cfg: cfg["security_groups"][0]["ingress"][0].pop("cidr") and cfg,
        "security_groups[0].ingress[0]",
        "invalid_rule_target",
    ),
    "rule_wrong_peer_key_direction": (
        lambda cfg: (
            cfg["security_groups"][1]["ingress"][0].update(destination_security_group_id="sg-1") or cfg
        ),
        "security_groups[1].ingress[0].destination_security_group_id",
        "unknown_field",
    ),
    "rule_unknown_peer_group": (
        lambda cfg: cfg["security_groups"][1]["ingress"][0].update(source_security_group_id="sg-zzz") or cfg,
        "security_groups[1].ingress[0].source_security_group_id",
        "unknown_reference",
    ),
    "sg_missing_egress": (
        lambda cfg: cfg["security_groups"][0].pop("egress") and cfg,
        "security_groups[0].egress",
        "required",
    ),
    "nacl_duplicate_rule_number": (
        lambda cfg: (
            cfg["network_acls"][0]["ingress"].append(
                {"rule_number": 100, "action": "deny", "protocol": "-1", "cidr": "0.0.0.0/0"}
            )
            or cfg
        ),
        "network_acls[0].ingress[1].rule_number",
        "duplicate_rule_number",
    ),
    "nacl_invalid_action": (
        lambda cfg: cfg["network_acls"][0]["ingress"][0].update(action="permit") or cfg,
        "network_acls[0].ingress[0].action",
        "invalid_action",
    ),
    "nacl_rule_number_out_of_range": (
        lambda cfg: cfg["network_acls"][0]["ingress"][0].update(rule_number=0) or cfg,
        "network_acls[0].ingress[0].rule_number",
        "invalid_rule_number",
    ),
    "nacl_unknown_subnet": (
        lambda cfg: cfg["network_acls"][0].update(subnet_ids=["subnet-missing"]) or cfg,
        "network_acls[0].subnet_ids[0]",
        "unknown_reference",
    ),
    "subnet_in_two_acls": (
        lambda cfg: (
            cfg["network_acls"].append(
                {"id": "acl-2", "vpc_id": "vpc-1", "subnet_ids": ["subnet-1"], "ingress": [], "egress": []}
            )
            or cfg
        ),
        "network_acls[1].subnet_ids[0]",
        "multiple_acl_association",
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_invalid_config_is_rejected_with_specific_error(name, valid_config):
    mutate, path, code = CASES[name]
    data = mutate(valid_config)
    result = validate_config(data)
    assert not result.ok
    assert result.config is None
    assert (path, code) in issues(result), f"{name}: got {sorted(issues(result))}"


def test_cross_vpc_security_group_reference_is_rejected(valid_config):
    valid_config["vpcs"].append({"id": "vpc-2", "cidr": "172.31.0.0/16"})
    valid_config["security_groups"].append(
        {"id": "sg-other", "vpc_id": "vpc-2", "name": "other", "ingress": [], "egress": []}
    )
    valid_config["security_groups"][1]["ingress"][0]["source_security_group_id"] = "sg-other"
    assert ("security_groups[1].ingress[0].source_security_group_id", "cross_vpc_reference") in issues(
        validate_config(valid_config)
    )


def test_instance_security_group_from_other_vpc_is_rejected(valid_config):
    valid_config["vpcs"].append({"id": "vpc-2", "cidr": "172.31.0.0/16"})
    valid_config["security_groups"].append(
        {"id": "sg-other", "vpc_id": "vpc-2", "name": "other", "ingress": [], "egress": []}
    )
    valid_config["instances"][0]["security_group_ids"] = ["sg-other"]
    assert ("instances[0].security_group_ids[0]", "cross_vpc_reference") in issues(
        validate_config(valid_config)
    )


def test_all_problems_are_reported_together(valid_config):
    valid_config["vpcs"][0]["cidr"] = "bad"
    valid_config["instances"][0]["private_ip"] = "also-bad"
    valid_config["security_groups"][0]["ingress"][0]["protocol"] = "nope"
    found = issues(validate_config(valid_config))
    assert {
        ("vpcs[0].cidr", "invalid_cidr"),
        ("instances[0].private_ip", "invalid_ip"),
        ("security_groups[0].ingress[0].protocol", "invalid_protocol"),
    } <= found


def test_invalid_resource_does_not_cascade_into_reference_errors(valid_config):
    # An invalid CIDR on the VPC must not make every subnet report "unknown VPC".
    valid_config["vpcs"][0]["cidr"] = "nonsense"
    codes = {code for _, code in issues(validate_config(valid_config))}
    assert "unknown_reference" not in codes


def test_error_list_is_capped(valid_config):
    valid_config["vpcs"] = [{"id": f"vpc-{i}", "cidr": "bad"} for i in range(300)]
    errors = validate_config(valid_config).errors
    assert len(errors) == schema.MAX_ERRORS + 1
    assert errors[-1].code == "too_many_errors"


def test_too_many_resources_in_a_section(valid_config):
    valid_config["instances"] = [
        {"id": f"i-{i}", "subnet_id": "subnet-1", "private_ip": "10.0.1.10", "security_group_ids": ["sg-1"]}
        for i in range(schema.MAX_RESOURCES + 1)
    ]
    assert ("instances", "too_many_items") in issues(validate_config(valid_config))


def test_too_many_resources_overall(valid_config):
    valid_config["vpcs"] = [{"id": f"vpc-{i}", "cidr": "10.0.0.0/16"} for i in range(300)]
    valid_config["instances"] = [
        {"id": f"i-{i}", "subnet_id": "subnet-1", "private_ip": "10.0.1.10", "security_group_ids": ["sg-1"]}
        for i in range(300)
    ]
    assert ("", "too_many_resources") in issues(validate_config(valid_config))


def test_parse_config_raises_with_all_errors(valid_config):
    valid_config["vpcs"][0]["cidr"] = "bad"
    with pytest.raises(ConfigValidationError) as info:
        parse_config(valid_config)
    assert info.value.errors[0].code == "invalid_cidr"


@pytest.mark.parametrize("payload", [None, 5, "text", [], [1, 2]])
def test_non_object_payloads_rejected(payload):
    result = validate_config(payload)
    assert not result.ok
    assert issues(result) == {("", "invalid_type")}


def test_json_depth_helper():
    # Depth counts scalar leaves as a level: dict(1) > list(2) > dict(3) > 1 (4).
    assert schema.check_json_depth({"a": [{"b": 1}]}, 4)
    assert not schema.check_json_depth({"a": [{"b": 1}]}, 3)
    deep = current = []
    for _ in range(100_000):
        nxt = []
        current.append(nxt)
        current = nxt
    assert not schema.check_json_depth(deep, 12)  # iterative: no RecursionError
