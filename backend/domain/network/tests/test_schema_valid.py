"""Valid inputs: bundled fixtures and the minimal config must parse cleanly."""

import json

from domain.network.schema import SCHEMA_VERSION, parse_config, validate_config


def test_bundled_fixtures_are_valid(sample_fixture):
    name, data = sample_fixture
    result = validate_config(data)
    assert result.ok, f"{name}: {[e.as_dict() for e in result.errors]}"
    assert result.config.schema_version == SCHEMA_VERSION
    assert len(result.config.instances) == 3
    assert result.warnings == ()


def test_minimal_config_parses_to_typed_model(valid_config):
    config = parse_config(valid_config)
    assert config.region == "us-east-1"
    assert [v.id for v in config.vpcs] == ["vpc-1"]
    assert config.instances[0].public_ip == "203.0.113.5"
    assert config.instances[0].tags == (("tier", "web"),)
    sg = {s.id: s for s in config.security_groups}
    assert sg["sg-2"].ingress[0].peer_security_group_id == "sg-1"
    assert sg["sg-1"].ingress[0].cidr == "0.0.0.0/0"


def test_only_schema_version_and_vpc_are_required():
    config = parse_config({"schema_version": "1.0", "vpcs": [{"id": "vpc-1", "cidr": "10.0.0.0/16"}]})
    assert config.region == "us-east-1"  # default
    assert config.instances == ()


def test_cidr_is_normalized_for_rules(valid_config):
    valid_config["security_groups"][0]["ingress"][0]["cidr"] = "10.0.1.7/24"  # host bits allowed in rules
    config = parse_config(valid_config)
    assert config.security_groups[0].ingress[0].cidr == "10.0.1.0/24"


def test_icmp_without_ports_and_all_protocols_are_valid(valid_config):
    rules = valid_config["security_groups"][0]["ingress"]
    rules.append({"protocol": "icmp", "cidr": "10.0.0.0/16"})
    rules.append({"protocol": "-1", "cidr": "10.0.0.0/16"})
    config = parse_config(valid_config)
    parsed = config.security_groups[0].ingress
    assert (parsed[1].protocol, parsed[1].from_port) == ("icmp", None)
    assert (parsed[2].protocol, parsed[2].to_port) == ("-1", None)


def test_parsed_model_is_json_serialisable_input_untouched(valid_config):
    before = json.dumps(valid_config, sort_keys=True)
    parse_config(valid_config)
    assert json.dumps(valid_config, sort_keys=True) == before  # validator never mutates input


def test_unused_resources_produce_warnings_not_errors(valid_config):
    valid_config["route_tables"].append({"id": "rtb-2", "vpc_id": "vpc-1", "routes": []})
    valid_config["security_groups"].append(
        {"id": "sg-3", "vpc_id": "vpc-1", "name": "idle", "ingress": [], "egress": []}
    )
    result = validate_config(valid_config)
    assert result.ok
    assert {w.code for w in result.warnings} == {"unassociated_route_table", "unused_security_group"}
