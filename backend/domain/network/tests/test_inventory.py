import json

from domain.network import inventory as inv
from domain.network.inventory import build_inventory
from domain.network.schema import parse_config


def _build(data):
    return build_inventory(parse_config(data))


def _edges(inventory, relation):
    return {(r.source, r.target) for r in inventory.relationships if r.relation_type == relation}


def test_counts_for_minimal_config(valid_config):
    inventory = _build(valid_config)
    assert inventory.counts_by_type() == {
        "vpc": 1,
        "subnet": 1,
        "internet_gateway": 1,
        "route_table": 1,
        "security_group": 2,
        "network_acl": 1,
        "instance": 1,
    }


def test_every_resource_type_is_reported_even_when_zero():
    inventory = _build({"schema_version": "1.0", "vpcs": [{"id": "vpc-1", "cidr": "10.0.0.0/16"}]})
    assert inventory.counts_by_type()["instance"] == 0
    assert set(inventory.counts_by_type()) == set(inv.RESOURCE_TYPES)


def test_relationships_for_minimal_config(valid_config):
    inventory = _build(valid_config)
    assert _edges(inventory, inv.MEMBER_OF_VPC) == {
        ("subnet-1", "vpc-1"),
        ("igw-1", "vpc-1"),
        ("rtb-1", "vpc-1"),
        ("acl-1", "vpc-1"),
        ("sg-1", "vpc-1"),
        ("sg-2", "vpc-1"),
    }
    assert _edges(inventory, inv.ASSOCIATED_ROUTE_TABLE) == {("subnet-1", "rtb-1")}
    assert _edges(inventory, inv.ASSOCIATED_NETWORK_ACL) == {("subnet-1", "acl-1")}
    assert _edges(inventory, inv.PLACED_IN_SUBNET) == {("i-1", "subnet-1")}
    assert _edges(inventory, inv.PROTECTED_BY) == {("i-1", "sg-1"), ("i-1", "sg-2")}
    assert _edges(inventory, inv.ROUTES_TO) == {("rtb-1", "igw-1")}
    assert _edges(inventory, inv.ALLOWS_INGRESS_FROM) == {("sg-2", "sg-1")}


def test_route_metadata_lists_destinations_and_skips_local(valid_config):
    valid_config["route_tables"][0]["routes"].append(
        {"destination_cidr": "198.51.100.0/24", "target": "igw-1"}
    )
    inventory = _build(valid_config)
    route = next(r for r in inventory.relationships if r.relation_type == inv.ROUTES_TO)
    assert route.metadata == {"destinations": ["0.0.0.0/0", "198.51.100.0/24"]}


def test_security_group_peer_rules_are_aggregated(valid_config):
    valid_config["security_groups"][1]["ingress"].append(
        {"protocol": "tcp", "from_port": 9000, "to_port": 9001, "source_security_group_id": "sg-1"}
    )
    inventory = _build(valid_config)
    edge = next(r for r in inventory.relationships if r.relation_type == inv.ALLOWS_INGRESS_FROM)
    assert [(r["from_port"], r["to_port"]) for r in edge.metadata["rules"]] == [(8000, 8000), (9000, 9001)]


def test_egress_peer_relationship_in_broken_fixture(fixture_dir):
    data = json.loads((fixture_dir / "broken_app_connectivity.json").read_text())
    inventory = _build(data)
    assert ("sg-web", "sg-db") in _edges(inventory, inv.ALLOWS_EGRESS_TO)
    assert ("sg-db", "sg-web") in _edges(inventory, inv.ALLOWS_INGRESS_FROM)
    assert ("sg-db", "sg-app") not in _edges(inventory, inv.ALLOWS_INGRESS_FROM)  # the seeded bug


def test_resource_metadata_is_json_native(valid_config):
    inventory = _build(valid_config)
    for resource in inventory.resources:
        json.dumps(resource.metadata)  # would raise on tuples-of-tuples / dataclasses
    instance = next(r for r in inventory.resources if r.external_id == "i-1")
    assert instance.metadata["tags"] == {"tier": "web"}
    assert instance.metadata["security_group_ids"] == ["sg-1", "sg-2"]
    assert instance.metadata["public_ip"] == "203.0.113.5"
    assert "id" not in instance.metadata and "name" not in instance.metadata


def test_resource_names_and_region(valid_config):
    inventory = _build(valid_config)
    by_id = {r.external_id: r for r in inventory.resources}
    assert by_id["i-1"].name == "web-1"
    assert by_id["igw-1"].name == "igw-1"  # gateways have no name field; fall back to the ID
    assert {r.region for r in inventory.resources} == {"us-east-1"}


def test_relationship_endpoints_always_exist_and_are_unique(sample_fixture):
    _, data = sample_fixture
    inventory = _build(data)
    ids = {r.external_id for r in inventory.resources}
    assert len(ids) == len(inventory.resources)
    edges = [(r.source, r.target, r.relation_type) for r in inventory.relationships]
    assert len(edges) == len(set(edges))
    assert all(s in ids and t in ids for s, t, _ in edges)
    assert all(rel in inv.RELATION_TYPES for _, _, rel in edges)


def test_inventory_is_deterministic(valid_config):
    assert _build(valid_config) == _build(valid_config)
