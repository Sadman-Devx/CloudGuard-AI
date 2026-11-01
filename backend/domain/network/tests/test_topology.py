import dataclasses
import json

import pytest

from domain.network import topology as topo
from domain.network.schema import Instance, Route, RouteTable, Subnet, parse_config
from domain.network.topology import build_topology


def build(data):
    return build_topology(parse_config(data))


def node(t, node_id):
    return next(n for n in t.nodes if n.id == node_id)


def edges(t, kind):
    return {(e.source, e.target) for e in t.edges if e.kind == kind}


def load(fixture_dir, name):
    return json.loads((fixture_dir / f"{name}.json").read_text())


# --------------------------------------------------------------------------- structure


def test_nodes_cover_every_resource_plus_internet(valid_config):
    t = build(valid_config)
    assert {n.id for n in t.nodes} == {
        "internet", "vpc-1", "igw-1", "rtb-1", "subnet-1", "acl-1", "sg-1", "sg-2", "i-1",
    }  # fmt: skip
    assert node(t, "internet").type == "internet"
    assert node(t, "internet").parent is None


def test_no_internet_node_without_gateway(valid_config):
    valid_config["internet_gateways"] = []
    valid_config["route_tables"][0]["routes"] = [{"destination_cidr": "10.0.0.0/16", "target": "local"}]
    t = build(valid_config)
    assert "internet" not in {n.id for n in t.nodes}
    assert not edges(t, topo.ATTACHED)


def test_vpc_membership_is_expressed_as_parent_not_edges(valid_config):
    t = build(valid_config)
    for node_id in ("igw-1", "rtb-1", "subnet-1", "acl-1", "sg-1", "sg-2", "i-1"):
        assert node(t, node_id).parent == "vpc-1", node_id
    assert node(t, "vpc-1").parent is None
    assert all(e.target != "vpc-1" and e.source != "vpc-1" for e in t.edges)


def test_edges_for_minimal_config(valid_config):
    t = build(valid_config)
    assert edges(t, topo.ATTACHED) == {("internet", "igw-1")}
    assert edges(t, topo.ROUTES_VIA) == {("rtb-1", "igw-1")}
    assert edges(t, topo.ASSOCIATED_ROUTE_TABLE) == {("subnet-1", "rtb-1")}
    assert edges(t, topo.ASSOCIATED_NETWORK_ACL) == {("subnet-1", "acl-1")}
    assert edges(t, topo.PLACED_IN_SUBNET) == {("i-1", "subnet-1")}
    assert edges(t, topo.PROTECTED_BY) == {("i-1", "sg-1"), ("i-1", "sg-2")}
    route = next(e for e in t.edges if e.kind == topo.ROUTES_VIA)
    assert route.label == "0.0.0.0/0" and route.data["destinations"] == ["0.0.0.0/0"]


def test_every_edge_endpoint_is_a_node_and_ids_unique(sample_fixture):
    _, data = sample_fixture
    t = build(data)
    ids = {n.id for n in t.nodes}
    assert len(ids) == len(t.nodes)
    assert len({e.id for e in t.edges}) == len(t.edges)
    assert all(e.source in ids and e.target in ids for e in t.edges)
    assert all(n.parent is None or n.parent in ids for n in t.nodes)
    assert t.issues == ()
    assert all(e.kind in topo.EDGE_KINDS for e in t.edges)


def test_output_is_deterministic_and_json_serialisable(sample_fixture):
    _, data = sample_fixture
    first, second = build(data), build(data)
    assert first == second
    assert json.dumps(first.as_dict(), sort_keys=True) == json.dumps(second.as_dict(), sort_keys=True)


def test_nodes_sorted_by_type_then_id(valid_config):
    order = [n.type for n in build(valid_config).nodes]
    assert order == sorted(order, key=lambda t: topo._TYPE_ORDER[t])


# --------------------------------------------------------------------------- public / private


def test_subnet_with_default_route_to_igw_is_public(valid_config):
    t = build(valid_config)
    meta = node(t, "subnet-1").data
    assert meta["kind"] == "public"
    assert meta["internet_gateway_id"] == "igw-1"
    assert node(t, "rtb-1").data["has_internet_route"] is True
    assert t.summary["public_subnets"] == ["subnet-1"]


def test_subnet_without_internet_route_is_private(valid_config):
    valid_config["route_tables"][0]["routes"] = [{"destination_cidr": "10.0.0.0/16", "target": "local"}]
    t = build(valid_config)
    assert node(t, "subnet-1").data["kind"] == "private"
    assert node(t, "subnet-1").data["internet_gateway_id"] is None
    assert t.summary["private_subnets"] == ["subnet-1"]


def test_non_default_igw_route_does_not_make_subnet_public(valid_config):
    valid_config["route_tables"][0]["routes"][1]["destination_cidr"] = "198.51.100.0/24"
    t = build(valid_config)
    assert node(t, "subnet-1").data["kind"] == "private"
    assert edges(t, topo.ROUTES_VIA) == {("rtb-1", "igw-1")}  # still drawn: the route exists


def test_instance_flags_follow_subnet_and_public_ip(valid_config):
    t = build(valid_config)
    assert node(t, "i-1").data["has_public_ip"] is True
    assert node(t, "i-1").data["subnet_kind"] == "public"
    valid_config["instances"][0].pop("public_ip")
    t = build(valid_config)
    assert node(t, "i-1").data["has_public_ip"] is False
    assert t.summary["instances_with_public_ip"] == []


def test_fixtures_classify_public_and_private_subnets(sample_fixture):
    _, data = sample_fixture
    t = build(data)
    assert t.summary["public_subnets"] == ["subnet-public"]
    assert t.summary["private_subnets"] == ["subnet-private"]
    assert node(t, "i-web-1").data["subnet_kind"] == "public"
    assert node(t, "i-db-1").data["subnet_kind"] == "private"


# --------------------------------------------------------------------------- security group flows


def test_sg_flow_merges_ingress_and_egress_into_one_edge(fixture_dir):
    t = build(load(fixture_dir, "safe_network"))
    flows = [e for e in t.edges if e.kind == topo.SG_TRAFFIC]
    assert len({(e.source, e.target) for e in flows}) == len(flows)  # one edge per ordered pair
    web_to_app = next(e for e in flows if (e.source, e.target) == ("sg-web", "sg-app"))
    assert web_to_app.data["sides"] == topo.SIDES_BOTH
    assert web_to_app.label == "tcp/8000"
    assert web_to_app.data["ingress_rules"] and web_to_app.data["egress_rules"]
    assert t.summary["one_sided_sg_flows"] == []


def test_one_sided_flow_is_flagged_in_broken_connectivity_fixture(fixture_dir):
    t = build(load(fixture_dir, "broken_app_connectivity"))
    flow = next(
        e for e in t.edges if e.kind == topo.SG_TRAFFIC and (e.source, e.target) == ("sg-app", "sg-db")
    )
    assert flow.data["sides"] == topo.SIDES_EGRESS_ONLY  # sg-app may send to sg-db, sg-db never allows it
    assert flow.data["ingress_rules"] == []
    assert t.summary["one_sided_sg_flows"] == ["sg-app->sg-db"]
    both = next(e for e in t.edges if (e.source, e.target) == ("sg-web", "sg-db"))
    assert both.data["sides"] == topo.SIDES_BOTH


def test_ingress_only_flow(valid_config):
    # sg-2 allows ingress from sg-1; sg-1 has no egress reference to sg-2 (it allows 0.0.0.0/0 instead).
    t = build(valid_config)
    flow = next(e for e in t.edges if e.kind == topo.SG_TRAFFIC)
    assert (flow.source, flow.target) == ("sg-1", "sg-2")
    assert flow.data["sides"] == topo.SIDES_INGRESS_ONLY
    assert flow.data["egress_rules"] == []


def test_port_labels(valid_config):
    rules = valid_config["security_groups"][1]["ingress"]
    rules.append({"protocol": "tcp", "from_port": 9000, "to_port": 9100, "source_security_group_id": "sg-1"})
    rules.append({"protocol": "-1", "source_security_group_id": "sg-1"})
    flow = next(e for e in build(valid_config).edges if e.kind == topo.SG_TRAFFIC)
    assert flow.label == "tcp/8000, tcp/9000-9100, all"


def test_direction_is_traffic_flow_not_declaration_owner(valid_config):
    # Ingress rule lives on sg-2 (peer sg-1) but the drawn edge runs sg-1 -> sg-2.
    flow = next(e for e in build(valid_config).edges if e.kind == topo.SG_TRAFFIC)
    assert flow.source == "sg-1" and flow.target == "sg-2"


# --------------------------------------------------------------------------- broken references


def _config(valid_config):
    return parse_config(valid_config)


def test_dangling_references_are_reported_not_raised(valid_config):
    config = _config(valid_config)
    broken = dataclasses.replace(
        config,
        subnets=(Subnet("subnet-1", "vpc-1", "10.0.1.0/24", "rtb-missing"),),
        instances=(Instance("i-1", "subnet-missing", "10.0.1.10", ("sg-missing", "sg-1"), None),),
        route_tables=(RouteTable("rtb-1", "vpc-1", (Route("0.0.0.0/0", "igw-missing"),)),),
    )
    t = build_topology(broken)
    codes = {(i.code, i.resource_id) for i in t.issues}
    assert codes == {
        ("dangling_reference", "rtb-1"),
        ("dangling_reference", "subnet-1"),
        ("dangling_reference", "i-1"),
    }
    messages = " ".join(i.message for i in t.issues)
    for missing in ("igw-missing", "rtb-missing", "subnet-missing", "sg-missing"):
        assert missing in messages
    ids = {n.id for n in t.nodes}
    assert all(e.source in ids and e.target in ids for e in t.edges)  # no half-edges
    assert ("i-1", "sg-1") in edges(t, topo.PROTECTED_BY)  # valid sibling edge survives


def test_dangling_peer_security_group_is_reported(valid_config):
    config = _config(valid_config)
    sg2 = config.security_groups[1]
    rule = dataclasses.replace(sg2.ingress[0], peer_security_group_id="sg-ghost")
    broken = dataclasses.replace(
        config,
        security_groups=(config.security_groups[0], dataclasses.replace(sg2, ingress=(rule,))),
    )
    t = build_topology(broken)
    assert [i.resource_id for i in t.issues] == ["sg-2"]
    assert not edges(t, topo.SG_TRAFFIC)


def test_reference_to_wrong_resource_type_is_reported(valid_config):
    config = _config(valid_config)
    broken = dataclasses.replace(
        config,
        instances=(dataclasses.replace(config.instances[0], security_group_ids=("subnet-1",)),),
    )
    t = build_topology(broken)
    assert [(i.code, i.resource_id) for i in t.issues] == [("dangling_reference", "i-1")]
    assert not edges(t, topo.PROTECTED_BY)


def test_undefined_vpc_leaves_node_unparented(valid_config):
    config = _config(valid_config)
    broken = dataclasses.replace(
        config, security_groups=(dataclasses.replace(config.security_groups[0], vpc_id="vpc-x"),)
    )
    t = build_topology(broken)
    assert node(t, "sg-1").parent is None
    assert any("vpc-x" in i.message for i in t.issues)


@pytest.mark.parametrize("name", ["safe_network", "exposed_database", "broken_app_connectivity"])
def test_summary_counts_match(fixture_dir, name):
    t = build(load(fixture_dir, name))
    assert t.summary["node_count"] == len(t.nodes) == 13
    assert t.summary["edge_count"] == len(t.edges)