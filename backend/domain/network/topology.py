"""Digital-twin topology graph built from a validated ``NetworkConfig``.

Pure Python (no Django). The result is a presentation-neutral graph (nodes + edges) that the
API serializes and the React Flow view lays out. It deliberately makes **no reachability
claims**: it describes what is configured and how resources are wired together. Reachability
(routes + firewalls, with reason traces) arrives with the simulation engine.

Conventions
-----------
* VPC membership is expressed with ``Node.parent`` (VPC id), not with edges, because drawing a
  ``member_of_vpc`` edge from every resource to its VPC only adds clutter.
* A subnet is **public** when its route table has a ``0.0.0.0/0`` route to an internet gateway
  of the same VPC (the AWS definition); otherwise it is **private**. A public subnet does not by
  itself make an instance reachable from the internet.
* Security-group edges point in the direction traffic is *permitted to flow* (source -> target)
  and merge ingress and egress declarations for the same pair. ``sides`` says which side(s) of
  the pair declare the rule, so a one-sided rule (a common misconfiguration) is visible.
* The builder is defensive: a reference to a missing resource never raises, it is skipped and
  reported in ``Topology.issues``. (Validated configs cannot trigger this; hand-built ones can.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from domain.network import inventory as inv
from domain.network.inventory import resource_metadata as _metadata
from domain.network.schema import NetworkConfig

INTERNET_ID = "internet"
INTERNET_TYPE = "internet"
DEFAULT_ROUTE = "0.0.0.0/0"

# Edge kinds
ATTACHED = "attached"  # internet -> internet gateway
ROUTES_VIA = "routes_via"  # route table -> internet gateway
ASSOCIATED_ROUTE_TABLE = "associated_route_table"  # subnet -> route table
ASSOCIATED_NETWORK_ACL = "associated_network_acl"  # subnet -> network acl
PLACED_IN_SUBNET = "placed_in_subnet"  # instance -> subnet
PROTECTED_BY = "protected_by"  # instance -> security group
SG_TRAFFIC = "sg_traffic"  # security group -> security group (permitted flow)

EDGE_KINDS = (
    ATTACHED,
    ROUTES_VIA,
    ASSOCIATED_ROUTE_TABLE,
    ASSOCIATED_NETWORK_ACL,
    PLACED_IN_SUBNET,
    PROTECTED_BY,
    SG_TRAFFIC,
)

SIDES_BOTH = "both"
SIDES_INGRESS_ONLY = "ingress_only"  # target allows it, source has no matching egress reference
SIDES_EGRESS_ONLY = "egress_only"  # source allows it, target has no matching ingress reference

_TYPE_ORDER = {
    INTERNET_TYPE: 0,
    inv.VPC: 1,
    inv.INTERNET_GATEWAY: 2,
    inv.ROUTE_TABLE: 3,
    inv.SUBNET: 4,
    inv.NETWORK_ACL: 5,
    inv.INSTANCE: 6,
    inv.SECURITY_GROUP: 7,
}


@dataclass(frozen=True)
class Node:
    id: str
    type: str
    label: str
    parent: str | None = None  # owning VPC id
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "parent": self.parent,
            "data": self.data,
        }


@dataclass(frozen=True)
class Edge:
    id: str
    source: str
    target: str
    kind: str
    label: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "label": self.label,
            "data": self.data,
        }


@dataclass(frozen=True)
class TopologyIssue:
    code: str
    message: str
    resource_id: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "resource_id": self.resource_id}


@dataclass(frozen=True)
class Topology:
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    issues: tuple[TopologyIssue, ...]
    summary: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.as_dict() for n in self.nodes],
            "edges": [e.as_dict() for e in self.edges],
            "issues": [i.as_dict() for i in self.issues],
            "summary": self.summary,
        }


def _port_label(rule: dict[str, Any]) -> str:
    protocol, low, high = rule["protocol"], rule["from_port"], rule["to_port"]
    if protocol == "-1":
        return "all"
    if low is None:
        return protocol
    return f"{protocol}/{low}" if low == high else f"{protocol}/{low}-{high}"


def _rule_view(rule: Any) -> dict[str, Any]:
    return {
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "description": rule.description,
    }


def _summarize_ports(rules: list[dict[str, Any]]) -> str:
    labels: list[str] = []
    for rule in rules:
        label = _port_label(rule)
        if label not in labels:
            labels.append(label)
    return ", ".join(labels)


def build_topology(config: NetworkConfig) -> Topology:
    """Build the topology graph for a validated configuration."""
    issues: list[TopologyIssue] = []
    nodes: dict[str, Node] = {}
    edges: dict[str, Edge] = {}

    def add_node(node: Node) -> None:
        nodes[node.id] = node

    def add_edge(source: str, target: str, kind: str, label: str = "", **data: Any) -> None:
        edge_id = f"{kind}:{source}->{target}"
        edges[edge_id] = Edge(edge_id, source, target, kind, label, data)

    def has(resource_id: str, owner: str, what: str, expected_type: str) -> bool:
        node = nodes.get(resource_id)
        if node is not None and node.type == expected_type:
            return True
        issues.append(
            TopologyIssue(
                "dangling_reference",
                f"{owner} refers to {what} '{resource_id}', which is not in this configuration.",
                owner,
            )
        )
        return False

    vpc_ids = {v.id for v in config.vpcs}
    igw_vpc = {g.id: g.vpc_id for g in config.internet_gateways}

    def owner_vpc(vpc_id: str, owner: str) -> str | None:
        if vpc_id in vpc_ids:
            return vpc_id
        issues.append(
            TopologyIssue(
                "dangling_reference", f"{owner} refers to VPC '{vpc_id}', which is not defined.", owner
            )
        )
        return None

    # ---- nodes -------------------------------------------------------------------------------
    for vpc in config.vpcs:
        add_node(Node(vpc.id, inv.VPC, vpc.name or vpc.id, None, _metadata(vpc)))

    if config.internet_gateways:
        add_node(Node(INTERNET_ID, INTERNET_TYPE, "Internet", None, {"description": "Public internet"}))
    for igw in config.internet_gateways:
        add_node(Node(igw.id, inv.INTERNET_GATEWAY, igw.id, owner_vpc(igw.vpc_id, igw.id), _metadata(igw)))
        add_edge(INTERNET_ID, igw.id, ATTACHED, "attached")

    # Public/private classification per route table (and the IGW providing the default route).
    default_igw: dict[str, str] = {}
    for table in config.route_tables:
        for route in table.routes:
            if route.destination_cidr == DEFAULT_ROUTE and igw_vpc.get(route.target) == table.vpc_id:
                default_igw[table.id] = route.target

    for table in config.route_tables:
        meta = _metadata(table)
        meta["has_internet_route"] = table.id in default_igw
        add_node(
            Node(table.id, inv.ROUTE_TABLE, table.name or table.id, owner_vpc(table.vpc_id, table.id), meta)
        )

    subnet_kind: dict[str, str] = {}
    for subnet in config.subnets:
        public = subnet.route_table_id in default_igw
        subnet_kind[subnet.id] = "public" if public else "private"
        meta = _metadata(subnet)
        meta.update(
            kind=subnet_kind[subnet.id],
            internet_gateway_id=default_igw.get(subnet.route_table_id),
        )
        add_node(
            Node(subnet.id, inv.SUBNET, subnet.name or subnet.id, owner_vpc(subnet.vpc_id, subnet.id), meta)
        )

    for acl in config.network_acls:
        add_node(
            Node(acl.id, inv.NETWORK_ACL, acl.name or acl.id, owner_vpc(acl.vpc_id, acl.id), _metadata(acl))
        )

    for sg in config.security_groups:
        meta = _metadata(sg)
        meta.update(ingress_rule_count=len(sg.ingress), egress_rule_count=len(sg.egress))
        add_node(Node(sg.id, inv.SECURITY_GROUP, sg.name or sg.id, owner_vpc(sg.vpc_id, sg.id), meta))

    subnet_vpc = {s.id: s.vpc_id for s in config.subnets}
    for inst in config.instances:
        meta = _metadata(inst)
        meta.update(
            has_public_ip=inst.public_ip is not None,
            subnet_kind=subnet_kind.get(inst.subnet_id),
        )
        parent = subnet_vpc.get(inst.subnet_id)
        add_node(
            Node(inst.id, inv.INSTANCE, inst.name or inst.id, parent if parent in vpc_ids else None, meta)
        )

    # ---- edges -------------------------------------------------------------------------------
    for table in config.route_tables:
        by_igw: dict[str, list[str]] = {}
        for route in table.routes:
            if route.target != "local":
                by_igw.setdefault(route.target, []).append(route.destination_cidr)
        for target, destinations in by_igw.items():
            if has(target, table.id, "internet gateway", inv.INTERNET_GATEWAY):
                add_edge(table.id, target, ROUTES_VIA, ", ".join(destinations), destinations=destinations)

    for subnet in config.subnets:
        if has(subnet.route_table_id, subnet.id, "route table", inv.ROUTE_TABLE):
            add_edge(subnet.id, subnet.route_table_id, ASSOCIATED_ROUTE_TABLE)

    for acl in config.network_acls:
        for subnet_id in acl.subnet_ids:
            if has(subnet_id, acl.id, "subnet", inv.SUBNET):
                add_edge(subnet_id, acl.id, ASSOCIATED_NETWORK_ACL)

    for inst in config.instances:
        if has(inst.subnet_id, inst.id, "subnet", inv.SUBNET):
            add_edge(inst.id, inst.subnet_id, PLACED_IN_SUBNET)
        for sg_id in inst.security_group_ids:
            if has(sg_id, inst.id, "security group", inv.SECURITY_GROUP):
                add_edge(inst.id, sg_id, PROTECTED_BY)

    # Security-group traffic: merge ingress/egress declarations of the same ordered pair.
    flows: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
    for sg in config.security_groups:
        for rule in sg.ingress:
            if rule.peer_security_group_id and has(
                rule.peer_security_group_id, sg.id, "security group", inv.SECURITY_GROUP
            ):
                flow = flows.setdefault((rule.peer_security_group_id, sg.id), {"ingress": [], "egress": []})
                flow["ingress"].append(_rule_view(rule))
        for rule in sg.egress:
            if rule.peer_security_group_id and has(
                rule.peer_security_group_id, sg.id, "security group", inv.SECURITY_GROUP
            ):
                flow = flows.setdefault((sg.id, rule.peer_security_group_id), {"ingress": [], "egress": []})
                flow["egress"].append(_rule_view(rule))
    for (source, target), flow in sorted(flows.items()):
        sides = (
            SIDES_BOTH
            if flow["ingress"] and flow["egress"]
            else (SIDES_INGRESS_ONLY if flow["ingress"] else SIDES_EGRESS_ONLY)
        )
        label = _summarize_ports(flow["ingress"] + flow["egress"])
        add_edge(
            source,
            target,
            SG_TRAFFIC,
            label,
            sides=sides,
            ingress_rules=flow["ingress"],
            egress_rules=flow["egress"],
        )

    ordered_nodes = tuple(sorted(nodes.values(), key=lambda n: (_TYPE_ORDER[n.type], n.id)))
    ordered_edges = tuple(
        sorted(edges.values(), key=lambda e: (EDGE_KINDS.index(e.kind), e.source, e.target))
    )
    summary = {
        "node_count": len(ordered_nodes),
        "edge_count": len(ordered_edges),
        "public_subnets": sorted(s for s, k in subnet_kind.items() if k == "public"),
        "private_subnets": sorted(s for s, k in subnet_kind.items() if k == "private"),
        "instances_with_public_ip": sorted(i.id for i in config.instances if i.public_ip),
        "one_sided_sg_flows": sorted(
            f"{e.source}->{e.target}"
            for e in ordered_edges
            if e.kind == SG_TRAFFIC and e.data["sides"] != SIDES_BOTH
        ),
    }
    return Topology(ordered_nodes, ordered_edges, tuple(issues), summary)