"""Flatten a validated ``NetworkConfig`` into resources and relationships.

Pure Python (no Django). The output is what gets persisted as the normalized
inventory and, on Day 3, what the topology builder consumes. Every relationship
endpoint is guaranteed to exist in ``resources`` because the validator already
rejected dangling references.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

from domain.network.schema import NetworkConfig

# Resource types
VPC = "vpc"
SUBNET = "subnet"
INTERNET_GATEWAY = "internet_gateway"
ROUTE_TABLE = "route_table"
SECURITY_GROUP = "security_group"
NETWORK_ACL = "network_acl"
INSTANCE = "instance"

RESOURCE_TYPES = (
    VPC,
    SUBNET,
    INTERNET_GATEWAY,
    ROUTE_TABLE,
    SECURITY_GROUP,
    NETWORK_ACL,
    INSTANCE,
)

# Relationship types (source -> target)
MEMBER_OF_VPC = "member_of_vpc"  # subnet | route_table | security_group | network_acl | igw -> vpc
ASSOCIATED_ROUTE_TABLE = "associated_route_table"  # subnet -> route_table
ASSOCIATED_NETWORK_ACL = "associated_network_acl"  # subnet -> network_acl
PLACED_IN_SUBNET = "placed_in_subnet"  # instance -> subnet
PROTECTED_BY = "protected_by"  # instance -> security_group
ROUTES_TO = "routes_to"  # route_table -> internet_gateway
ALLOWS_INGRESS_FROM = "allows_ingress_from"  # security_group -> peer security_group
ALLOWS_EGRESS_TO = "allows_egress_to"  # security_group -> peer security_group

RELATION_TYPES = (
    MEMBER_OF_VPC,
    ASSOCIATED_ROUTE_TABLE,
    ASSOCIATED_NETWORK_ACL,
    PLACED_IN_SUBNET,
    PROTECTED_BY,
    ROUTES_TO,
    ALLOWS_INGRESS_FROM,
    ALLOWS_EGRESS_TO,
)


@dataclass(frozen=True)
class ResourceRecord:
    external_id: str
    resource_type: str
    name: str
    region: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class RelationshipRecord:
    source: str  # external_id
    target: str  # external_id
    relation_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Inventory:
    resources: tuple[ResourceRecord, ...]
    relationships: tuple[RelationshipRecord, ...]

    def counts_by_type(self) -> dict[str, int]:
        counts = {rtype: 0 for rtype in RESOURCE_TYPES}
        for resource in self.resources:
            counts[resource.resource_type] += 1
        return counts


def _plain(value: Any) -> Any:
    """Convert tuples to lists so metadata is JSON-native and stable."""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _metadata(obj: Any, *, drop: tuple[str, ...] = ("id", "name")) -> dict[str, Any]:
    data = {k: v for k, v in dataclasses.asdict(obj).items() if k not in drop}
    if "tags" in data:
        data["tags"] = dict(data["tags"])
    return _plain(data)


def _rule_summary(rule: Any) -> dict[str, Any]:
    return {
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "description": rule.description,
    }


def build_inventory(config: NetworkConfig) -> Inventory:
    """Build the normalized resource list and relationship list."""
    resources: list[ResourceRecord] = []
    relationships: list[RelationshipRecord] = []
    region = config.region

    def add(resource_type: str, obj: Any, name: str = "") -> None:
        resources.append(
            ResourceRecord(obj.id, resource_type, name or getattr(obj, "name", ""), region, _metadata(obj))
        )

    def link(source: str, target: str, relation_type: str, **metadata: Any) -> None:
        relationships.append(RelationshipRecord(source, target, relation_type, metadata))

    for vpc in config.vpcs:
        add(VPC, vpc)
    for subnet in config.subnets:
        add(SUBNET, subnet)
        link(subnet.id, subnet.vpc_id, MEMBER_OF_VPC)
        link(subnet.id, subnet.route_table_id, ASSOCIATED_ROUTE_TABLE)
    for igw in config.internet_gateways:
        add(INTERNET_GATEWAY, igw, name=igw.id)
        link(igw.id, igw.vpc_id, MEMBER_OF_VPC)
    for table in config.route_tables:
        add(ROUTE_TABLE, table)
        link(table.id, table.vpc_id, MEMBER_OF_VPC)
        by_target: dict[str, list[str]] = {}
        for route in table.routes:
            if route.target != "local":
                by_target.setdefault(route.target, []).append(route.destination_cidr)
        for target, destinations in by_target.items():
            link(table.id, target, ROUTES_TO, destinations=destinations)
    for acl in config.network_acls:
        add(NETWORK_ACL, acl)
        link(acl.id, acl.vpc_id, MEMBER_OF_VPC)
        for subnet_id in acl.subnet_ids:
            link(subnet_id, acl.id, ASSOCIATED_NETWORK_ACL)
    for sg in config.security_groups:
        add(SECURITY_GROUP, sg)
        link(sg.id, sg.vpc_id, MEMBER_OF_VPC)
        for relation, rules in ((ALLOWS_INGRESS_FROM, sg.ingress), (ALLOWS_EGRESS_TO, sg.egress)):
            by_peer: dict[str, list[dict[str, Any]]] = {}
            for rule in rules:
                if rule.peer_security_group_id:
                    by_peer.setdefault(rule.peer_security_group_id, []).append(_rule_summary(rule))
            for peer, summaries in by_peer.items():
                link(sg.id, peer, relation, rules=summaries)
    for inst in config.instances:
        add(INSTANCE, inst)
        link(inst.id, inst.subnet_id, PLACED_IN_SUBNET)
        for sg_id in inst.security_group_ids:
            link(inst.id, sg_id, PROTECTED_BY)

    return Inventory(tuple(resources), tuple(relationships))
