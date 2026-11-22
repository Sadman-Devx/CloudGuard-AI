"""Live-AWS importer, pure part: boto3 ``Describe*`` responses -> normalized configuration.

``aws_live.fetch_aws_data`` makes the (read-only) API calls and returns the dict this module reads:

    {"vpcs": [...], "subnets": [...], "internet_gateways": [...], "route_tables": [...],
     "security_groups": [...], "network_acls": [...], "instances": [...],          # EC2
     "db_instances": [...], "load_balancers": [...], "listeners": {arn: [ports]},  # optional
     "buckets": [{"name": "...", "public": false}]}                                 # optional

Keeping the mapping free of boto3 means it can be run on saved responses and is easy to review.
"""

from __future__ import annotations

from typing import Any

from domain.network.importers.builder import (
    ConfigBuilder,
    ImporterError,
    ImportReport,
    clean_text,
    tag_map,
    tag_name,
)

_LIVE_STATES = ("pending", "running", "stopping", "stopped")
_ENGINES = {
    "postgres": "postgres",
    "aurora-postgresql": "aurora-postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "aurora-mysql": "aurora-mysql",
    "aurora": "aurora-mysql",
    "oracle-ee": "oracle",
    "oracle-se2": "oracle",
    "sqlserver-ee": "mssql",
    "sqlserver-se": "mssql",
    "sqlserver-ex": "mssql",
    "sqlserver-web": "mssql",
}
_ROUTE_TARGETS = (
    ("NatGatewayId", "nat"),
    ("VpcPeeringConnectionId", "pcx"),
    ("TransitGatewayId", "tgw"),
    ("VpcEndpointId", "vpce"),
    ("NetworkInterfaceId", "eni"),
    ("InstanceId", "instance"),
    ("EgressOnlyInternetGatewayId", "egress-only"),
    ("CarrierGatewayId", "eni"),
    ("LocalGatewayId", "eni"),
)


def import_aws_describe(data: dict[str, Any], *, region: str, name: str = "") -> ImportReport:
    b = ConfigBuilder(name or f"AWS {region}", region, source="aws")

    for vpc in data.get("vpcs", []):
        b.add_vpc(vpc["VpcId"], vpc.get("CidrBlock"), tag_name(vpc.get("Tags")))
        if vpc.get("Ipv6CidrBlockAssociationSet"):
            b.warn(
                "IPV6_SKIPPED", f"VPC {vpc['VpcId']} has IPv6 CIDRs; they are not modelled and were skipped."
            )

    for igw in data.get("internet_gateways", []):
        for attachment in igw.get("Attachments", []):
            if attachment.get("State") in ("available", "attached", None):
                b.add_internet_gateway(igw["InternetGatewayId"], b.make_id(attachment["VpcId"]))

    subnet_table: dict[str, str] = {}
    for table in data.get("route_tables", []):
        tid = b.add_route_table(
            table["RouteTableId"], b.make_id(table.get("VpcId", "")), tag_name(table.get("Tags"))
        )
        if not tid:
            continue
        for route in table.get("Routes", []):
            _add_route(b, tid, route)
        for association in table.get("Associations", []):
            if association.get("Main"):
                b.main_route_table[b.make_id(table["VpcId"])] = tid
            elif association.get("SubnetId"):
                subnet_table[association["SubnetId"]] = tid

    for subnet in data.get("subnets", []):
        b.add_subnet(
            subnet["SubnetId"],
            b.make_id(subnet.get("VpcId", "")),
            subnet.get("CidrBlock"),
            zone=subnet.get("AvailabilityZone", ""),
            name=tag_name(subnet.get("Tags")),
            route_table_id=subnet_table.get(subnet["SubnetId"]),
        )

    for sg in data.get("security_groups", []):
        b.add_security_group(
            sg["GroupId"], b.make_id(sg.get("VpcId", "")), sg.get("GroupName", ""), sg.get("Description", "")
        )
    for sg in data.get("security_groups", []):
        gid = b.make_id(sg["GroupId"])
        if gid not in b.security_groups:
            continue
        for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
            for permission in sg.get(key, []):
                b.security_groups[gid][direction].extend(_permission_rules(b, gid, direction, permission))

    for acl in data.get("network_acls", []):
        aid = b.add_network_acl(
            acl["NetworkAclId"], b.make_id(acl.get("VpcId", "")), tag_name(acl.get("Tags"))
        )
        if not aid:
            continue
        for association in acl.get("Associations", []):
            if association.get("SubnetId"):
                b.network_acls[aid]["subnet_ids"].append(b.make_id(association["SubnetId"]))
        for entry in acl.get("Entries", []):
            port = entry.get("PortRange") or {}
            b.add_nacl_entry(
                aid,
                egress=bool(entry.get("Egress")),
                number=entry.get("RuleNumber"),
                action=entry.get("RuleAction", ""),
                protocol=entry.get("Protocol"),
                cidr=entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
                from_port=port.get("From"),
                to_port=port.get("To"),
            )

    for inst in data.get("instances", []):
        if (inst.get("State") or {}).get("Name") not in _LIVE_STATES:
            continue
        b.add_instance(
            inst["InstanceId"],
            b.make_id(inst.get("SubnetId", "")) if inst.get("SubnetId") else None,
            [b.make_id(g["GroupId"]) for g in inst.get("SecurityGroups", [])],
            name=tag_name(inst.get("Tags")) or inst["InstanceId"],
            private_ip=inst.get("PrivateIpAddress"),
            public_ip=inst.get("PublicIpAddress") or None,
            tags=tag_map(inst.get("Tags")),
        )

    _extensions(b, data)
    if not (data.get("vpcs") or data.get("subnets")):
        raise ImporterError("No VPCs or subnets were returned. Check the region and the role's permissions.")
    return b.build()


def _add_route(b: ConfigBuilder, table_id: str, route: dict[str, Any]) -> None:
    if route.get("State") == "blackhole":
        return
    if route.get("DestinationPrefixListId"):
        b.warn("PREFIX_LIST_SKIPPED", f"A route in {table_id} uses a prefix list; it was skipped.")
        return
    if route.get("DestinationIpv6CidrBlock"):
        b.warn("IPV6_SKIPPED", f"{table_id}: IPv6 routes are not modelled and were skipped.")
        return
    destination = route.get("DestinationCidrBlock")
    gateway = route.get("GatewayId")
    if gateway == "local":
        b.add_route(table_id, destination, "local", None)
    elif isinstance(gateway, str) and gateway.startswith("igw-"):
        b.add_route(table_id, destination, "igw", b.make_id(gateway))
    elif isinstance(gateway, str) and gateway.startswith("vgw-"):
        b.add_route(table_id, destination, "vgw", None)
    else:
        for field_name, kind in _ROUTE_TARGETS:
            if route.get(field_name):
                b.add_route(table_id, destination, kind, None)
                return


def _permission_rules(b: ConfigBuilder, gid: str, direction: str, permission: dict[str, Any]) -> list[dict]:
    out: list[dict] = []
    where = f"{gid} {direction}"
    common = (permission.get("IpProtocol"), permission.get("FromPort"), permission.get("ToPort"))
    for item in permission.get("IpRanges", []):
        rule = b.rule(
            *common,
            cidr=item.get("CidrIp"),
            description=item.get("Description", ""),
            direction=direction,
            where=where,
        )
        if rule:
            out.append(rule)
    for item in permission.get("Ipv6Ranges", []):
        rule = b.rule(
            *common,
            cidr=item.get("CidrIpv6"),
            description=item.get("Description", ""),
            direction=direction,
            where=where,
        )
        if rule:
            out.append(rule)
    for pair in permission.get("UserIdGroupPairs", []):
        peer = b.make_id(pair.get("GroupId", ""))
        if pair.get("VpcPeeringConnectionId") or peer not in b.security_groups:
            b.warn(
                "PEER_GROUP_SKIPPED",
                f"{where}: a rule references a security group outside the import and was skipped.",
            )
            continue
        rule = b.rule(
            *common, peer=peer, description=pair.get("Description", ""), direction=direction, where=where
        )
        if rule:
            out.append(rule)
    if permission.get("PrefixListIds"):
        b.warn("PREFIX_LIST_SKIPPED", f"{where}: prefix-list sources are not modelled and were skipped.")
    return out


def _extensions(b: ConfigBuilder, data: dict[str, Any]) -> None:
    for db in data.get("db_instances", []):
        engine = _ENGINES.get(str(db.get("Engine", "")).lower())
        subnets = [
            b.make_id(s["SubnetIdentifier"])
            for s in (db.get("DBSubnetGroup") or {}).get("Subnets", [])
            if b.make_id(s["SubnetIdentifier"]) in b.subnets
        ]
        sgs = [
            b.make_id(g["VpcSecurityGroupId"])
            for g in db.get("VpcSecurityGroups", [])
            if b.make_id(g["VpcSecurityGroupId"]) in b.security_groups
        ]
        if not (engine and subnets and sgs):
            b.warn(
                "DATABASE_SKIPPED",
                f"{db.get('DBInstanceIdentifier')}: unsupported engine or outside the imported VPCs.",
            )
            continue
        b.add_extension(
            "databases",
            {
                "id": b.make_id(f"db-{db['DBInstanceIdentifier']}"),
                "name": clean_text(db["DBInstanceIdentifier"]),
                "engine": engine,
                "subnet_ids": subnets,
                "security_group_ids": sgs,
                "publicly_accessible": bool(db.get("PubliclyAccessible")),
                "sensitive": True,
                "encrypted": bool(db.get("StorageEncrypted")),
            },
        )

    listeners = data.get("listeners", {})
    for lb in data.get("load_balancers", []):
        if lb.get("Type", "application") != "application":
            continue
        subnets = [
            b.make_id(z["SubnetId"])
            for z in lb.get("AvailabilityZones", [])
            if z.get("SubnetId") and b.make_id(z["SubnetId"]) in b.subnets
        ]
        sgs = [b.make_id(g) for g in lb.get("SecurityGroups", []) if b.make_id(g) in b.security_groups]
        ports = sorted({p for p in listeners.get(lb.get("LoadBalancerArn"), []) if isinstance(p, int)})
        if not (subnets and sgs and ports):
            b.warn(
                "LB_SKIPPED",
                f"{lb.get('LoadBalancerName')}: outside the imported VPCs or without listeners; skipped.",
            )
            continue
        b.add_extension(
            "load_balancers",
            {
                "id": b.make_id(f"lb-{lb['LoadBalancerName']}"),
                "name": clean_text(lb["LoadBalancerName"]),
                "scheme": "internal" if lb.get("Scheme") == "internal" else "internet-facing",
                "subnet_ids": subnets,
                "security_group_ids": sgs,
                "listener_ports": ports[:20],
            },
        )

    for bucket in data.get("buckets", []):
        b.add_extension(
            "buckets",
            {
                "id": b.make_id(f"bucket-{bucket['name']}"),
                "name": clean_text(bucket["name"]),
                "public": bool(bucket.get("public")),
                "sensitive": False,
                "encrypted": False,
            },
        )
