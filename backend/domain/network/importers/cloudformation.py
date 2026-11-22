"""CloudFormation importer: a template (JSON or YAML) -> normalized configuration.

Templates are parsed with ``yaml.SafeLoader`` plus constructors for the short-form intrinsics
(``!Ref``, ``!GetAtt``, ``!Sub`` ...), which become the long form (``{"Ref": ...}``). Nothing in the
template is evaluated: a ``!Ref`` to a resource is a reference by logical id, a ``!Ref`` to a
parameter uses the parameter's ``Default`` when it has one, and any other computed value
(``!Sub``, ``!Join``, ``!FindInMap``...) is treated as unknown and reported.

Supported: AWS::EC2::{VPC, InternetGateway, VPCGatewayAttachment, Subnet, RouteTable, Route,
SubnetRouteTableAssociation, SecurityGroup (+Ingress/Egress), NetworkAcl, NetworkAclEntry,
SubnetNetworkAclAssociation, Instance} and, as ``extensions``, AWS::RDS::DBInstance,
AWS::ElasticLoadBalancingV2::LoadBalancer/Listener and AWS::S3::Bucket.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from domain.network.importers.builder import (
    ConfigBuilder,
    ImporterError,
    ImportReport,
    clean_text,
    tag_map,
    tag_name,
)
from domain.network.schema import REGION_PATTERN

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
_PSEUDO = {"AWS::Region", "AWS::AccountId", "AWS::StackName", "AWS::NoValue", "AWS::Partition"}


class _TemplateLoader(yaml.SafeLoader):
    """SafeLoader that understands CloudFormation's short-form intrinsic functions."""


def _intrinsic(name: str):
    key = "Ref" if name == "Ref" else f"Fn::{name}"

    def construct(loader: yaml.SafeLoader, node: yaml.Node) -> dict[str, Any]:
        if isinstance(node, yaml.ScalarNode):
            value: Any = loader.construct_scalar(node)
            if name == "GetAtt" and isinstance(value, str):
                value = value.split(".", 1)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        else:
            value = loader.construct_mapping(node, deep=True)
        return {key: value}

    return construct


for _name in (
    "Ref",
    "GetAtt",
    "Sub",
    "Join",
    "Select",
    "Split",
    "FindInMap",
    "If",
    "Equals",
    "Not",
    "And",
    "Or",
    "Condition",
    "ImportValue",
    "Base64",
    "Cidr",
    "GetAZs",
    "Transform",
):
    _TemplateLoader.add_constructor(f"!{_name}", _intrinsic(_name))


def parse_template(content: str | dict) -> dict:
    if isinstance(content, dict):
        return content
    if not isinstance(content, str) or not content.strip():
        raise ImporterError("The CloudFormation template is empty.")
    try:
        data = json.loads(content)
    except ValueError:
        try:
            data = yaml.load(content, Loader=_TemplateLoader)  # noqa: S506 - SafeLoader subclass
        except yaml.YAMLError as exc:
            raise ImporterError(f"The template is neither valid JSON nor valid YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("Resources"), dict):
        raise ImporterError("This does not look like a CloudFormation template (no Resources section).")
    return data


class _Template:
    def __init__(self, data: dict):
        self.resources: dict[str, dict] = {
            k: v
            for k, v in data["Resources"].items()
            if isinstance(v, dict) and isinstance(v.get("Type"), str)
        }
        self.parameters: dict[str, Any] = data.get("Parameters") or {}
        self.ids: dict[str, str] = {}  # logical id -> builder id
        self.unknown: set[str] = set()

    def props(self, logical: str) -> dict:
        return self.resources[logical].get("Properties") or {}

    def of_type(self, *types: str) -> list[str]:
        return [k for k, v in self.resources.items() if v["Type"] in types]

    def value(self, node: Any) -> Any:
        """A plain value: literals as is, Ref to a parameter -> its Default, other intrinsics -> None."""
        if isinstance(node, dict) and len(node) == 1:
            ((fn, arg),) = node.items()
            if fn == "Ref":
                if arg in self.parameters and isinstance(self.parameters[arg], dict):
                    return self.parameters[arg].get("Default")
                return None
            return None
        return node

    def ref(self, node: Any) -> str | None:
        """Builder id of the resource a ``Ref`` / ``GetAtt`` points at."""
        if isinstance(node, dict) and len(node) == 1:
            ((fn, arg),) = node.items()
            logical = (
                arg
                if fn == "Ref"
                else arg[0]
                if fn == "Fn::GetAtt" and isinstance(arg, list) and arg
                else None
            )
            if isinstance(logical, str):
                return self.ids.get(logical)
        if isinstance(node, str):
            return self.ids.get(node)
        return None

    def refs(self, nodes: Any) -> list[str]:
        out = [self.ref(n) for n in (nodes if isinstance(nodes, list) else [])]
        return [o for o in dict.fromkeys(out) if o]


def _tags(props: dict) -> Any:
    return props.get("Tags")


def _flat_tags(t: _Template, props: dict) -> list[dict]:
    """Tags with intrinsic values resolved (unknown values dropped)."""
    out = []
    for tag in props.get("Tags") or []:
        if isinstance(tag, dict):
            value = t.value(tag.get("Value"))
            if isinstance(value, str):
                out.append({"Key": tag.get("Key"), "Value": value})
    return out


def import_cloudformation(content: Any, *, name: str = "") -> ImportReport:
    t = _Template(parse_template(content))
    region = next(
        (
            z[:-1]
            for z in (_zone(t, k) for k in t.of_type("AWS::EC2::Subnet"))
            if z and REGION_PATTERN.match(z[:-1])
        ),
        "us-east-1",
    )
    b = ConfigBuilder(name or "CloudFormation import", region, source="cloudformation")

    for logical in t.of_type("AWS::EC2::VPC"):
        p = t.props(logical)
        cidr = t.value(p.get("CidrBlock"))
        if cidr is None:
            b.warn(
                "UNKNOWN_VALUE", f"{logical}: CidrBlock is computed (not a literal or a parameter default)."
            )
        t.ids[logical] = b.add_vpc(logical, cidr, tag_name(_flat_tags(t, p)) or logical) or ""
    for logical in t.of_type("AWS::EC2::InternetGateway"):
        t.ids[logical] = ""  # becomes real once an attachment names the VPC
    for logical in t.of_type("AWS::EC2::VPCGatewayAttachment"):
        p = t.props(logical)
        igw = p.get("InternetGatewayId")
        igw_logical = igw.get("Ref") if isinstance(igw, dict) else None
        if igw_logical in t.resources and t.resources[igw_logical]["Type"] == "AWS::EC2::InternetGateway":
            t.ids[igw_logical] = b.add_internet_gateway(igw_logical, t.ref(p.get("VpcId"))) or ""

    main_tables: dict[str, str] = {}
    for logical in t.of_type("AWS::EC2::RouteTable"):
        p = t.props(logical)
        t.ids[logical] = b.add_route_table(logical, t.ref(p.get("VpcId")), tag_name(_flat_tags(t, p))) or ""
    for logical in t.of_type("AWS::EC2::Route"):
        p = t.props(logical)
        _cfn_route(t, b, t.ref(p.get("RouteTableId")), p)

    launch_public: dict[str, bool] = {}
    for logical in t.of_type("AWS::EC2::Subnet"):
        p = t.props(logical)
        sid = b.add_subnet(
            logical,
            t.ref(p.get("VpcId")),
            t.value(p.get("CidrBlock")),
            zone=_zone(t, logical) or "",
            name=tag_name(_flat_tags(t, p)),
        )
        t.ids[logical] = sid or ""
        if sid:
            launch_public[sid] = t.value(p.get("MapPublicIpOnLaunch")) in (True, "true", "True")
    for logical in t.of_type("AWS::EC2::SubnetRouteTableAssociation"):
        p = t.props(logical)
        subnet, table = t.ref(p.get("SubnetId")), t.ref(p.get("RouteTableId"))
        if subnet in b.subnets and table in b.route_tables:
            b.subnets[subnet]["route_table_id"] = table
    del main_tables  # CloudFormation has no main-table resource; the VPC's implicit one is assumed

    for logical in t.of_type("AWS::EC2::SecurityGroup"):
        p = t.props(logical)
        t.ids[logical] = (
            b.add_security_group(
                logical,
                t.ref(p.get("VpcId")),
                t.value(p.get("GroupName")) or logical,
                t.value(p.get("GroupDescription")) or "",
                default_egress=False,
            )
            or ""
        )
    for logical in t.of_type("AWS::EC2::SecurityGroup"):
        gid = t.ids.get(logical)
        p = t.props(logical)
        if gid not in b.security_groups:
            continue
        for direction, key in (("ingress", "SecurityGroupIngress"), ("egress", "SecurityGroupEgress")):
            for i, rule in enumerate(p.get(key) or []):
                built = _cfn_rule(t, b, rule, direction, f"{logical}.{key}[{i}]")
                if built:
                    b.security_groups[gid][direction].append(built)
        if "SecurityGroupEgress" not in p:  # CloudFormation: omitted egress = AWS default allow-all
            b.security_groups[gid]["egress"].append(
                {"protocol": "-1", "cidr": "0.0.0.0/0", "description": "AWS default egress"}
            )
            b.warn(
                "DEFAULT_EGRESS_ASSUMED",
                f"{logical} declares no egress rules; AWS default allow-all egress was added.",
            )
    for logical in t.of_type("AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"):
        p = t.props(logical)
        gid = t.ref(p.get("GroupId"))
        direction = "ingress" if t.resources[logical]["Type"].endswith("Ingress") else "egress"
        if gid in b.security_groups:
            built = _cfn_rule(t, b, p, direction, logical)
            if built:
                b.security_groups[gid][direction].append(built)

    for logical in t.of_type("AWS::EC2::NetworkAcl"):
        p = t.props(logical)
        t.ids[logical] = b.add_network_acl(logical, t.ref(p.get("VpcId")), tag_name(_flat_tags(t, p))) or ""
    for logical in t.of_type("AWS::EC2::NetworkAclEntry"):
        p = t.props(logical)
        port = p.get("PortRange") or {}
        b.add_nacl_entry(
            t.ref(p.get("NetworkAclId")),
            egress=t.value(p.get("Egress")) in (True, "true", "True"),
            number=t.value(p.get("RuleNumber")),
            action=t.value(p.get("RuleAction")) or "",
            protocol=t.value(p.get("Protocol")),
            cidr=t.value(p.get("CidrBlock")) or t.value(p.get("Ipv6CidrBlock")),
            from_port=t.value(port.get("From")) if isinstance(port, dict) else None,
            to_port=t.value(port.get("To")) if isinstance(port, dict) else None,
        )
    for logical in t.of_type("AWS::EC2::SubnetNetworkAclAssociation"):
        p = t.props(logical)
        acl, subnet = t.ref(p.get("NetworkAclId")), t.ref(p.get("SubnetId"))
        if acl in b.network_acls and subnet:
            b.network_acls[acl]["subnet_ids"].append(subnet)

    for logical in t.of_type("AWS::EC2::Instance"):
        p = t.props(logical)
        subnet = t.ref(p.get("SubnetId"))
        groups = t.refs(p.get("SecurityGroupIds"))
        public: Any = None
        for nic in p.get("NetworkInterfaces") or []:
            if isinstance(nic, dict):
                subnet = subnet or t.ref(nic.get("SubnetId"))
                groups += t.refs(nic.get("GroupSet"))
                if t.value(nic.get("AssociatePublicIpAddress")) in (True, "true", "True"):
                    public = True
        if public is None:
            public = launch_public.get(subnet or "", False)
        private = t.value(p.get("PrivateIpAddress"))
        t.ids[logical] = (
            b.add_instance(
                logical,
                subnet,
                groups,
                name=tag_name(_flat_tags(t, p)) or logical,
                private_ip=private if isinstance(private, str) else None,
                public_ip=public,
                tags=tag_map(_flat_tags(t, p)),
            )
            or ""
        )

    _cfn_extensions(t, b)
    if t.of_type("AWS::IAM::Role", "AWS::IAM::InstanceProfile"):
        b.warn(
            "IAM_NOT_IMPORTED",
            "IAM roles are not imported from CloudFormation; IAM attack paths are not built.",
        )
    return b.build()


def _zone(t: _Template, logical: str) -> str | None:
    zone = t.value(t.props(logical).get("AvailabilityZone"))
    return zone if isinstance(zone, str) else None


def _cfn_route(t: _Template, b: ConfigBuilder, table: str | None, p: dict) -> None:
    destination = t.value(p.get("DestinationCidrBlock"))
    if table not in b.route_tables or destination is None:
        return
    gateway = p.get("GatewayId")
    gid = t.ref(gateway)
    if gid in b.internet_gateways:
        b.add_route(table, destination, "igw", gid)
        return
    for field_name, kind in (
        ("NatGatewayId", "nat"),
        ("VpcPeeringConnectionId", "pcx"),
        ("TransitGatewayId", "tgw"),
        ("VpcEndpointId", "vpce"),
        ("NetworkInterfaceId", "eni"),
        ("InstanceId", "instance"),
        ("EgressOnlyInternetGatewayId", "egress-only"),
    ):
        if p.get(field_name):
            b.add_route(table, destination, kind, None)
            return
    if gateway:
        b.add_route(table, destination, "vgw", None)


def _cfn_rule(t: _Template, b: ConfigBuilder, p: dict, direction: str, where: str) -> dict | None:
    if not isinstance(p, dict):
        return None
    peer_key = "SourceSecurityGroupId" if direction == "ingress" else "DestinationSecurityGroupId"
    peer = t.ref(p.get(peer_key))
    cidr = t.value(p.get("CidrIp")) or t.value(p.get("CidrIpv6"))
    if not peer and cidr is None:
        b.warn(
            "RULE_SOURCE_UNKNOWN", f"{where}: the source is computed or unsupported; the rule was skipped."
        )
        return None
    return b.rule(
        t.value(p.get("IpProtocol")),
        t.value(p.get("FromPort")),
        t.value(p.get("ToPort")),
        cidr=cidr if not peer else None,
        peer=peer,
        description=t.value(p.get("Description")) or "",
        direction=direction,
        where=where,
    )


def _cfn_extensions(t: _Template, b: ConfigBuilder) -> None:
    subnet_groups = {k: t.refs(t.props(k).get("SubnetIds")) for k in t.of_type("AWS::RDS::DBSubnetGroup")}
    for logical in t.of_type("AWS::RDS::DBInstance"):
        p = t.props(logical)
        engine = _ENGINES.get(str(t.value(p.get("Engine")) or "").lower())
        group = p.get("DBSubnetGroupName")
        group_logical = group.get("Ref") if isinstance(group, dict) else None
        subnets = [s for s in subnet_groups.get(group_logical, []) if s in b.subnets]
        sgs = [g for g in t.refs(p.get("VPCSecurityGroups")) if g in b.security_groups]
        if not (engine and subnets and sgs):
            b.warn(
                "DATABASE_SKIPPED",
                f"{logical}: needs a supported engine, subnet group and security groups; skipped.",
            )
            continue
        did = b.make_id(logical)
        t.ids[logical] = did
        b.add_extension(
            "databases",
            {
                "id": did,
                "name": clean_text(t.value(p.get("DBInstanceIdentifier")) or logical),
                "engine": engine,
                "subnet_ids": subnets,
                "security_group_ids": sgs,
                "publicly_accessible": t.value(p.get("PubliclyAccessible")) in (True, "true", "True"),
                "sensitive": True,
                "encrypted": t.value(p.get("StorageEncrypted")) in (True, "true", "True"),
            },
        )

    ports: dict[str, list[int]] = {}
    for logical in t.of_type("AWS::ElasticLoadBalancingV2::Listener"):
        p = t.props(logical)
        lb = p.get("LoadBalancerArn")
        lb_logical = lb.get("Ref") if isinstance(lb, dict) else None
        port = t.value(p.get("Port"))
        try:
            ports.setdefault(lb_logical or "", []).append(int(port))
        except (TypeError, ValueError):
            continue
    for logical in t.of_type("AWS::ElasticLoadBalancingV2::LoadBalancer"):
        p = t.props(logical)
        subnets = [s for s in t.refs(p.get("Subnets")) if s in b.subnets]
        sgs = [g for g in t.refs(p.get("SecurityGroups")) if g in b.security_groups]
        listening = sorted(set(ports.get(logical, [])))
        kind = t.value(p.get("Type")) or "application"
        if kind != "application" or not (subnets and sgs and listening):
            b.warn(
                "LB_SKIPPED",
                f"{logical}: only application load balancers with listeners are imported.",
            )
            continue
        lid = b.make_id(logical)
        t.ids[logical] = lid
        b.add_extension(
            "load_balancers",
            {
                "id": lid,
                "name": clean_text(t.value(p.get("Name")) or logical),
                "scheme": "internal" if t.value(p.get("Scheme")) == "internal" else "internet-facing",
                "subnet_ids": subnets,
                "security_group_ids": sgs,
                "listener_ports": listening[:20],
            },
        )

    for logical in t.of_type("AWS::S3::Bucket"):
        p = t.props(logical)
        bid = b.make_id(logical)
        t.ids[logical] = bid
        b.add_extension(
            "buckets",
            {
                "id": bid,
                "name": clean_text(t.value(p.get("BucketName")) or logical),
                "public": t.value(p.get("AccessControl")) in ("PublicRead", "PublicReadWrite"),
                "sensitive": False,
                "encrypted": bool(p.get("BucketEncryption")),
            },
        )
