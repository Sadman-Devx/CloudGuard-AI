"""Normalized AWS-inspired network configuration: typed model + validator.

Pure Python (no Django). Uploaded JSON is untrusted, so the validator:

* collects *all* problems (capped) instead of failing on the first one, which
  gives the UI actionable feedback;
* never evaluates or executes anything from the input;
* restricts identifiers to a conservative character set (they flow into graph
  node IDs, URLs and, later, LLM prompts);
* reports unsupported constructs explicitly instead of guessing.

The supported subset is documented in ``docs/supported-network-semantics.md``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "1.0"

SUPPORTED_PROTOCOLS = ("tcp", "udp", "icmp", "-1")

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REGION_PATTERN = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_UNSUPPORTED_TARGET_PREFIX = re.compile(r"^(nat|pcx|tgw|vgw|eni|vpce|i)-")

MAX_TEXT_LENGTH = 256
MAX_TAG_LENGTH = 128
MAX_TAGS = 50
MAX_RESOURCES = 500
MAX_RULES_PER_LIST = 200
MAX_ROUTES_PER_TABLE = 100
MAX_SECURITY_GROUPS_PER_INSTANCE = 5
MAX_ERRORS = 100
DEFAULT_REGION = "us-east-1"

# Public addresses must not fall in these ranges. RFC 5737 documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are deliberately allowed so
# fixtures can use safe synthetic "public" IPs.
_NON_PUBLIC_RANGES = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)

_SECTION_KEYS = (
    "vpcs",
    "subnets",
    "internet_gateways",
    "route_tables",
    "security_groups",
    "network_acls",
    "instances",
)

# --------------------------------------------------------------------------
# Typed model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Vpc:
    id: str
    cidr: str
    name: str = ""


@dataclass(frozen=True)
class Subnet:
    id: str
    vpc_id: str
    cidr: str
    route_table_id: str
    availability_zone: str = ""
    name: str = ""


@dataclass(frozen=True)
class InternetGateway:
    id: str
    vpc_id: str


@dataclass(frozen=True)
class Route:
    destination_cidr: str
    target: str  # "local" or an internet gateway id


@dataclass(frozen=True)
class RouteTable:
    id: str
    vpc_id: str
    routes: tuple[Route, ...] = ()
    name: str = ""


@dataclass(frozen=True)
class SecurityGroupRule:
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str | None = None
    peer_security_group_id: str | None = None
    description: str = ""


@dataclass(frozen=True)
class SecurityGroup:
    id: str
    vpc_id: str
    name: str
    ingress: tuple[SecurityGroupRule, ...]
    egress: tuple[SecurityGroupRule, ...]
    description: str = ""


@dataclass(frozen=True)
class NaclRule:
    rule_number: int
    action: str  # "allow" | "deny"
    protocol: str
    cidr: str
    from_port: int | None
    to_port: int | None


@dataclass(frozen=True)
class NetworkAcl:
    id: str
    vpc_id: str
    subnet_ids: tuple[str, ...]
    ingress: tuple[NaclRule, ...]
    egress: tuple[NaclRule, ...]
    name: str = ""


@dataclass(frozen=True)
class Instance:
    id: str
    subnet_id: str
    private_ip: str
    security_group_ids: tuple[str, ...]
    public_ip: str | None = None
    name: str = ""
    tags: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class NetworkConfig:
    schema_version: str
    name: str
    region: str
    vpcs: tuple[Vpc, ...]
    subnets: tuple[Subnet, ...]
    internet_gateways: tuple[InternetGateway, ...]
    route_tables: tuple[RouteTable, ...]
    security_groups: tuple[SecurityGroup, ...]
    network_acls: tuple[NetworkAcl, ...]
    instances: tuple[Instance, ...]


# --------------------------------------------------------------------------
# Results / errors
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationIssue:
    path: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "code": self.code, "message": self.message}


@dataclass(frozen=True)
class ValidationResult:
    config: NetworkConfig | None
    errors: tuple[ValidationIssue, ...]
    warnings: tuple[ValidationIssue, ...]

    @property
    def ok(self) -> bool:
        return not self.errors and self.config is not None


class ConfigValidationError(Exception):
    def __init__(self, errors: tuple[ValidationIssue, ...]):
        super().__init__(f"Configuration invalid ({len(errors)} error(s))")
        self.errors = errors


# --------------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------------


def check_json_depth(value: Any, max_depth: int) -> bool:
    """Return True when ``value`` nests no deeper than ``max_depth`` (iterative)."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return False
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)
    return True


def validate_config(data: Any) -> ValidationResult:
    """Validate untrusted JSON data and return a typed config when valid."""
    return _Validator(data).run()


def parse_config(data: Any) -> NetworkConfig:
    """Validate and return the typed config, or raise ``ConfigValidationError``."""
    result = validate_config(data)
    if not result.ok:
        raise ConfigValidationError(result.errors)
    assert result.config is not None
    return result.config


# --------------------------------------------------------------------------
# Implementation
# --------------------------------------------------------------------------


class _Collector:
    def __init__(self) -> None:
        self.errors: list[ValidationIssue] = []
        self.warnings: list[ValidationIssue] = []
        self._capped = False

    def error(self, path: str, code: str, message: str) -> None:
        if len(self.errors) >= MAX_ERRORS:
            if not self._capped:
                self._capped = True
                self.errors.append(
                    ValidationIssue("", "too_many_errors", f"Stopped after {MAX_ERRORS} errors.")
                )
            return
        self.errors.append(ValidationIssue(path, code, message))

    def warn(self, path: str, code: str, message: str) -> None:
        self.warnings.append(ValidationIssue(path, code, message))


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


class _Validator:
    def __init__(self, data: Any) -> None:
        self.data = data
        self.c = _Collector()
        # id -> (resource type, path) for every identifier that parsed, even if
        # the rest of the resource was invalid (avoids cascading false errors).
        self.declared: dict[str, tuple[str, str]] = {}
        # id -> fully parsed resource
        self.parsed: dict[str, Any] = {}
        self.pending_sg_refs: list[tuple[str, str, str]] = []  # (path, peer id, owner vpc id)

    # ---- primitives -----------------------------------------------------

    def _object(self, value: Any, path: str) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            self.c.error(path, "invalid_type", "Expected an object.")
            return None
        return value

    def _keys(self, obj: dict[str, Any], path: str, required: set[str], optional: set[str]) -> None:
        for key in sorted(required):
            if key not in obj:
                self.c.error(_join(path, key), "required", f"'{key}' is required.")
        for key in obj:
            if key not in required and key not in optional:
                self.c.error(_join(path, str(key)), "unknown_field", f"Unknown field '{key}'.")

    def _list(self, obj: dict[str, Any], key: str, path: str, max_items: int) -> list[Any]:
        if key not in obj:
            return []
        value = obj[key]
        field_path = _join(path, key)
        if not isinstance(value, list):
            self.c.error(field_path, "invalid_type", "Expected a list.")
            return []
        if len(value) > max_items:
            self.c.error(field_path, "too_many_items", f"At most {max_items} items are allowed.")
            return []
        return value

    def _text(self, obj: dict[str, Any], key: str, path: str, default: str = "") -> str:
        if key not in obj:
            return default
        value = obj[key]
        field_path = _join(path, key)
        if not isinstance(value, str):
            self.c.error(field_path, "invalid_type", "Expected a string.")
            return default
        if len(value) > MAX_TEXT_LENGTH:
            self.c.error(field_path, "too_long", f"At most {MAX_TEXT_LENGTH} characters allowed.")
            return default
        if _CONTROL_CHARS.search(value):
            self.c.error(field_path, "invalid_characters", "Control characters are not allowed.")
            return default
        return value

    def _ident(self, obj: dict[str, Any], key: str, path: str) -> str | None:
        if key not in obj:
            return None
        value = obj[key]
        field_path = _join(path, key)
        if not isinstance(value, str) or not ID_PATTERN.match(value):
            self.c.error(
                field_path,
                "invalid_id",
                "Identifiers must be 1-64 characters: letters, digits, '.', '_' or '-', "
                "starting with a letter or digit.",
            )
            return None
        return value

    def _declare(self, ident: str | None, rtype: str, path: str) -> None:
        if ident is None:
            return
        previous = self.declared.get(ident)
        if previous is not None:
            self.c.error(
                _join(path, "id"),
                "duplicate_id",
                f"Identifier '{ident}' is already used at {previous[1]}.",
            )
            return
        self.declared[ident] = (rtype, path)

    def _cidr(
        self,
        value: Any,
        path: str,
        *,
        strict: bool = True,
        prefix_range: tuple[int, int] | None = None,
    ) -> ipaddress.IPv4Network | None:
        if not isinstance(value, str):
            self.c.error(path, "invalid_type", "Expected a CIDR string such as '10.0.0.0/24'.")
            return None
        if "/" not in value:
            self.c.error(path, "invalid_cidr", "Use CIDR notation with a prefix, e.g. '10.0.0.0/24'.")
            return None
        try:
            net = ipaddress.ip_network(value, strict=strict)
        except ValueError as exc:
            self.c.error(path, "invalid_cidr", f"Invalid CIDR '{value}': {exc}")
            return None
        if net.version != 4:
            self.c.error(path, "unsupported_ipv6", "IPv6 is not supported in this version.")
            return None
        if prefix_range and not prefix_range[0] <= net.prefixlen <= prefix_range[1]:
            self.c.error(
                path,
                "invalid_prefix_length",
                f"Prefix length must be between /{prefix_range[0]} and /{prefix_range[1]}.",
            )
            return None
        return net  # type: ignore[return-value]

    def _ipv4(self, value: Any, path: str) -> ipaddress.IPv4Address | None:
        if not isinstance(value, str):
            self.c.error(path, "invalid_type", "Expected an IPv4 address string.")
            return None
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            self.c.error(path, "invalid_ip", f"'{value}' is not a valid IP address.")
            return None
        if addr.version != 4:
            self.c.error(path, "unsupported_ipv6", "IPv6 is not supported in this version.")
            return None
        return addr  # type: ignore[return-value]

    @staticmethod
    def _is_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _protocol_ports(self, obj: dict[str, Any], path: str) -> tuple[str, int | None, int | None] | None:
        if "protocol" not in obj:
            return None
        protocol = obj["protocol"]
        if not isinstance(protocol, str) or protocol not in SUPPORTED_PROTOCOLS:
            self.c.error(
                _join(path, "protocol"),
                "invalid_protocol",
                f"Protocol must be one of {', '.join(SUPPORTED_PROTOCOLS)}.",
            )
            return None

        from_port, to_port = obj.get("from_port"), obj.get("to_port")
        fp, tp = _join(path, "from_port"), _join(path, "to_port")

        if protocol == "-1":
            if from_port is not None or to_port is not None:
                self.c.error(fp, "ports_not_allowed", "Omit ports when protocol is '-1' (all).")
                return None
            return protocol, None, None

        if protocol == "icmp" and from_port is None and to_port is None:
            return protocol, None, None

        low, high = (-1, 255) if protocol == "icmp" else (0, 65535)
        ok = True
        for key_path, value in ((fp, from_port), (tp, to_port)):
            if value is None:
                self.c.error(key_path, "required", "Port is required for this protocol.")
                ok = False
            elif not self._is_int(value) or not low <= value <= high:
                self.c.error(key_path, "invalid_port", f"Port must be an integer in {low}-{high}.")
                ok = False
        if not ok:
            return None
        if from_port > to_port:
            self.c.error(fp, "invalid_port_range", "from_port must be <= to_port.")
            return None
        return protocol, from_port, to_port

    # ---- top level ------------------------------------------------------

    def run(self) -> ValidationResult:
        root = self._object(self.data, "")
        if root is None:
            return self._result(None)

        self._keys(
            root,
            "",
            required={"schema_version", "vpcs"},
            optional={"name", "region", *_SECTION_KEYS},
        )
        if "schema_version" in root and root["schema_version"] != SCHEMA_VERSION:
            self.c.error(
                "schema_version",
                "unsupported_schema_version",
                f"Only schema_version '{SCHEMA_VERSION}' is supported.",
            )

        name = self._text(root, "name", "")
        region = self._text(root, "region", "", DEFAULT_REGION)
        if region and not REGION_PATTERN.match(region):
            self.c.error("region", "invalid_region", "Region must look like 'us-east-1'.")
            region = DEFAULT_REGION

        raw = {key: self._list(root, key, "", MAX_RESOURCES) for key in _SECTION_KEYS}
        total = sum(len(items) for items in raw.values())
        if total > MAX_RESOURCES:
            self.c.error("", "too_many_resources", f"At most {MAX_RESOURCES} resources are allowed.")
            return self._result(None)
        if "vpcs" in root and isinstance(root["vpcs"], list) and not raw["vpcs"]:
            self.c.error("vpcs", "required", "At least one VPC is required.")

        vpcs = self._parse_vpcs(raw["vpcs"])
        igws = self._parse_igws(raw["internet_gateways"])
        route_tables = self._parse_route_tables(raw["route_tables"])
        subnets = self._parse_subnets(raw["subnets"])
        sgs = self._parse_security_groups(raw["security_groups"])
        nacls = self._parse_nacls(raw["network_acls"])
        instances = self._parse_instances(raw["instances"])

        self._check_igws(igws)
        self._check_route_tables(route_tables)
        self._check_subnets(subnets)
        self._check_sg_refs()
        self._check_nacls(nacls)
        self._check_instances(instances)
        self._warn_unused(route_tables, sgs, subnets, instances)

        if self.c.errors:
            return self._result(None)

        config = NetworkConfig(
            schema_version=SCHEMA_VERSION,
            name=name,
            region=region,
            vpcs=tuple(v for _, v in vpcs),
            subnets=tuple(v for _, v in subnets),
            internet_gateways=tuple(v for _, v in igws),
            route_tables=tuple(v for _, v in route_tables),
            security_groups=tuple(v for _, v in sgs),
            network_acls=tuple(v for _, v in nacls),
            instances=tuple(v for _, v in instances),
        )
        return self._result(config)

    def _result(self, config: NetworkConfig | None) -> ValidationResult:
        if self.c.errors:
            config = None
        return ValidationResult(config, tuple(self.c.errors), tuple(self.c.warnings))

    # ---- per-resource parsing ------------------------------------------

    def _each(self, items: list[Any], section: str, required: set[str], optional: set[str]):
        for index, raw in enumerate(items):
            path = f"{section}[{index}]"
            obj = self._object(raw, path)
            if obj is None:
                continue
            self._keys(obj, path, required, optional)
            yield path, obj

    def _parse_vpcs(self, items: list[Any]) -> list[tuple[str, Vpc]]:
        out: list[tuple[str, Vpc]] = []
        for path, obj in self._each(items, "vpcs", {"id", "cidr"}, {"name"}):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "vpc", path)
            net = (
                self._cidr(obj["cidr"], _join(path, "cidr"), prefix_range=(16, 28)) if "cidr" in obj else None
            )
            name = self._text(obj, "name", path)
            if ident and net and self.declared[ident][1] == path:
                vpc = Vpc(ident, str(net), name)
                self.parsed[ident] = vpc
                out.append((path, vpc))
        return out

    def _parse_igws(self, items: list[Any]) -> list[tuple[str, InternetGateway]]:
        out: list[tuple[str, InternetGateway]] = []
        for path, obj in self._each(items, "internet_gateways", {"id", "vpc_id"}, set()):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "internet_gateway", path)
            vpc_id = self._ident(obj, "vpc_id", path)
            if ident and vpc_id and self.declared[ident][1] == path:
                igw = InternetGateway(ident, vpc_id)
                self.parsed[ident] = igw
                out.append((path, igw))
        return out

    def _parse_route_tables(self, items: list[Any]) -> list[tuple[str, RouteTable]]:
        out: list[tuple[str, RouteTable]] = []
        for path, obj in self._each(items, "route_tables", {"id", "vpc_id"}, {"routes", "name"}):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "route_table", path)
            vpc_id = self._ident(obj, "vpc_id", path)
            name = self._text(obj, "name", path)
            routes: list[Route] = []
            routes_ok = True
            for j, raw_route in enumerate(self._list(obj, "routes", path, MAX_ROUTES_PER_TABLE)):
                rpath = f"{path}.routes[{j}]"
                robj = self._object(raw_route, rpath)
                if robj is None:
                    routes_ok = False
                    continue
                self._keys(robj, rpath, {"destination_cidr", "target"}, set())
                dest = (
                    self._cidr(robj["destination_cidr"], _join(rpath, "destination_cidr"))
                    if "destination_cidr" in robj
                    else None
                )
                target = robj.get("target")
                if "target" in robj and (not isinstance(target, str) or not ID_PATTERN.match(target)):
                    self.c.error(_join(rpath, "target"), "invalid_id", "Target must be 'local' or an ID.")
                    target = None
                if dest is None or target is None:
                    routes_ok = False
                    continue
                routes.append(Route(str(dest), target))
            if ident and vpc_id and routes_ok and self.declared[ident][1] == path:
                table = RouteTable(ident, vpc_id, tuple(routes), name)
                self.parsed[ident] = table
                out.append((path, table))
        return out

    def _parse_subnets(self, items: list[Any]) -> list[tuple[str, Subnet]]:
        out: list[tuple[str, Subnet]] = []
        required = {"id", "vpc_id", "cidr", "route_table_id"}
        for path, obj in self._each(items, "subnets", required, {"availability_zone", "name"}):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "subnet", path)
            vpc_id = self._ident(obj, "vpc_id", path)
            rt_id = self._ident(obj, "route_table_id", path)
            net = (
                self._cidr(obj["cidr"], _join(path, "cidr"), prefix_range=(16, 28)) if "cidr" in obj else None
            )
            az = self._text(obj, "availability_zone", path)
            name = self._text(obj, "name", path)
            if ident and vpc_id and rt_id and net and self.declared[ident][1] == path:
                subnet = Subnet(ident, vpc_id, str(net), rt_id, az, name)
                self.parsed[ident] = subnet
                out.append((path, subnet))
        return out

    def _parse_security_groups(self, items: list[Any]) -> list[tuple[str, SecurityGroup]]:
        out: list[tuple[str, SecurityGroup]] = []
        required = {"id", "vpc_id", "name", "ingress", "egress"}
        for path, obj in self._each(items, "security_groups", required, {"description"}):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "security_group", path)
            vpc_id = self._ident(obj, "vpc_id", path)
            name = self._text(obj, "name", path)
            description = self._text(obj, "description", path)
            ingress = self._sg_rules(obj, "ingress", path, vpc_id)
            egress = self._sg_rules(obj, "egress", path, vpc_id)
            if (
                ident
                and vpc_id
                and "name" in obj
                and ingress is not None
                and egress is not None
                and self.declared[ident][1] == path
            ):
                sg = SecurityGroup(ident, vpc_id, name, tuple(ingress), tuple(egress), description)
                self.parsed[ident] = sg
                out.append((path, sg))
        return out

    def _sg_rules(
        self, sg_obj: dict[str, Any], direction: str, path: str, vpc_id: str | None
    ) -> list[SecurityGroupRule] | None:
        if direction not in sg_obj:
            return None
        peer_key = f"{'source' if direction == 'ingress' else 'destination'}_security_group_id"
        rules: list[SecurityGroupRule] = []
        ok = True
        for j, raw in enumerate(self._list(sg_obj, direction, path, MAX_RULES_PER_LIST)):
            rpath = f"{path}.{direction}[{j}]"
            robj = self._object(raw, rpath)
            if robj is None:
                ok = False
                continue
            self._keys(robj, rpath, {"protocol"}, {"from_port", "to_port", "cidr", peer_key, "description"})
            ports = self._protocol_ports(robj, rpath)
            has_cidr, has_peer = "cidr" in robj, peer_key in robj
            if has_cidr == has_peer:
                self.c.error(rpath, "invalid_rule_target", f"Specify exactly one of 'cidr' or '{peer_key}'.")
            cidr = None
            if has_cidr:
                net = self._cidr(robj["cidr"], _join(rpath, "cidr"), strict=False)
                cidr = str(net) if net else None
            peer = self._ident(robj, peer_key, rpath) if has_peer else None
            description = self._text(robj, "description", rpath)
            if peer and vpc_id:
                self.pending_sg_refs.append((_join(rpath, peer_key), peer, vpc_id))
            if ports and has_cidr != has_peer and (cidr or peer):
                rules.append(SecurityGroupRule(ports[0], ports[1], ports[2], cidr, peer, description))
            else:
                ok = False
        return rules if ok else None

    def _nacl_rules(self, obj: dict[str, Any], direction: str, path: str) -> list[NaclRule] | None:
        if direction not in obj:
            return None
        rules: list[NaclRule] = []
        ok = True
        seen_numbers: set[int] = set()
        for j, raw in enumerate(self._list(obj, direction, path, MAX_RULES_PER_LIST)):
            rpath = f"{path}.{direction}[{j}]"
            robj = self._object(raw, rpath)
            if robj is None:
                ok = False
                continue
            self._keys(
                robj,
                rpath,
                {"rule_number", "action", "protocol", "cidr"},
                {"from_port", "to_port"},
            )
            number = robj.get("rule_number")
            number_ok = self._is_int(number) and 1 <= number <= 32766
            if "rule_number" in robj and not number_ok:
                self.c.error(_join(rpath, "rule_number"), "invalid_rule_number", "Use an integer 1-32766.")
            elif number_ok and number in seen_numbers:
                self.c.error(
                    _join(rpath, "rule_number"),
                    "duplicate_rule_number",
                    f"Rule number {number} is used twice in {direction}.",
                )
                number_ok = False
            elif number_ok:
                seen_numbers.add(number)
            action = robj.get("action")
            action_ok = action in ("allow", "deny") if isinstance(action, str) else False
            if "action" in robj and not action_ok:
                self.c.error(_join(rpath, "action"), "invalid_action", "Action must be 'allow' or 'deny'.")
            ports = self._protocol_ports(robj, rpath)
            net = self._cidr(robj["cidr"], _join(rpath, "cidr"), strict=False) if "cidr" in robj else None
            if number_ok and action_ok and ports and net:
                rules.append(NaclRule(number, action, ports[0], str(net), ports[1], ports[2]))
            else:
                ok = False
        return rules if ok else None

    def _parse_nacls(self, items: list[Any]) -> list[tuple[str, NetworkAcl]]:
        out: list[tuple[str, NetworkAcl]] = []
        required = {"id", "vpc_id", "subnet_ids", "ingress", "egress"}
        for path, obj in self._each(items, "network_acls", required, {"name"}):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "network_acl", path)
            vpc_id = self._ident(obj, "vpc_id", path)
            name = self._text(obj, "name", path)
            subnet_ids: list[str] = []
            ids_ok = "subnet_ids" in obj
            for k, raw_id in enumerate(self._list(obj, "subnet_ids", path, MAX_RESOURCES)):
                if isinstance(raw_id, str) and ID_PATTERN.match(raw_id):
                    subnet_ids.append(raw_id)
                else:
                    ids_ok = False
                    self.c.error(f"{path}.subnet_ids[{k}]", "invalid_id", "Invalid subnet identifier.")
            ingress = self._nacl_rules(obj, "ingress", path)
            egress = self._nacl_rules(obj, "egress", path)
            if (
                ident
                and vpc_id
                and ids_ok
                and ingress is not None
                and egress is not None
                and self.declared[ident][1] == path
            ):
                acl = NetworkAcl(ident, vpc_id, tuple(subnet_ids), tuple(ingress), tuple(egress), name)
                self.parsed[ident] = acl
                out.append((path, acl))
        return out

    def _parse_instances(self, items: list[Any]) -> list[tuple[str, Instance]]:
        out: list[tuple[str, Instance]] = []
        required = {"id", "subnet_id", "private_ip", "security_group_ids"}
        for path, obj in self._each(items, "instances", required, {"public_ip", "name", "tags"}):
            ident = self._ident(obj, "id", path)
            self._declare(ident, "instance", path)
            subnet_id = self._ident(obj, "subnet_id", path)
            private = (
                self._ipv4(obj["private_ip"], _join(path, "private_ip")) if "private_ip" in obj else None
            )
            public_ip: str | None = None
            public_ok = True
            if obj.get("public_ip") is not None:
                addr = self._ipv4(obj["public_ip"], _join(path, "public_ip"))
                if addr is None:
                    public_ok = False
                elif any(addr in net for net in _NON_PUBLIC_RANGES):
                    self.c.error(
                        _join(path, "public_ip"),
                        "invalid_public_ip",
                        f"'{addr}' is not a public address (private/reserved range).",
                    )
                    public_ok = False
                else:
                    public_ip = str(addr)
            name = self._text(obj, "name", path)
            tags, tags_ok = self._tags(obj, path)

            sg_ids: list[str] = []
            sg_ok = "security_group_ids" in obj
            raw_sgs = self._list(obj, "security_group_ids", path, MAX_SECURITY_GROUPS_PER_INSTANCE + 1)
            if "security_group_ids" in obj and not isinstance(obj["security_group_ids"], list):
                sg_ok = False
            elif not 1 <= len(raw_sgs) <= MAX_SECURITY_GROUPS_PER_INSTANCE:
                if isinstance(obj.get("security_group_ids"), list):
                    self.c.error(
                        _join(path, "security_group_ids"),
                        "invalid_length",
                        f"Provide 1-{MAX_SECURITY_GROUPS_PER_INSTANCE} security groups.",
                    )
                sg_ok = False
            for k, raw_id in enumerate(raw_sgs):
                if isinstance(raw_id, str) and ID_PATTERN.match(raw_id):
                    if raw_id in sg_ids:
                        self.c.error(
                            f"{path}.security_group_ids[{k}]",
                            "duplicate_reference",
                            f"'{raw_id}' is listed more than once.",
                        )
                        sg_ok = False
                    sg_ids.append(raw_id)
                else:
                    sg_ok = False
                    self.c.error(
                        f"{path}.security_group_ids[{k}]", "invalid_id", "Invalid security group ID."
                    )
            if (
                ident
                and subnet_id
                and private
                and public_ok
                and tags_ok
                and sg_ok
                and self.declared[ident][1] == path
            ):
                inst = Instance(ident, subnet_id, str(private), tuple(sg_ids), public_ip, name, tags)
                self.parsed[ident] = inst
                out.append((path, inst))
        return out

    def _tags(self, obj: dict[str, Any], path: str) -> tuple[tuple[tuple[str, str], ...], bool]:
        if "tags" not in obj:
            return (), True
        raw = obj["tags"]
        tpath = _join(path, "tags")
        if not isinstance(raw, dict):
            self.c.error(tpath, "invalid_type", "Expected an object of string tags.")
            return (), False
        if len(raw) > MAX_TAGS:
            self.c.error(tpath, "too_many_items", f"At most {MAX_TAGS} tags are allowed.")
            return (), False
        ok = True
        tags: list[tuple[str, str]] = []
        for key, value in raw.items():
            if (
                not isinstance(value, str)
                or len(key) > MAX_TAG_LENGTH
                or len(value) > MAX_TAG_LENGTH
                or _CONTROL_CHARS.search(key)
                or _CONTROL_CHARS.search(value)
            ):
                self.c.error(
                    f"{tpath}.{key}",
                    "invalid_tag",
                    f"Tags must be strings up to {MAX_TAG_LENGTH} chars without control characters.",
                )
                ok = False
            else:
                tags.append((key, value))
        return tuple(sorted(tags)), ok

    # ---- cross-reference checks ----------------------------------------

    def _ref(self, path: str, value: str, expected: str) -> Any | None:
        declared = self.declared.get(value)
        label = expected.replace("_", " ")
        if declared is None:
            self.c.error(path, "unknown_reference", f"'{value}' does not match any {label} in this file.")
            return None
        if declared[0] != expected:
            self.c.error(
                path,
                "wrong_reference_type",
                f"'{value}' is a {declared[0].replace('_', ' ')}, expected a {label}.",
            )
            return None
        return self.parsed.get(value)

    def _check_igws(self, igws: list[tuple[str, InternetGateway]]) -> None:
        by_vpc: dict[str, str] = {}
        for path, igw in igws:
            self._ref(_join(path, "vpc_id"), igw.vpc_id, "vpc")
            if igw.vpc_id in by_vpc:
                self.c.error(
                    _join(path, "vpc_id"),
                    "multiple_internet_gateways",
                    f"VPC '{igw.vpc_id}' already has an internet gateway ({by_vpc[igw.vpc_id]}).",
                )
            else:
                by_vpc[igw.vpc_id] = igw.id

    def _check_route_tables(self, tables: list[tuple[str, RouteTable]]) -> None:
        for path, table in tables:
            vpc = self._ref(_join(path, "vpc_id"), table.vpc_id, "vpc")
            seen: set[str] = set()
            for j, route in enumerate(table.routes):
                rpath = f"{path}.routes[{j}]"
                if route.destination_cidr in seen:
                    self.c.error(
                        _join(rpath, "destination_cidr"),
                        "duplicate_route",
                        f"Destination {route.destination_cidr} is defined twice.",
                    )
                seen.add(route.destination_cidr)
                tpath = _join(rpath, "target")
                if route.target == "local":
                    if vpc and route.destination_cidr != vpc.cidr:
                        self.c.error(
                            tpath,
                            "invalid_local_route",
                            f"The 'local' route must use the VPC CIDR ({vpc.cidr}).",
                        )
                elif route.target in self.declared:
                    igw = self._ref(tpath, route.target, "internet_gateway")
                    if igw and table.vpc_id != igw.vpc_id:
                        self.c.error(
                            tpath,
                            "cross_vpc_reference",
                            f"Internet gateway '{igw.id}' is attached to a different VPC.",
                        )
                elif _UNSUPPORTED_TARGET_PREFIX.match(route.target):
                    self.c.error(
                        tpath,
                        "unsupported_route_target",
                        "Only 'local' and internet gateway targets are supported.",
                    )
                else:
                    self.c.error(tpath, "unknown_reference", f"'{route.target}' does not match any resource.")

    def _check_subnets(self, subnets: list[tuple[str, Subnet]]) -> None:
        by_vpc: dict[str, list[tuple[str, Subnet]]] = {}
        for path, subnet in subnets:
            vpc = self._ref(_join(path, "vpc_id"), subnet.vpc_id, "vpc")
            table = self._ref(_join(path, "route_table_id"), subnet.route_table_id, "route_table")
            if vpc and not ipaddress.ip_network(subnet.cidr).subnet_of(ipaddress.ip_network(vpc.cidr)):
                self.c.error(
                    _join(path, "cidr"),
                    "subnet_outside_vpc",
                    f"Subnet {subnet.cidr} is not inside VPC CIDR {vpc.cidr}.",
                )
            if table and table.vpc_id != subnet.vpc_id:
                self.c.error(
                    _join(path, "route_table_id"),
                    "cross_vpc_reference",
                    f"Route table '{table.id}' belongs to a different VPC.",
                )
            by_vpc.setdefault(subnet.vpc_id, []).append((path, subnet))
        for entries in by_vpc.values():
            for i, (_, first) in enumerate(entries):
                for path2, second in entries[i + 1 :]:
                    if ipaddress.ip_network(first.cidr).overlaps(ipaddress.ip_network(second.cidr)):
                        self.c.error(
                            _join(path2, "cidr"),
                            "overlapping_subnets",
                            f"Subnet {second.cidr} overlaps {first.id} ({first.cidr}).",
                        )

    def _check_sg_refs(self) -> None:
        for path, peer_id, owner_vpc in self.pending_sg_refs:
            peer = self._ref(path, peer_id, "security_group")
            if peer and peer.vpc_id != owner_vpc:
                self.c.error(
                    path,
                    "cross_vpc_reference",
                    f"Security group '{peer_id}' belongs to a different VPC (peering is unsupported).",
                )

    def _check_nacls(self, nacls: list[tuple[str, NetworkAcl]]) -> None:
        assigned: dict[str, str] = {}
        for path, acl in nacls:
            self._ref(_join(path, "vpc_id"), acl.vpc_id, "vpc")
            for k, subnet_id in enumerate(acl.subnet_ids):
                spath = f"{path}.subnet_ids[{k}]"
                subnet = self._ref(spath, subnet_id, "subnet")
                if subnet and subnet.vpc_id != acl.vpc_id:
                    self.c.error(spath, "cross_vpc_reference", f"Subnet '{subnet_id}' is in a different VPC.")
                if subnet_id in assigned:
                    self.c.error(
                        spath,
                        "multiple_acl_association",
                        f"Subnet '{subnet_id}' is already associated with {assigned[subnet_id]}.",
                    )
                else:
                    assigned[subnet_id] = acl.id

    def _check_instances(self, instances: list[tuple[str, Instance]]) -> None:
        private_seen: dict[tuple[str, str], str] = {}
        public_seen: dict[str, str] = {}
        for path, inst in instances:
            subnet = self._ref(_join(path, "subnet_id"), inst.subnet_id, "subnet")
            if subnet:
                net = ipaddress.ip_network(subnet.cidr)
                ip = ipaddress.ip_address(inst.private_ip)
                ippath = _join(path, "private_ip")
                if ip not in net:
                    self.c.error(ippath, "ip_outside_subnet", f"{ip} is not inside subnet {subnet.cidr}.")
                elif int(ip) - int(net.network_address) < 4 or ip == net.broadcast_address:
                    self.c.error(
                        ippath,
                        "reserved_ip",
                        f"{ip} is reserved by AWS (first four and last address of a subnet).",
                    )
                else:
                    key = (subnet.vpc_id, inst.private_ip)
                    if key in private_seen:
                        self.c.error(
                            ippath,
                            "duplicate_ip",
                            f"{ip} is already used by {private_seen[key]} in this VPC.",
                        )
                    else:
                        private_seen[key] = inst.id
            if inst.public_ip:
                if inst.public_ip in public_seen:
                    self.c.error(
                        _join(path, "public_ip"),
                        "duplicate_ip",
                        f"{inst.public_ip} is already used by {public_seen[inst.public_ip]}.",
                    )
                else:
                    public_seen[inst.public_ip] = inst.id
            for k, sg_id in enumerate(inst.security_group_ids):
                sg = self._ref(f"{path}.security_group_ids[{k}]", sg_id, "security_group")
                if sg and subnet and sg.vpc_id != subnet.vpc_id:
                    self.c.error(
                        f"{path}.security_group_ids[{k}]",
                        "cross_vpc_reference",
                        f"Security group '{sg_id}' is in a different VPC than the instance subnet.",
                    )

    def _warn_unused(self, tables, sgs, subnets, instances) -> None:
        used_tables = {s.route_table_id for _, s in subnets}
        for path, table in tables:
            if table.id not in used_tables:
                self.c.warn(path, "unassociated_route_table", f"Route table '{table.id}' has no subnets.")
        used_sgs = {sg_id for _, inst in instances for sg_id in inst.security_group_ids}
        for path, sg in sgs:
            if sg.id not in used_sgs:
                self.c.warn(
                    path,
                    "unused_security_group",
                    f"Security group '{sg.id}' is not attached to any instance.",
                )
