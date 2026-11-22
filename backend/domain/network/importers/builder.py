"""Shared builder: collects resources from any source and emits the normalized configuration JSON.

The builder owns the awkward parts so the source-specific mappers stay small:

* identifiers are sanitized to the schema's character set (and made unique);
* constructs the schema does not model (NAT/peering/transit-gateway routes, prefix lists,
  IPv6 networks, unsupported protocols) are dropped *with a warning*, never silently;
* AWS defaults are made explicit (the VPC's local route, the main route table, a default
  allow-all egress rule when the source says AWS would add one);
* addresses a plan cannot know (private IPs, public IPs) are assigned deterministically and said so.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from domain.network.schema import (
    ID_PATTERN,
    MAX_RESOURCES,
    MAX_RULES_PER_LIST,
    MAX_TEXT_LENGTH,
    REGION_PATTERN,
    SUPPORTED_PROTOCOLS,
)

DEFAULT_REGION = "us-east-1"
# RFC 5737 documentation range: accepted as "public" by the schema and never routable.
_SYNTHETIC_PUBLIC_NET = ipaddress.ip_network("203.0.113.0/24")
_PROTOCOL_NUMBERS = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
    "-1": "-1",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
}
_UNSUPPORTED_ROUTE_KINDS = ("nat", "pcx", "tgw", "vgw", "eni", "vpce", "instance", "egress-only")


class ImporterError(ValueError):
    """The input cannot be understood at all (as opposed to containing unsupported parts)."""

    def __init__(self, message: str, issues: list[dict[str, str]] | None = None):
        super().__init__(message)
        self.issues = issues or [{"path": "", "code": "import_failed", "message": message}]


@dataclass
class ImportReport:
    """What the importer did: the JSON, plus everything it had to drop, assume or assign."""

    config: dict[str, Any]
    warnings: list[dict[str, str]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


def clean_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    text = "" if value is None else str(value)
    return re.sub(r"[\x00-\x1f\x7f]", " ", text).strip()[:limit]


def normalize_protocol(value: Any) -> str | None:
    """AWS protocol names/numbers -> the schema's tcp/udp/icmp/-1, or None when unsupported."""
    return _PROTOCOL_NUMBERS.get(str(value).strip().lower()) if value is not None else None


def tag_name(tags: Any) -> str:
    """The ``Name`` tag from either ``{"Name": "x"}`` or ``[{"Key": "Name", "Value": "x"}]``."""
    if isinstance(tags, dict):
        return clean_text(tags.get("Name", ""))
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict) and tag.get("Key") == "Name":
                return clean_text(tag.get("Value", ""))
    return ""


def tag_map(tags: Any) -> dict[str, str]:
    pairs: dict[str, str] = {}
    if isinstance(tags, dict):
        items = tags.items()
    elif isinstance(tags, list):
        items = ((t.get("Key"), t.get("Value")) for t in tags if isinstance(t, dict))
    else:
        return pairs
    for key, value in items:
        if isinstance(key, str) and key and not key.startswith("aws:") and isinstance(value, str):
            pairs[clean_text(key, 128)] = clean_text(value, 128)
        if len(pairs) >= 50:
            break
    return pairs


class ConfigBuilder:
    def __init__(self, name: str, region: str = DEFAULT_REGION, *, source: str = "import"):
        self.name = clean_text(name) or source
        self.region = region if REGION_PATTERN.match(region or "") else DEFAULT_REGION
        self.source = source
        self.warnings: list[dict[str, str]] = []
        self._ids: dict[str, str] = {}  # sanitized id -> original key (collision detection)
        self.vpcs: dict[str, dict] = {}
        self.internet_gateways: dict[str, dict] = {}
        self.route_tables: dict[str, dict] = {}
        self.subnets: dict[str, dict] = {}
        self.security_groups: dict[str, dict] = {}
        self.network_acls: dict[str, dict] = {}
        self.instances: dict[str, dict] = {}
        self.extensions: dict[str, list[dict]] = {}
        self.main_route_table: dict[str, str] = {}  # vpc id -> route table id
        self._dropped_routes: dict[str, int] = {}
        self._warned: set[tuple[str, str]] = set()
        self._public_counter = 9

    # ------------------------------------------------------------------ helpers
    def warn(self, code: str, message: str, path: str = "") -> None:
        key = (code, message)
        if key in self._warned or len(self.warnings) >= 200:
            return
        self._warned.add(key)
        self.warnings.append({"path": path, "code": code, "message": message})

    def make_id(self, raw: str) -> str:
        """A schema-safe, unique identifier derived from ``raw`` (an AWS id or an IaC address)."""
        text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(raw)).strip("-._") or "resource"
        if len(text) > 64 or not ID_PATTERN.match(text):
            digest = hashlib.sha1(str(raw).encode()).hexdigest()[:8]
            text = f"{text[:54].strip('-._') or 'r'}-{digest}"
        candidate, n = text, 2
        while candidate in self._ids and self._ids[candidate] != raw:
            suffix = f"-{n}"
            candidate = text[: 64 - len(suffix)] + suffix
            n += 1
        self._ids[candidate] = raw
        return candidate

    def cidr(self, value: Any, what: str, *, allow_ipv6: bool = False) -> str | None:
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            self.warn("INVALID_CIDR", f"{what}: '{value}' is not a CIDR and was skipped.")
            return None
        if net.version == 6 and not allow_ipv6:
            self.warn(
                "IPV6_SKIPPED",
                f"{what}: IPv6 network {net} is not modelled for this resource and was skipped.",
            )
            return None
        return str(net)

    # ------------------------------------------------------------------ core resources
    def add_vpc(self, key: str, cidr: Any, name: str = "") -> str | None:
        net = self.cidr(cidr, f"VPC {key}")
        if net is None:
            self.warn("VPC_SKIPPED", f"VPC {key} has no usable IPv4 CIDR and was skipped.")
            return None
        vid = self.make_id(key)
        self.vpcs[vid] = {"id": vid, "cidr": net, "name": clean_text(name) or vid}
        return vid

    def add_internet_gateway(self, key: str, vpc_id: str | None) -> str | None:
        if not vpc_id or vpc_id not in self.vpcs:
            self.warn(
                "IGW_UNATTACHED",
                f"Internet gateway {key} is not attached to an imported VPC and was skipped.",
            )
            return None
        gid = self.make_id(key)
        self.internet_gateways[gid] = {"id": gid, "vpc_id": vpc_id}
        return gid

    def add_route_table(self, key: str, vpc_id: str | None, name: str = "") -> str | None:
        if not vpc_id or vpc_id not in self.vpcs:
            self.warn("ROUTE_TABLE_SKIPPED", f"Route table {key} belongs to no imported VPC and was skipped.")
            return None
        rid = self.make_id(key)
        self.route_tables[rid] = {"id": rid, "vpc_id": vpc_id, "name": clean_text(name) or rid, "routes": []}
        return rid

    def add_route(
        self, table_id: str | None, destination: Any, target_kind: str, target_id: str | None
    ) -> None:
        """``target_kind`` is "local", "igw" or the AWS prefix of an unsupported target (nat, pcx...)."""
        table = self.route_tables.get(table_id or "")
        if table is None:
            return
        net = self.cidr(destination, f"Route in {table['id']}")
        if net is None:
            return
        if target_kind == "igw":
            if target_id in self.internet_gateways:
                table["routes"].append({"destination_cidr": net, "target": target_id})
            else:
                self.warn(
                    "ROUTE_DROPPED",
                    f"A route in {table['id']} points at an unknown internet gateway and was dropped.",
                )
        elif target_kind == "local":
            table["routes"].append({"destination_cidr": net, "target": "local"})
        else:
            self._dropped_routes[target_kind] = self._dropped_routes.get(target_kind, 0) + 1

    def add_subnet(
        self,
        key: str,
        vpc_id: str | None,
        cidr: Any,
        *,
        zone: str = "",
        name: str = "",
        route_table_id: str | None = None,
    ) -> str | None:
        net = self.cidr(cidr, f"Subnet {key}")
        if net is None or not vpc_id or vpc_id not in self.vpcs:
            self.warn("SUBNET_SKIPPED", f"Subnet {key} has no usable IPv4 CIDR or VPC and was skipped.")
            return None
        sid = self.make_id(key)
        self.subnets[sid] = {
            "id": sid,
            "vpc_id": vpc_id,
            "cidr": net,
            "route_table_id": route_table_id or "",
            "availability_zone": clean_text(zone, 32),
            "name": clean_text(name) or sid,
        }
        return sid

    def rule(
        self,
        protocol: Any,
        from_port: Any,
        to_port: Any,
        *,
        cidr: Any = None,
        peer: str | None = None,
        description: str = "",
        direction: str = "ingress",
        where: str = "",
    ) -> dict | None:
        proto = normalize_protocol(protocol)
        if proto is None or proto not in SUPPORTED_PROTOCOLS:
            self.warn(
                "PROTOCOL_SKIPPED", f"{where}: protocol '{protocol}' is not modelled; the rule was skipped."
            )
            return None
        entry: dict[str, Any] = {"protocol": proto}
        if proto in ("tcp", "udp"):
            low = 0 if from_port in (None, "") else from_port
            high = 65535 if to_port in (None, "") else to_port
            try:
                entry["from_port"], entry["to_port"] = int(low), int(high)
            except (TypeError, ValueError):
                self.warn(
                    "PORT_SKIPPED", f"{where}: ports '{from_port}-{to_port}' are not numbers; rule skipped."
                )
                return None
        elif proto == "icmp":
            try:
                if from_port not in (None, "") and to_port not in (None, ""):
                    entry["from_port"], entry["to_port"] = int(from_port), int(to_port)
            except (TypeError, ValueError):
                pass
        if peer:
            entry[f"{'source' if direction == 'ingress' else 'destination'}_security_group_id"] = peer
        elif cidr:
            net = self.cidr(cidr, where, allow_ipv6=True)
            if net is None:
                return None
            entry["cidr"] = net
        else:
            return None
        if description:
            entry["description"] = clean_text(description)
        return entry

    def add_security_group(
        self,
        key: str,
        vpc_id: str | None,
        name: str,
        description: str = "",
        *,
        ingress: list[dict] | None = None,
        egress: list[dict] | None = None,
        default_egress: bool = False,
    ) -> str | None:
        if not vpc_id or vpc_id not in self.vpcs:
            self.warn("SG_SKIPPED", f"Security group {key} belongs to no imported VPC and was skipped.")
            return None
        gid = self.make_id(key)
        rules_out = list(egress or [])
        if default_egress and not rules_out:
            rules_out = [{"protocol": "-1", "cidr": "0.0.0.0/0", "description": "AWS default egress"}]
            self.warn(
                "DEFAULT_EGRESS_ASSUMED",
                f"{key} declares no egress rules; AWS adds an allow-all egress rule by default, "
                "so it was added.",
            )
        self.security_groups[gid] = {
            "id": gid,
            "vpc_id": vpc_id,
            "name": clean_text(name) or gid,
            "description": clean_text(description),
            "ingress": list(ingress or []),
            "egress": rules_out,
        }
        return gid

    def add_network_acl(self, key: str, vpc_id: str | None, name: str = "") -> str | None:
        if not vpc_id or vpc_id not in self.vpcs:
            self.warn("NACL_SKIPPED", f"Network ACL {key} belongs to no imported VPC and was skipped.")
            return None
        aid = self.make_id(key)
        self.network_acls[aid] = {
            "id": aid,
            "vpc_id": vpc_id,
            "name": clean_text(name) or aid,
            "subnet_ids": [],
            "ingress": [],
            "egress": [],
        }
        return aid

    def add_nacl_entry(
        self,
        acl_id: str | None,
        *,
        egress: bool,
        number: Any,
        action: str,
        protocol: Any,
        cidr: Any,
        from_port: Any = None,
        to_port: Any = None,
    ) -> None:
        acl = self.network_acls.get(acl_id or "")
        if acl is None:
            return
        try:
            rule_number = int(number)
        except (TypeError, ValueError):
            return
        if not 1 <= rule_number <= 32766:  # 32767 / "*" is the implicit final deny
            return
        proto = normalize_protocol(protocol)
        action = str(action).lower()
        net = self.cidr(cidr, f"Network ACL {acl['id']}", allow_ipv6=True)
        if proto is None or action not in ("allow", "deny") or net is None:
            self.warn(
                "NACL_ENTRY_SKIPPED", f"An entry of network ACL {acl['id']} is not modelled and was skipped."
            )
            return
        entry: dict[str, Any] = {"rule_number": rule_number, "action": action, "protocol": proto, "cidr": net}
        if proto in ("tcp", "udp"):
            try:
                entry["from_port"] = int(0 if from_port in (None, "") else from_port)
                entry["to_port"] = int(65535 if to_port in (None, "") else to_port)
            except (TypeError, ValueError):
                return
        (acl["egress"] if egress else acl["ingress"]).append(entry)

    def add_instance(
        self,
        key: str,
        subnet_id: str | None,
        security_group_ids: list[str],
        *,
        name: str = "",
        private_ip: str | None = None,
        public_ip: str | bool | None = None,
        tags: dict[str, str] | None = None,
    ) -> str | None:
        subnet = self.subnets.get(subnet_id or "")
        groups = [g for g in dict.fromkeys(security_group_ids) if g in self.security_groups]
        if subnet is None:
            self.warn("INSTANCE_SKIPPED", f"Instance {key} is not in an imported subnet and was skipped.")
            return None
        if not groups:
            self.warn("INSTANCE_SKIPPED", f"Instance {key} has no imported security group and was skipped.")
            return None
        iid = self.make_id(key)
        self.instances[iid] = {
            "id": iid,
            "name": clean_text(name) or iid,
            "subnet_id": subnet["id"],
            "private_ip": private_ip or "",
            "security_group_ids": groups[:5],
            "tags": dict(list((tags or {}).items())[:50]),
            "_public": public_ip,
        }
        return iid

    # ------------------------------------------------------------------ extensions
    def add_extension(self, kind: str, item: dict) -> None:
        self.extensions.setdefault(kind, []).append(item)

    # ------------------------------------------------------------------ output
    def _finish_routing(self) -> None:
        for vpc_id, vpc in self.vpcs.items():
            tables = [t for t in self.route_tables.values() if t["vpc_id"] == vpc_id]
            main = self.main_route_table.get(vpc_id)
            if main not in self.route_tables:
                main = (
                    tables[0]["id"]
                    if tables
                    else self.add_route_table(f"main-{vpc_id}", vpc_id, "main (implicit)")
                )
                if main:
                    self.warn(
                        "MAIN_ROUTE_TABLE_ASSUMED",
                        f"VPC {vpc_id}: no main route table was declared; one was assumed.",
                    )
            self.main_route_table[vpc_id] = main or ""
            for table in (t for t in self.route_tables.values() if t["vpc_id"] == vpc_id):
                if not any(r["target"] == "local" for r in table["routes"]):
                    table["routes"].insert(0, {"destination_cidr": vpc["cidr"], "target": "local"})
        for subnet in self.subnets.values():
            if subnet["route_table_id"] not in self.route_tables:
                subnet["route_table_id"] = self.main_route_table.get(subnet["vpc_id"], "")
        for subnet in [s for s in self.subnets.values() if not s["route_table_id"]]:
            self.warn("SUBNET_SKIPPED", f"Subnet {subnet['id']} has no route table and was skipped.")
            del self.subnets[subnet["id"]]
        for kind, count in sorted(self._dropped_routes.items()):
            label = "NAT gateway" if kind == "nat" else "VPC peering" if kind == "pcx" else kind
            self.warn(
                "UNSUPPORTED_ROUTE_TARGET",
                f"{count} route(s) via {label} were dropped: the model has no such route target yet, so "
                "outbound/peered paths through them are not evaluated.",
            )

    def _assign_addresses(self) -> None:
        used_private: dict[str, set[str]] = {}
        for inst in self.instances.values():
            used_private.setdefault(self.subnets[inst["subnet_id"]]["vpc_id"], set()).add(inst["private_ip"])
        for inst in self.instances.values():
            subnet = self.subnets[inst["subnet_id"]]
            net = ipaddress.ip_network(subnet["cidr"])
            if not inst["private_ip"]:
                taken = used_private.setdefault(subnet["vpc_id"], set())
                for host in list(net.hosts())[3:260]:  # skip the AWS-reserved first addresses
                    if str(host) not in taken:
                        inst["private_ip"] = str(host)
                        taken.add(str(host))
                        self.warn(
                            "PRIVATE_IP_ASSIGNED",
                            f"{inst['id']} has no known private IP (it is assigned at apply time); "
                            f"{inst['private_ip']} was assigned from {subnet['cidr']} for analysis.",
                        )
                        break
            wants_public = inst.pop("_public")
            if wants_public is True:
                self._public_counter += 1
                host = _SYNTHETIC_PUBLIC_NET[min(self._public_counter, 254)]
                inst["public_ip"] = str(host)
                self.warn(
                    "PUBLIC_IP_ASSIGNED",
                    f"{inst['id']} gets a public IP at apply time; the documentation address {host} stands "
                    "in for it so exposure can be analysed.",
                )
            elif isinstance(wants_public, str) and wants_public:
                inst["public_ip"] = wants_public

    def build(self) -> ImportReport:
        self._finish_routing()
        # NACLs may only cover subnets that survived
        for acl in self.network_acls.values():
            acl["subnet_ids"] = [s for s in acl["subnet_ids"] if s in self.subnets]
        self._assign_addresses()

        sections = {
            "vpcs": list(self.vpcs.values()),
            "subnets": list(self.subnets.values()),
            "internet_gateways": list(self.internet_gateways.values()),
            "route_tables": list(self.route_tables.values()),
            "security_groups": list(self.security_groups.values()),
            "network_acls": list(self.network_acls.values()),
            "instances": list(self.instances.values()),
        }
        total = sum(len(v) for v in sections.values())
        if total == 0:
            raise ImporterError("No supported network resources were found in the input.")
        if total > MAX_RESOURCES:
            raise ImporterError(
                f"The input describes {total} resources; at most {MAX_RESOURCES} are supported. "
                "Import one VPC at a time."
            )
        for sg in sections["security_groups"]:
            for direction in ("ingress", "egress"):
                if len(sg[direction]) > MAX_RULES_PER_LIST:
                    self.warn(
                        "RULES_TRUNCATED",
                        f"{sg['id']} has more than {MAX_RULES_PER_LIST} {direction} rules; "
                        "the rest were dropped.",
                    )
                    sg[direction] = sg[direction][:MAX_RULES_PER_LIST]

        config: dict[str, Any] = {
            "schema_version": "1.0",
            "name": self.name,
            "region": self.region,
            **sections,
        }
        extensions = {k: v for k, v in self.extensions.items() if v}
        if extensions:
            config["extensions"] = extensions
        return ImportReport(
            config=config,
            warnings=self.warnings,
            stats={k: len(v) for k, v in sections.items() if v},
        )
