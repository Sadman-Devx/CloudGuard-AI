"""Optional resources beyond the core network subset.

Pure Python (no Django, no import of ``schema`` so there is no cycle). The configuration JSON may
carry one extra top-level object, ``"extensions"``::

    "extensions": {
      "load_balancers": [...], "databases": [...], "buckets": [...],
      "iam_roles": [...], "nat_gateways": [...], "vpc_peerings": [...]
    }

It is validated in the same pass as the rest of the configuration (every problem is reported with a
JSON path) and cross-checked against the core resources. What each kind is used for:

* ``load_balancers``, ``databases``, ``buckets``, ``iam_roles`` become nodes and edges of the attack
  graph (``attack_graph.build_attack_graph``);
* ``nat_gateways`` and ``vpc_peerings`` are validated and kept, but no reachability model uses them
  yet, so they never create or remove an attack path (the graph says so in its warnings).

The core reachability engine and the SG rules still look only at the core resources.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RESERVED_IDS = frozenset({"internet"})
MAX_ITEMS = 200
MAX_TEXT = 200

ENGINE_PORTS = {
    "postgres": 5432,
    "aurora-postgresql": 5432,
    "mysql": 3306,
    "mariadb": 3306,
    "aurora-mysql": 3306,
    "mssql": 1433,
    "oracle": 1521,
    "mongodb": 27017,
    "redis": 6379,
}
ACCESS_LEVELS = ("read", "write", "admin")
LB_SCHEMES = ("internet-facing", "internal")
ANY_RESOURCE = "*"

Issue = tuple[str, str, str]  # (path, code, message)


@dataclass(frozen=True)
class NatGateway:
    id: str
    subnet_id: str
    name: str = ""


@dataclass(frozen=True)
class VpcPeering:
    id: str
    vpc_id: str
    peer_vpc_id: str
    name: str = ""


@dataclass(frozen=True)
class LoadBalancer:
    id: str
    name: str
    scheme: str
    subnet_ids: tuple[str, ...]
    security_group_ids: tuple[str, ...]
    listener_ports: tuple[int, ...]
    target_instance_ids: tuple[str, ...] = ()
    target_port: int | None = None  # None: the instance port equals the listener port


@dataclass(frozen=True)
class Database:
    id: str
    name: str
    engine: str
    port: int
    subnet_ids: tuple[str, ...]
    security_group_ids: tuple[str, ...]
    publicly_accessible: bool = False
    sensitive: bool = True
    encrypted: bool = False


@dataclass(frozen=True)
class Bucket:
    id: str
    name: str
    public: bool = False
    sensitive: bool = False
    encrypted: bool = False


@dataclass(frozen=True)
class Permission:
    access: str  # read | write | admin
    resource_ids: tuple[str, ...]  # bucket / database ids, or ("*",)


@dataclass(frozen=True)
class IamRole:
    id: str
    name: str
    instance_ids: tuple[str, ...] = ()
    permissions: tuple[Permission, ...] = ()
    can_assume: tuple[str, ...] = ()
    imds_v2_required: bool = False


@dataclass(frozen=True)
class Extensions:
    nat_gateways: tuple[NatGateway, ...] = ()
    vpc_peerings: tuple[VpcPeering, ...] = ()
    load_balancers: tuple[LoadBalancer, ...] = ()
    databases: tuple[Database, ...] = ()
    buckets: tuple[Bucket, ...] = ()
    iam_roles: tuple[IamRole, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.nat_gateways,
                self.vpc_peerings,
                self.load_balancers,
                self.databases,
                self.buckets,
                self.iam_roles,
            )
        )


_KINDS = ("nat_gateways", "vpc_peerings", "load_balancers", "databases", "buckets", "iam_roles")


class _Parser:
    def __init__(
        self,
        *,
        instance_ids: set[str],
        subnet_ids: set[str],
        security_group_ids: set[str],
        vpc_ids: set[str],
        taken_ids: set[str],
    ) -> None:
        self.instance_ids = instance_ids
        self.subnet_ids = subnet_ids
        self.sg_ids = security_group_ids
        self.vpc_ids = vpc_ids
        self.taken = set(taken_ids) | RESERVED_IDS
        self.issues: list[Issue] = []
        self.own_ids: dict[str, str] = {}  # extension id -> path (duplicate detection)

    # ---- primitives ----------------------------------------------------------------------

    def err(self, path: str, code: str, message: str) -> None:
        if len(self.issues) < 100:
            self.issues.append((path, code, message))

    def obj(self, value: Any, path: str, required: set[str], optional: set[str]) -> dict | None:
        if not isinstance(value, dict):
            self.err(path, "invalid_type", "Expected an object.")
            return None
        for key in sorted(required):
            if key not in value:
                self.err(f"{path}.{key}", "required", f"'{key}' is required.")
        for key in value:
            if key not in required and key not in optional:
                self.err(f"{path}.{key}", "unknown_field", f"Unknown field '{key}'.")
        return value

    def text(self, obj: dict, key: str, path: str, default: str = "") -> str:
        value = obj.get(key, default)
        if not isinstance(value, str) or len(value) > MAX_TEXT or re.search(r"[\x00-\x1f\x7f]", value):
            self.err(f"{path}.{key}", "invalid_text", "Expected a short string without control characters.")
            return default
        return value

    def boolean(self, obj: dict, key: str, path: str, default: bool) -> bool:
        value = obj.get(key, default)
        if not isinstance(value, bool):
            self.err(f"{path}.{key}", "invalid_type", "Expected true or false.")
            return default
        return value

    def ident(self, obj: dict, path: str) -> str | None:
        value = obj.get("id")
        if not isinstance(value, str) or not ID_PATTERN.match(value):
            self.err(f"{path}.id", "invalid_id", "Identifier must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}.")
            return None
        if value in self.taken:
            self.err(f"{path}.id", "duplicate_id", f"'{value}' is already used by another resource.")
            return None
        if value in self.own_ids:
            self.err(f"{path}.id", "duplicate_id", f"'{value}' is already declared at {self.own_ids[value]}.")
            return None
        self.own_ids[value] = path
        return value

    def ref(self, value: Any, path: str, known: set[str], label: str) -> str | None:
        if not isinstance(value, str) or value not in known:
            self.err(path, "unknown_reference", f"Unknown {label}.")
            return None
        return value

    def ref_list(
        self, obj: dict, key: str, path: str, known: set[str], label: str, *, required: bool = False
    ) -> tuple[str, ...]:
        if key not in obj:
            if required:
                self.err(f"{path}.{key}", "required", f"'{key}' is required.")
            return ()
        value = obj[key]
        field = f"{path}.{key}"
        if not isinstance(value, list) or len(value) > MAX_ITEMS or (required and not value):
            self.err(
                field, "invalid_list", f"Expected a {'non-empty ' if required else ''}list of {label} ids."
            )
            return ()
        out = [self.ref(v, f"{field}[{i}]", known, label) for i, v in enumerate(value)]
        return tuple(dict.fromkeys(v for v in out if v))

    def port(self, value: Any, path: str) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            self.err(path, "invalid_port", "Port must be an integer from 1 to 65535.")
            return None
        return value

    def items(self, root: dict, key: str) -> list[tuple[str, Any]]:
        if key not in root:
            return []
        value = root[key]
        if not isinstance(value, list) or len(value) > MAX_ITEMS:
            self.err(f"extensions.{key}", "invalid_list", f"Expected a list of at most {MAX_ITEMS} items.")
            return []
        return [(f"extensions.{key}[{i}]", v) for i, v in enumerate(value)]

    # ---- kinds ---------------------------------------------------------------------------

    def nat_gateways(self, root: dict) -> list[NatGateway]:
        out = []
        for path, raw in self.items(root, "nat_gateways"):
            o = self.obj(raw, path, {"id", "subnet_id"}, {"name"})
            if o is None:
                continue
            ident = self.ident(o, path)
            subnet = self.ref(o.get("subnet_id"), f"{path}.subnet_id", self.subnet_ids, "subnet")
            name = self.text(o, "name", path)
            if ident and subnet:
                out.append(NatGateway(ident, subnet, name))
        return out

    def vpc_peerings(self, root: dict) -> list[VpcPeering]:
        out = []
        for path, raw in self.items(root, "vpc_peerings"):
            o = self.obj(raw, path, {"id", "vpc_id", "peer_vpc_id"}, {"name"})
            if o is None:
                continue
            ident = self.ident(o, path)
            a = self.ref(o.get("vpc_id"), f"{path}.vpc_id", self.vpc_ids, "VPC")
            b = self.ref(o.get("peer_vpc_id"), f"{path}.peer_vpc_id", self.vpc_ids, "VPC")
            if a and b and a == b:
                self.err(f"{path}.peer_vpc_id", "invalid_peering", "A VPC cannot peer with itself.")
                b = None
            name = self.text(o, "name", path)
            if ident and a and b:
                out.append(VpcPeering(ident, a, b, name))
        return out

    def load_balancers(self, root: dict) -> list[LoadBalancer]:
        out = []
        for path, raw in self.items(root, "load_balancers"):
            o = self.obj(
                raw,
                path,
                {"id", "scheme", "subnet_ids", "security_group_ids", "listener_ports"},
                {"name", "target_instance_ids", "target_port"},
            )
            if o is None:
                continue
            ident = self.ident(o, path)
            scheme = o.get("scheme")
            if scheme not in LB_SCHEMES:
                self.err(f"{path}.scheme", "invalid_value", f"scheme must be one of {', '.join(LB_SCHEMES)}.")
                scheme = None
            subnets = self.ref_list(o, "subnet_ids", path, self.subnet_ids, "subnet", required=True)
            groups = self.ref_list(
                o, "security_group_ids", path, self.sg_ids, "security group", required=True
            )
            targets = self.ref_list(o, "target_instance_ids", path, self.instance_ids, "instance")
            ports_raw = o.get("listener_ports")
            ports: list[int] = []
            if not isinstance(ports_raw, list) or not ports_raw or len(ports_raw) > 20:
                self.err(f"{path}.listener_ports", "invalid_list", "Expected 1-20 listener ports.")
            else:
                for i, p in enumerate(ports_raw):
                    checked = self.port(p, f"{path}.listener_ports[{i}]")
                    if checked:
                        ports.append(checked)
            target_port = None
            if o.get("target_port") is not None:
                target_port = self.port(o["target_port"], f"{path}.target_port")
            name = self.text(o, "name", path, ident or "")
            if ident and scheme and subnets and groups and ports:
                out.append(
                    LoadBalancer(
                        ident,
                        name,
                        scheme,
                        subnets,
                        groups,
                        tuple(dict.fromkeys(ports)),
                        targets,
                        target_port,
                    )
                )
        return out

    def databases(self, root: dict) -> list[Database]:
        out = []
        for path, raw in self.items(root, "databases"):
            o = self.obj(
                raw,
                path,
                {"id", "engine", "subnet_ids", "security_group_ids"},
                {"name", "port", "publicly_accessible", "sensitive", "encrypted"},
            )
            if o is None:
                continue
            ident = self.ident(o, path)
            engine = o.get("engine")
            if engine not in ENGINE_PORTS:
                self.err(
                    f"{path}.engine",
                    "invalid_value",
                    f"engine must be one of {', '.join(sorted(ENGINE_PORTS))}.",
                )
                engine = None
            port = ENGINE_PORTS.get(engine or "", 0)
            if o.get("port") is not None:
                port = self.port(o["port"], f"{path}.port") or port
            subnets = self.ref_list(o, "subnet_ids", path, self.subnet_ids, "subnet", required=True)
            groups = self.ref_list(
                o, "security_group_ids", path, self.sg_ids, "security group", required=True
            )
            name = self.text(o, "name", path, ident or "")
            public = self.boolean(o, "publicly_accessible", path, False)
            sensitive = self.boolean(o, "sensitive", path, True)
            encrypted = self.boolean(o, "encrypted", path, False)
            if ident and engine and port and subnets and groups:
                out.append(Database(ident, name, engine, port, subnets, groups, public, sensitive, encrypted))
        return out

    def buckets(self, root: dict) -> list[Bucket]:
        out = []
        for path, raw in self.items(root, "buckets"):
            o = self.obj(raw, path, {"id"}, {"name", "public", "sensitive", "encrypted"})
            if o is None:
                continue
            ident = self.ident(o, path)
            name = self.text(o, "name", path, ident or "")
            public = self.boolean(o, "public", path, False)
            sensitive = self.boolean(o, "sensitive", path, False)
            encrypted = self.boolean(o, "encrypted", path, False)
            if ident:
                out.append(Bucket(ident, name, public, sensitive, encrypted))
        return out

    def iam_roles(self, root: dict) -> list[tuple[str, Any, IamRole]]:
        """Parsed without cross-role / resource checks; ``parse_extensions`` finishes those."""
        out = []
        for path, raw in self.items(root, "iam_roles"):
            o = self.obj(
                raw, path, {"id"}, {"name", "instance_ids", "permissions", "can_assume", "imds_v2_required"}
            )
            if o is None:
                continue
            ident = self.ident(o, path)
            name = self.text(o, "name", path, ident or "")
            instances = self.ref_list(o, "instance_ids", path, self.instance_ids, "instance")
            imds = self.boolean(o, "imds_v2_required", path, False)
            perms_raw = o.get("permissions", [])
            perms: list[tuple[str, str, list]] = []
            if not isinstance(perms_raw, list) or len(perms_raw) > 50:
                self.err(f"{path}.permissions", "invalid_list", "Expected a list of at most 50 permissions.")
            else:
                for i, p_raw in enumerate(perms_raw):
                    p_path = f"{path}.permissions[{i}]"
                    po = self.obj(p_raw, p_path, {"access", "resource_ids"}, set())
                    if po is None:
                        continue
                    access = po.get("access")
                    if access not in ACCESS_LEVELS:
                        self.err(
                            f"{p_path}.access",
                            "invalid_value",
                            f"access must be one of {', '.join(ACCESS_LEVELS)}.",
                        )
                        continue
                    ids = po.get("resource_ids")
                    if (
                        not isinstance(ids, list)
                        or not ids
                        or len(ids) > MAX_ITEMS
                        or not all(isinstance(x, str) for x in ids)
                    ):
                        self.err(
                            f"{p_path}.resource_ids",
                            "invalid_list",
                            "Expected a non-empty list of resource ids or '*'.",
                        )
                        continue
                    perms.append((p_path, access, ids))
            assume = o.get("can_assume", [])
            if (
                not isinstance(assume, list)
                or len(assume) > MAX_ITEMS
                or not all(isinstance(x, str) for x in assume)
            ):
                self.err(f"{path}.can_assume", "invalid_list", "Expected a list of role ids.")
                assume = []
            if ident:
                out.append((ident, (path, perms, assume), IamRole(ident, name, instances, (), (), imds)))
        return out


def parse_extensions(
    raw: Any,
    *,
    instance_ids: Iterable[str],
    subnet_ids: Iterable[str],
    security_group_ids: Iterable[str],
    vpc_ids: Iterable[str],
    taken_ids: Iterable[str] = (),
) -> tuple[Extensions, list[Issue]]:
    """Validate the ``extensions`` object. Returns the typed result and every issue found."""
    parser = _Parser(
        instance_ids=set(instance_ids),
        subnet_ids=set(subnet_ids),
        security_group_ids=set(security_group_ids),
        vpc_ids=set(vpc_ids),
        taken_ids=set(taken_ids),
    )
    if not isinstance(raw, dict):
        parser.err("extensions", "invalid_type", "Expected an object.")
        return Extensions(), parser.issues
    for key in raw:
        if key not in _KINDS:
            parser.err(f"extensions.{key}", "unknown_field", f"Unknown field '{key}'.")

    nat = parser.nat_gateways(raw)
    peerings = parser.vpc_peerings(raw)
    lbs = parser.load_balancers(raw)
    dbs = parser.databases(raw)
    buckets = parser.buckets(raw)
    parsed_roles = parser.iam_roles(raw)

    # Cross-checks that need every extension id.
    data_ids = {d.id for d in dbs} | {b.id for b in buckets}
    role_ids = {ident for ident, _, _ in parsed_roles}
    roles: list[IamRole] = []
    for ident, (path, perms, assume), base in parsed_roles:
        permissions: list[Permission] = []
        for p_path, access, ids in perms:
            ok = True
            for i, rid in enumerate(ids):
                if rid != ANY_RESOURCE and rid not in data_ids:
                    parser.err(
                        f"{p_path}.resource_ids[{i}]", "unknown_reference", "Unknown bucket or database."
                    )
                    ok = False
            if ok:
                permissions.append(Permission(access, tuple(dict.fromkeys(ids))))
        can_assume: list[str] = []
        for i, rid in enumerate(assume):
            if rid not in role_ids or rid == ident:
                parser.err(
                    f"{path}.can_assume[{i}]", "unknown_reference", "Unknown role (or the role itself)."
                )
            else:
                can_assume.append(rid)
        roles.append(
            IamRole(
                base.id,
                base.name,
                base.instance_ids,
                tuple(permissions),
                tuple(dict.fromkeys(can_assume)),
                base.imds_v2_required,
            )
        )

    return (
        Extensions(tuple(nat), tuple(peerings), tuple(lbs), tuple(dbs), tuple(buckets), tuple(roles)),
        parser.issues,
    )


def extensions_from_json(raw_config: Any, config: Any) -> Extensions:
    """Typed extensions for a stored configuration (already validated at import time).

    ``config`` is the parsed ``NetworkConfig``. Returns an empty ``Extensions`` when the JSON has no
    ``extensions`` object.
    """
    section = raw_config.get("extensions") if isinstance(raw_config, dict) else None
    if section is None:
        return Extensions()
    extensions, _ = parse_extensions(section, **core_ids(config))
    return extensions


def core_ids(config: Any) -> dict[str, set[str]]:
    """Id sets of the core resources, in the keyword form ``parse_extensions`` expects."""
    taken = {
        r.id
        for group in (
            config.vpcs,
            config.subnets,
            config.internet_gateways,
            config.route_tables,
            config.security_groups,
            config.network_acls,
            config.instances,
        )
        for r in group
    }
    return {
        "instance_ids": {i.id for i in config.instances},
        "subnet_ids": {s.id for s in config.subnets},
        "security_group_ids": {g.id for g in config.security_groups},
        "vpc_ids": {v.id for v in config.vpcs},
        "taken_ids": taken,
    }
