"""Terraform importer: ``terraform show -json`` of a plan or a state -> normalized configuration.

Resource attributes that Terraform only knows at apply time (ids, ARNs) are missing from a plan, so
cross-references are resolved through the plan's ``configuration`` section (the ``references``
Terraform records for every expression). Identifiers in the result are the resource addresses
(``aws_security_group.web``) when the real id is unknown, and the real id when a state provides it.

Supported: aws_vpc, aws_internet_gateway, aws_route_table (+ aws_route), aws_main_route_table_association,
aws_route_table_association, aws_subnet, aws_security_group (+ aws_security_group_rule and the
aws_vpc_security_group_{ingress,egress}_rule resources), aws_network_acl (+ _rule, _association),
aws_instance and, as ``extensions``, aws_db_instance, aws_lb/aws_alb (+ listeners) and aws_s3_bucket.
Everything else is ignored; IAM resources are reported as not imported.
"""

from __future__ import annotations

import re
from typing import Any

from domain.network.importers.builder import (
    ConfigBuilder,
    ImporterError,
    ImportReport,
    clean_text,
    tag_map,
    tag_name,
)
from domain.network.schema import REGION_PATTERN

_INDEX = re.compile(r"\[[^\]]*\]")
_REFERENCE = re.compile(r"^((?:module\.[\w-]+\.)*)(aws_\w+)\.([\w-]+)")
_ENGINES = (
    ("aurora-postgresql", "aurora-postgresql"),
    ("aurora-mysql", "aurora-mysql"),
    ("aurora", "aurora-mysql"),
    ("postgres", "postgres"),
    ("mariadb", "mariadb"),
    ("mysql", "mysql"),
    ("sqlserver", "mssql"),
    ("oracle", "oracle"),
)
_UNSUPPORTED_GATEWAYS = (
    ("nat_gateway_id", "nat"),
    ("vpc_peering_connection_id", "pcx"),
    ("transit_gateway_id", "tgw"),
    ("vpc_endpoint_id", "vpce"),
    ("network_interface_id", "eni"),
    ("instance_id", "instance"),
    ("egress_only_gateway_id", "egress-only"),
    ("carrier_gateway_id", "eni"),
    ("local_gateway_id", "eni"),
)


def _base(address: str) -> str:
    return _INDEX.sub("", address)


def _walk_module(module: dict, out: list[dict]) -> None:
    out.extend(r for r in module.get("resources", []) if isinstance(r, dict) and r.get("mode") == "managed")
    for child in module.get("child_modules", []) or []:
        if isinstance(child, dict):
            _walk_module(child, out)


def _walk_config(module: dict, prefix: str, out: dict[str, dict]) -> None:
    for res in module.get("resources", []) or []:
        if isinstance(res, dict) and res.get("address"):
            out[prefix + res["address"]] = res.get("expressions") or {}
    for call_name, call in (module.get("module_calls") or {}).items():
        if isinstance(call, dict) and isinstance(call.get("module"), dict):
            _walk_config(call["module"], f"{prefix}module.{call_name}.", out)


class _Context:
    def __init__(self, document: dict):
        values = document.get("planned_values") or document.get("values") or {}
        root = values.get("root_module")
        if not isinstance(root, dict):
            raise ImporterError(
                "This does not look like `terraform show -json` output (no planned_values / values section)."
            )
        self.resources: list[dict] = []
        _walk_module(root, self.resources)
        self.expressions: dict[str, dict] = {}
        config_root = (document.get("configuration") or {}).get("root_module")
        if isinstance(config_root, dict):
            _walk_config(config_root, "", self.expressions)
        self.document = document
        self.ids: dict[str, str] = {}  # resource base address -> builder id
        self.actual: dict[str, str] = {}  # real AWS id -> builder id
        self.by_address = {_base(r["address"]): r for r in self.resources if r.get("address")}

    # ---- resolving references ------------------------------------------------------------
    def module_prefix(self, res: dict) -> str:
        match = re.match(r"^((?:module\.[\w-]+(?:\[[^\]]*\])?\.)*)", res["address"])
        return _INDEX.sub("", match.group(1)) if match else ""

    def _targets(self, res: dict, expr: Any) -> list[str]:
        refs = (expr or {}).get("references") if isinstance(expr, dict) else None
        found: list[str] = []
        for ref in refs or []:
            match = _REFERENCE.match(ref)
            if match:
                target = f"{self.module_prefix(res)}{match.group(2)}.{match.group(3)}"
                if target not in found and target != _base(res["address"]):
                    found.append(target)
        return found

    def expr(self, res: dict, *path: Any) -> Any:
        node: Any = self.expressions.get(_base(res["address"]), {})
        for step in path:
            if isinstance(node, dict):
                node = node.get(step)
            elif isinstance(node, list) and isinstance(step, int) and step < len(node):
                node = node[step]
            else:
                return None
        return node

    def lookup(self, token: Any) -> str | None:
        """Builder id for a base address or a literal AWS id, if we created one."""
        if isinstance(token, str):
            return self.ids.get(token) or self.actual.get(token)
        return None

    def one(self, res: dict, attr: str, *path: Any, values: dict | None = None) -> str | None:
        """A single referenced resource: through the configuration references, else a literal id."""
        expr = self.expr(res, *path, attr) if path else self.expr(res, attr)
        for target in self._targets(res, expr):
            if self.lookup(target):
                return self.lookup(target)
        literal = (values if values is not None else res.get("values") or {}).get(attr)
        return self.lookup(literal)

    def many(self, res: dict, attr: str, *path: Any, values: dict | None = None) -> list[str]:
        expr = self.expr(res, *path, attr) if path else self.expr(res, attr)
        out = [self.lookup(t) for t in self._targets(res, expr)]
        literal = (values if values is not None else res.get("values") or {}).get(attr) or []
        out += [self.lookup(v) for v in literal if isinstance(v, str)]
        return [o for o in dict.fromkeys(out) if o]


def _name(res: dict, values: dict) -> str:
    return (
        tag_name(values.get("tags") or values.get("tags_all"))
        or clean_text(values.get("name"))
        or res.get("name", "")
    )


def _key(res: dict) -> str:
    return (res.get("values") or {}).get("id") or res["address"]


def _register(ctx: _Context, res: dict, builder_id: str | None) -> None:
    if not builder_id:
        return
    ctx.ids.setdefault(_base(res["address"]), builder_id)
    actual = (res.get("values") or {}).get("id")
    if isinstance(actual, str) and actual:
        ctx.actual[actual] = builder_id


def _of_type(ctx: _Context, *types: str) -> list[dict]:
    return [r for r in ctx.resources if r.get("type") in types]


def import_terraform(document: Any, *, name: str = "") -> ImportReport:
    if not isinstance(document, dict):
        raise ImporterError("Expected the JSON object produced by `terraform show -json`.")
    ctx = _Context(document)
    region = _region(ctx)
    b = ConfigBuilder(name or "Terraform import", region, source="terraform")

    for res in _of_type(ctx, "aws_vpc"):
        v = res.get("values") or {}
        _register(ctx, res, b.add_vpc(_key(res), v.get("cidr_block"), _name(res, v)))

    for res in _of_type(ctx, "aws_internet_gateway"):
        _register(ctx, res, b.add_internet_gateway(_key(res), ctx.one(res, "vpc_id")))

    main_tables: list[tuple[str, str]] = []
    for res in _of_type(ctx, "aws_route_table"):
        v = res.get("values") or {}
        table = b.add_route_table(_key(res), ctx.one(res, "vpc_id"), _name(res, v))
        _register(ctx, res, table)
        for i, route in enumerate(v.get("route") or []):
            _add_tf_route(ctx, b, res, table, route if isinstance(route, dict) else {}, ("route", i))
    for res in _of_type(ctx, "aws_route"):
        v = res.get("values") or {}
        _add_tf_route(ctx, b, res, ctx.one(res, "route_table_id"), v, ())
    for res in _of_type(ctx, "aws_default_route_table"):
        b.warn(
            "DEFAULT_ROUTE_TABLE",
            f"{res['address']}: aws_default_route_table is not imported; use aws_route_table.",
        )
    for res in _of_type(ctx, "aws_main_route_table_association"):
        vpc, table = ctx.one(res, "vpc_id"), ctx.one(res, "route_table_id")
        if vpc and table:
            main_tables.append((vpc, table))
    for vpc, table in main_tables:
        b.main_route_table[vpc] = table

    launch_public: dict[str, bool] = {}
    for res in _of_type(ctx, "aws_subnet"):
        v = res.get("values") or {}
        sid = b.add_subnet(
            _key(res),
            ctx.one(res, "vpc_id"),
            v.get("cidr_block"),
            zone=v.get("availability_zone") or "",
            name=_name(res, v),
        )
        _register(ctx, res, sid)
        if sid:
            launch_public[sid] = bool(v.get("map_public_ip_on_launch"))
    for res in _of_type(ctx, "aws_route_table_association"):
        subnet, table = ctx.one(res, "subnet_id"), ctx.one(res, "route_table_id")
        if subnet in b.subnets and table in b.route_tables:
            b.subnets[subnet]["route_table_id"] = table

    for res in _of_type(ctx, "aws_security_group"):
        v = res.get("values") or {}
        gid = b.add_security_group(
            _key(res),
            ctx.one(res, "vpc_id"),
            _name(res, v) or clean_text(v.get("name_prefix")),
            v.get("description") or "",
            default_egress=False,
        )
        _register(ctx, res, gid)
    for res in _of_type(ctx, "aws_security_group"):
        gid = ctx.ids.get(_base(res["address"]))
        if gid not in b.security_groups:
            continue
        for direction in ("ingress", "egress"):
            for i, block in enumerate((res.get("values") or {}).get(direction) or []):
                for rule in _tf_block_rules(ctx, b, res, gid, direction, block, i):
                    b.security_groups[gid][direction].append(rule)
    for res in _of_type(ctx, "aws_security_group_rule"):
        v = res.get("values") or {}
        gid = ctx.one(res, "security_group_id")
        direction = v.get("type")
        if gid in b.security_groups and direction in ("ingress", "egress"):
            peer = ctx.one(res, "source_security_group_id") or (gid if v.get("self") else None)
            rule = b.rule(
                v.get("protocol"),
                v.get("from_port"),
                v.get("to_port"),
                cidr=(v.get("cidr_blocks") or v.get("ipv6_cidr_blocks") or [None])[0] if not peer else None,
                peer=peer,
                description=v.get("description") or "",
                direction=direction,
                where=res["address"],
            )
            _extra_cidrs(b, v, rule, gid, direction, res["address"], peer)
            if rule:
                b.security_groups[gid][direction].append(rule)
    for res in _of_type(ctx, "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"):
        v = res.get("values") or {}
        gid = ctx.one(res, "security_group_id")
        direction = "ingress" if "ingress" in res["type"] else "egress"
        if gid in b.security_groups:
            rule = b.rule(
                v.get("ip_protocol"),
                v.get("from_port"),
                v.get("to_port"),
                cidr=v.get("cidr_ipv4") or v.get("cidr_ipv6"),
                peer=ctx.one(res, "referenced_security_group_id"),
                description=v.get("description") or "",
                direction=direction,
                where=res["address"],
            )
            if rule:
                b.security_groups[gid][direction].append(rule)

    for res in _of_type(ctx, "aws_network_acl"):
        v = res.get("values") or {}
        acl = b.add_network_acl(_key(res), ctx.one(res, "vpc_id"), _name(res, v))
        _register(ctx, res, acl)
        if not acl:
            continue
        b.network_acls[acl]["subnet_ids"].extend(ctx.many(res, "subnet_ids"))
        for direction in ("ingress", "egress"):
            for entry in v.get(direction) or []:
                if isinstance(entry, dict):
                    b.add_nacl_entry(
                        acl,
                        egress=direction == "egress",
                        number=entry.get("rule_no"),
                        action=entry.get("action", ""),
                        protocol=entry.get("protocol"),
                        cidr=entry.get("cidr_block") or entry.get("ipv6_cidr_block"),
                        from_port=entry.get("from_port"),
                        to_port=entry.get("to_port"),
                    )
    for res in _of_type(ctx, "aws_network_acl_rule"):
        v = res.get("values") or {}
        b.add_nacl_entry(
            ctx.one(res, "network_acl_id"),
            egress=bool(v.get("egress")),
            number=v.get("rule_number"),
            action=v.get("rule_action", ""),
            protocol=v.get("protocol"),
            cidr=v.get("cidr_block") or v.get("ipv6_cidr_block"),
            from_port=v.get("from_port"),
            to_port=v.get("to_port"),
        )
    for res in _of_type(ctx, "aws_network_acl_association"):
        acl, subnet = ctx.one(res, "network_acl_id"), ctx.one(res, "subnet_id")
        if acl in b.network_acls and subnet and subnet not in b.network_acls[acl]["subnet_ids"]:
            b.network_acls[acl]["subnet_ids"].append(subnet)

    for res in _of_type(ctx, "aws_instance"):
        v = res.get("values") or {}
        subnet = ctx.one(res, "subnet_id")
        public: Any = v.get("associate_public_ip_address")
        if isinstance(v.get("public_ip"), str) and v["public_ip"]:
            public = v["public_ip"]
        elif public is None:
            public = launch_public.get(subnet or "", False)
        _register(
            ctx,
            res,
            b.add_instance(
                _key(res),
                subnet,
                ctx.many(res, "vpc_security_group_ids"),
                name=_name(res, v),
                private_ip=v.get("private_ip") if isinstance(v.get("private_ip"), str) else None,
                public_ip=public,
                tags=tag_map(v.get("tags")),
            ),
        )

    _terraform_extensions(ctx, b)
    if any(r.get("type", "").startswith("aws_iam_") for r in ctx.resources):
        b.warn(
            "IAM_NOT_IMPORTED",
            "IAM roles and policies are not imported from Terraform; IAM attack paths are not built.",
        )
    return b.build()


def _region(ctx: _Context) -> str:
    providers = (ctx.document.get("configuration") or {}).get("provider_config") or {}
    for provider in providers.values():
        if isinstance(provider, dict) and provider.get("name") == "aws":
            value = ((provider.get("expressions") or {}).get("region") or {}).get("constant_value")
            if isinstance(value, str) and REGION_PATTERN.match(value):
                return value
    for res in ctx.resources:
        zone = (res.get("values") or {}).get("availability_zone")
        if isinstance(zone, str) and REGION_PATTERN.match(zone[:-1]):
            return zone[:-1]
    return "us-east-1"


def _add_tf_route(ctx, b, res, table, route, path):
    destination = route.get("cidr_block") or route.get("destination_cidr_block")
    if route.get("ipv6_cidr_block") or route.get("destination_ipv6_cidr_block"):
        b.warn("IPV6_SKIPPED", f"{res['address']}: IPv6 routes are not modelled and were skipped.")
    if not destination or table not in b.route_tables:
        return
    gateway = ctx.one(res, "gateway_id", *path, values=route)
    literal = route.get("gateway_id")
    if gateway in b.internet_gateways:
        b.add_route(table, destination, "igw", gateway)
    elif literal == "local":
        b.add_route(table, destination, "local", None)
    else:
        for field_name, kind in _UNSUPPORTED_GATEWAYS:
            if route.get(field_name) or ctx.expr(res, *path, field_name):
                b.add_route(table, destination, kind, None)
                return
        if isinstance(literal, str) and literal.startswith("igw-"):
            b.add_route(table, destination, "igw", ctx.lookup(literal))
        elif gateway or literal:
            b.add_route(table, destination, "vgw", None)


def _tf_block_rules(ctx, b, res, gid, direction, block, index):
    if not isinstance(block, dict):
        return []
    where = f"{res['address']} {direction}[{index}]"
    out = []
    peers = ctx.many(res, "security_groups", direction, index, values=block)
    if block.get("self"):
        peers.append(gid)
    for peer in dict.fromkeys(peers):
        rule = b.rule(
            block.get("protocol"),
            block.get("from_port"),
            block.get("to_port"),
            peer=peer,
            description=block.get("description") or "",
            direction=direction,
            where=where,
        )
        if rule:
            out.append(rule)
    for cidr in (block.get("cidr_blocks") or []) + (block.get("ipv6_cidr_blocks") or []):
        rule = b.rule(
            block.get("protocol"),
            block.get("from_port"),
            block.get("to_port"),
            cidr=cidr,
            description=block.get("description") or "",
            direction=direction,
            where=where,
        )
        if rule:
            out.append(rule)
    if block.get("prefix_list_ids"):
        b.warn("PREFIX_LIST_SKIPPED", f"{where}: prefix-list sources are not modelled and were skipped.")
    if not out and not peers and not (block.get("cidr_blocks") or block.get("ipv6_cidr_blocks")):
        b.warn(
            "RULE_SOURCE_UNKNOWN", f"{where}: the source is only known at apply time; the rule was skipped."
        )
    return out


def _extra_cidrs(b, values, first_rule, gid, direction, where, peer):
    """aws_security_group_rule may list several CIDRs; the first became ``first_rule``."""
    if peer:
        return
    cidrs = (values.get("cidr_blocks") or []) + (values.get("ipv6_cidr_blocks") or [])
    for cidr in cidrs[1:]:
        rule = b.rule(
            values.get("protocol"),
            values.get("from_port"),
            values.get("to_port"),
            cidr=cidr,
            description=values.get("description") or "",
            direction=direction,
            where=where,
        )
        if rule:
            b.security_groups[gid][direction].append(rule)


def _engine(value: Any) -> str | None:
    text = str(value or "").lower()
    return next((mapped for prefix, mapped in _ENGINES if text.startswith(prefix)), None)


def _terraform_extensions(ctx: _Context, b: ConfigBuilder) -> None:
    groups: dict[str, list[str]] = {}
    for res in _of_type(ctx, "aws_db_subnet_group"):
        groups[_base(res["address"])] = ctx.many(res, "subnet_ids")

    for res in _of_type(ctx, "aws_db_instance"):
        v = res.get("values") or {}
        engine = _engine(v.get("engine"))
        subnets: list[str] = []
        for target in ctx._targets(res, ctx.expr(res, "db_subnet_group_name")):
            subnets = groups.get(target, [])
        sgs = [g for g in ctx.many(res, "vpc_security_group_ids") if g in b.security_groups]
        subnets = [s for s in subnets if s in b.subnets]
        if not (engine and subnets and sgs):
            b.warn(
                "DATABASE_SKIPPED",
                f"{res['address']}: needs a supported engine, subnet group and security groups; skipped.",
            )
            continue
        did = b.make_id(_key(res))
        _register(ctx, res, did)
        b.add_extension(
            "databases",
            {
                "id": did,
                "name": clean_text(v.get("identifier") or res.get("name")),
                "engine": engine,
                "subnet_ids": subnets,
                "security_group_ids": sgs,
                "publicly_accessible": bool(v.get("publicly_accessible")),
                "sensitive": True,
                "encrypted": bool(v.get("storage_encrypted")),
            },
        )

    listeners: dict[str, list[int]] = {}
    for res in _of_type(ctx, "aws_lb_listener", "aws_alb_listener"):
        lb = ctx.expr(res, "load_balancer_arn")
        port = (res.get("values") or {}).get("port")
        for target in ctx._targets(res, lb):
            if isinstance(port, int):
                listeners.setdefault(target, []).append(port)
    for res in _of_type(ctx, "aws_lb", "aws_alb"):
        v = res.get("values") or {}
        subnets = [s for s in ctx.many(res, "subnets") if s in b.subnets]
        sgs = [g for g in ctx.many(res, "security_groups") if g in b.security_groups]
        ports = sorted(set(listeners.get(_base(res["address"]), [])))
        if v.get("load_balancer_type") in ("network", "gateway") or not (subnets and sgs and ports):
            b.warn(
                "LB_SKIPPED",
                f"{res['address']}: only application load balancers with listeners are imported.",
            )
            continue
        lid = b.make_id(_key(res))
        _register(ctx, res, lid)
        b.add_extension(
            "load_balancers",
            {
                "id": lid,
                "name": clean_text(v.get("name") or res.get("name")),
                "scheme": "internal" if v.get("internal") else "internet-facing",
                "subnet_ids": subnets,
                "security_group_ids": sgs,
                "listener_ports": ports[:20],
            },
        )

    public_acls: set[str] = set()
    for res in _of_type(ctx, "aws_s3_bucket_acl"):
        if (res.get("values") or {}).get("acl") in ("public-read", "public-read-write"):
            public_acls.update(ctx._targets(res, ctx.expr(res, "bucket")))
    for res in _of_type(ctx, "aws_s3_bucket"):
        v = res.get("values") or {}
        public = v.get("acl") in ("public-read", "public-read-write") or _base(res["address"]) in public_acls
        sid = b.make_id(_key(res))
        _register(ctx, res, sid)
        b.add_extension(
            "buckets",
            {
                "id": sid,
                "name": clean_text(v.get("bucket") or res.get("name")),
                "public": public,
                "sensitive": False,
                "encrypted": False,
            },
        )
