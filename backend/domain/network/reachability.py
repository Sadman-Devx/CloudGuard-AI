"""Deterministic reachability over the supported network subset.

Pure Python (no Django). Given a validated ``NetworkConfig`` and a question ("can X reach Y on
tcp/5432?") this returns ``allowed``, ``blocked`` or ``unknown`` plus an ordered trace of every
check that was made. An LLM never takes part in this decision.

What is modelled (see ``docs/supported-network-semantics.md`` for the user-facing version)
-----------------------------------------------------------------------------------------
* **Internet -> instance**: the instance needs a public IP, its subnet needs a route that sends
  traffic back through an internet gateway, the subnet's network ACL must allow the request in and
  the reply out (ACLs are *stateless*), and a security-group ingress rule must allow the source.
* **Instance -> instance (same VPC)**: source security-group egress, destination security-group
  ingress, local routes in both directions, and network ACLs in all four places a packet or its
  reply crosses a subnet boundary. Traffic inside one subnet never crosses an ACL, so ACL checks
  are skipped then (as in AWS).
* Security groups are **stateful** (a reply is implicitly allowed). Network ACLs are **stateless**
  and **ordered**: the lowest rule number that matches decides, and the implicit last rule denies.

Everything else is reported as ``unknown`` instead of being guessed: ICMP, and traffic between
different VPCs (peering and transit gateways are not supported by the importer).

Two modelling decisions worth knowing
-------------------------------------
* **The anonymous internet client** (no ``source_ip``) matches only ``0.0.0.0/0`` rules. A rule
  for a narrower CIDR (an office range) does not cover an arbitrary client, which is exactly why
  "SSH open to 0.0.0.0/0" and "SSH open to the office" are different findings. Pass ``source_ip``
  to ask about one specific public address instead.
* **A subnet with no network ACL** in the snapshot is evaluated as AWS's *default* ACL, which
  allows everything. The assumption is recorded on the result (``assumptions``) so it is never
  silent. A configured ACL is always evaluated exactly.

Reason codes are collected from *every* failing check, not only the first, so a result can say
both "no public IP" and "no public route" at once.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from domain.network.rules import SENSITIVE_PORTS, WORLD_CIDR
from domain.network.schema import (
    NON_PUBLIC_RANGES,
    NaclRule,
    NetworkConfig,
    RouteTable,
    SecurityGroup,
)

REACHABILITY_VERSION = "1.0"
CONFIDENCE_TYPE = "deterministic_supported_subset"

INTERNET = "internet"

# Verdicts
ALLOWED = "allowed"
BLOCKED = "blocked"
UNKNOWN = "unknown"

# Step statuses
PASS = "pass"
FAIL = "fail"
UNKNOWN_STEP = "unknown"
NOT_APPLICABLE = "not_applicable"

QUERY_PROTOCOLS = ("tcp", "udp", "icmp")
MODELLED_PROTOCOLS = ("tcp", "udp")

# Replies come back to an ephemeral client port. Clients differ (Linux 32768-60999, Windows
# 49152-65535, NAT gateways 1024-65535), so a stateless ACL has to allow the whole range to be
# safe. A rule set that allows only part of it yields ``unknown`` (NACL_REPLY_PARTIAL).
EPHEMERAL_PORTS = (1024, 65535)

SG_RISK_OVERLY_BROAD = "OVERLY_BROAD_INGRESS"
_SENSITIVE_PORT_NUMBERS = frozenset(port for port, _ in SENSITIVE_PORTS.values())

Interval = tuple[int, int]


class QueryError(ValueError):
    """The question itself is malformed or refers to resources that do not exist."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PathQuery:
    source: str  # "internet" or an instance id
    destination: str  # an instance id
    protocol: str
    port: int | None
    source_ip: str | None = None  # only meaningful for source == "internet"

    @property
    def key(self) -> str:
        who = self.source if self.source_ip is None else f"{self.source}@{self.source_ip}"
        where = self.protocol if self.port is None else f"{self.protocol}/{self.port}"
        return f"{who}>{self.destination}:{where}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "protocol": self.protocol,
            "port": self.port,
        }


@dataclass(frozen=True)
class Step:
    check: str
    status: str
    code: str
    detail: str
    resources: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "status": self.status,
            "code": self.code,
            "detail": self.detail,
            "resources": list(self.resources),
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class PathResult:
    query: PathQuery
    result: str
    reason_codes: tuple[str, ...]
    steps: tuple[Step, ...]
    assumptions: tuple[str, ...]
    security_group_risk: str | None
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.query.key,
            **self.query.as_dict(),
            "result": self.result,
            "reason_codes": list(self.reason_codes),
            "security_group_risk": self.security_group_risk,
            "confidence_type": CONFIDENCE_TYPE,
            "assumptions": list(self.assumptions),
            "explanation": self.explanation,
            "trace": [s.as_dict() for s in self.steps],
        }


# --------------------------------------------------------------------------
# Address, route and rule matching helpers
# --------------------------------------------------------------------------


@lru_cache(maxsize=1024)
def _network(cidr: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(cidr, strict=False)


def _cidr_has(cidr: str, ip: ipaddress.IPv4Address | None) -> bool:
    """Does ``cidr`` cover ``ip``? ``None`` is the anonymous client: only 0.0.0.0/0 covers it."""
    network = _network(cidr)
    if ip is None:
        return network.prefixlen == 0
    return ip in network


def _port_text(protocol: str, port: int | None) -> str:
    return protocol if port is None else f"{protocol}/{port}"


def _lookup_route(table: RouteTable | None, ip: ipaddress.IPv4Address | None) -> str | None:
    """Longest-prefix match. Returns the target (``local`` or an internet gateway id), or None."""
    if table is None:
        return None
    best: tuple[int, str] | None = None
    for route in table.routes:
        network = _network(route.destination_cidr)
        covers = network.prefixlen == 0 if ip is None else ip in network
        if covers and (best is None or network.prefixlen > best[0]):
            best = (network.prefixlen, route.target)
    return best[1] if best else None


def _rule_covers_port(
    protocol: str, from_port: int | None, to_port: int | None, query_protocol: str, port: int
) -> bool:
    if protocol == "-1":
        return True
    if protocol != query_protocol or from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _is_broad(rule_cidr: str | None, protocol: str, from_port: int | None, to_port: int | None) -> bool:
    """A world-open rule that is all-traffic or covers a sensitive port."""
    if rule_cidr != WORLD_CIDR:
        return False
    if protocol == "-1":
        return True
    if from_port is None or to_port is None:
        return False
    if from_port <= 1 and to_port >= 65535:
        return True
    return any(from_port <= p <= to_port for p in _SENSITIVE_PORT_NUMBERS)


def _sg_matches(
    groups: list[SecurityGroup],
    direction: str,
    protocol: str,
    port: int,
    peer_ip: ipaddress.IPv4Address | None,
    peer_group_ids: frozenset[str],
) -> list[dict[str, Any]]:
    """Every rule, across ``groups``, that allows this traffic to/from the peer (evidence)."""
    matches: list[dict[str, Any]] = []
    for sg in groups:
        rules = sg.ingress if direction == "ingress" else sg.egress
        for index, rule in enumerate(rules):
            if not _rule_covers_port(rule.protocol, rule.from_port, rule.to_port, protocol, port):
                continue
            if rule.cidr is not None:
                peer_ok = _cidr_has(rule.cidr, peer_ip)
            else:
                peer_ok = rule.peer_security_group_id in peer_group_ids
            if not peer_ok:
                continue
            matches.append(
                {
                    "security_group": sg.id,
                    "direction": direction,
                    "index": index,
                    "protocol": rule.protocol,
                    "from_port": rule.from_port,
                    "to_port": rule.to_port,
                    "cidr": rule.cidr,
                    "peer_security_group_id": rule.peer_security_group_id,
                    "broad": _is_broad(rule.cidr, rule.protocol, rule.from_port, rule.to_port),
                }
            )
    return matches


# ---- ordered, stateless network ACL evaluation over a port interval ---------------------


def _subtract(intervals: list[Interval], low: int, high: int) -> list[Interval]:
    out: list[Interval] = []
    for a, b in intervals:
        if b < low or a > high:
            out.append((a, b))
            continue
        if a < low:
            out.append((a, low - 1))
        if b > high:
            out.append((high + 1, b))
    return out


def _intersect(intervals: list[Interval], low: int, high: int) -> list[Interval]:
    return [(max(a, low), min(b, high)) for a, b in intervals if max(a, low) <= min(b, high)]


def _acl_decide(
    rules: tuple[NaclRule, ...],
    protocol: str,
    ip: ipaddress.IPv4Address | None,
    low: int,
    high: int,
) -> tuple[str, list[dict[str, Any]]]:
    """Evaluate ordered ACL rules for ``protocol`` ports ``low..high`` and a peer address.

    Returns ``("allow" | "deny" | "partial", matched_rules)``. ``partial`` only happens for a port
    *range* (the stateless reply path): some ports are allowed and some are not.
    """
    remaining: list[Interval] = [(low, high)]
    allowed: list[Interval] = []
    denied: list[Interval] = []
    matched: list[dict[str, Any]] = []

    for rule in sorted(rules, key=lambda r: r.rule_number):
        if not remaining:
            break
        if rule.protocol not in ("-1", protocol) or not _cidr_has(rule.cidr, ip):
            continue
        rule_low, rule_high = (
            (0, 65535)
            if rule.protocol == "-1" or rule.from_port is None or rule.to_port is None
            else (rule.from_port, rule.to_port)
        )
        hit = _intersect(remaining, rule_low, rule_high)
        if not hit:
            continue
        (allowed if rule.action == "allow" else denied).extend(hit)
        remaining = _subtract(remaining, rule_low, rule_high)
        matched.append(
            {
                "rule_number": rule.rule_number,
                "action": rule.action,
                "protocol": rule.protocol,
                "cidr": rule.cidr,
                "from_port": rule.from_port,
                "to_port": rule.to_port,
                "applies_to_ports": [list(i) for i in hit],
            }
        )

    if remaining:  # the implicit final rule ("*") denies everything unmatched
        denied.extend(remaining)
        matched.append(
            {
                "rule_number": "*",
                "action": "deny",
                "protocol": "-1",
                "cidr": WORLD_CIDR,
                "from_port": None,
                "to_port": None,
                "applies_to_ports": [list(i) for i in remaining],
            }
        )

    if allowed and not denied:
        return "allow", matched
    if not allowed:
        return "deny", matched
    return "partial", matched


# --------------------------------------------------------------------------
# Query validation
# --------------------------------------------------------------------------

_QUERY_FIELDS = {"source", "destination", "protocol", "port", "source_ip"}


def validate_query(raw: Any, config: NetworkConfig, *, label: str = "") -> PathQuery:
    """Turn untrusted input into a ``PathQuery`` or raise ``QueryError`` listing every problem."""
    prefix = f"{label}: " if label else ""
    if not isinstance(raw, dict):
        raise QueryError([f"{prefix}a path must be an object."])
    errors: list[str] = []

    for name in sorted(set(raw) - _QUERY_FIELDS):
        errors.append(f"{prefix}unknown field '{name}'.")

    instance_ids = {i.id for i in config.instances}
    # Untrusted values may be lists/objects; only strings can be ids (and only hashables can be
    # looked up in a set).
    source = raw.get("source") if isinstance(raw.get("source"), str) else None
    destination = raw.get("destination") if isinstance(raw.get("destination"), str) else None
    if source != INTERNET and source not in instance_ids:
        errors.append(f"{prefix}source must be 'internet' or the id of an instance in this snapshot.")
    if destination == INTERNET:
        errors.append(f"{prefix}destination must be an instance; internet-bound paths are not modelled.")
    elif destination not in instance_ids:
        errors.append(f"{prefix}destination must be the id of an instance in this snapshot.")
    if source == destination and source in instance_ids:
        errors.append(f"{prefix}source and destination must be different instances.")

    protocol = raw.get("protocol")
    if protocol not in QUERY_PROTOCOLS:
        errors.append(f"{prefix}protocol must be one of {', '.join(QUERY_PROTOCOLS)}.")
    port = raw.get("port")
    if protocol in MODELLED_PROTOCOLS:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            errors.append(f"{prefix}port must be an integer in 0-65535 for {protocol}.")
    else:
        port = None  # icmp has no port here; an invalid protocol is already reported

    source_ip = raw.get("source_ip")
    if source_ip is not None:
        if source != INTERNET:
            errors.append(f"{prefix}source_ip is only valid when the source is 'internet'.")
            source_ip = None
        else:
            try:
                address = ipaddress.ip_address(source_ip) if isinstance(source_ip, str) else None
            except ValueError:
                address = None
            if not isinstance(address, ipaddress.IPv4Address):
                errors.append(f"{prefix}source_ip must be an IPv4 address.")
                source_ip = None
            elif any(address in net for net in NON_PUBLIC_RANGES) or any(
                address in _network(v.cidr) for v in config.vpcs
            ):
                errors.append(f"{prefix}source_ip must be a public internet address, not {address}.")
                source_ip = None
            else:
                source_ip = str(address)

    if errors:
        raise QueryError(errors)
    return PathQuery(source, destination, protocol, port, source_ip)


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


def _step(
    check: str,
    status: str,
    code: str,
    detail: str,
    resources: tuple[str, ...] = (),
    **evidence: Any,
) -> Step:
    return Step(check, status, code, detail, resources, evidence)


class Reachability:
    """Evaluates paths against one configuration. Build once, ask many questions."""

    def __init__(self, config: NetworkConfig):
        self.config = config
        self.instances = {i.id: i for i in config.instances}
        self.subnets = {s.id: s for s in config.subnets}
        self.tables = {t.id: t for t in config.route_tables}
        self.groups = {g.id: g for g in config.security_groups}
        self.acl_by_subnet = {sid: acl for acl in config.network_acls for sid in acl.subnet_ids}

    # ---- public API ----------------------------------------------------------------------

    def evaluate(self, query: PathQuery) -> PathResult:
        if query.protocol not in MODELLED_PROTOCOLS:
            steps = [
                _step(
                    "protocol",
                    UNKNOWN_STEP,
                    "UNSUPPORTED_PROTOCOL",
                    f"{query.protocol} reachability is not modelled; only tcp and udp are evaluated.",
                )
            ]
            return self._result(query, steps, [], None)

        destination = self.instances[query.destination]
        if query.source == INTERNET:
            return self._from_internet(query, destination)
        return self._between_instances(query, self.instances[query.source], destination)

    # ---- internet -> instance --------------------------------------------------------------

    def _from_internet(self, query: PathQuery, dst) -> PathResult:
        client = ipaddress.IPv4Address(query.source_ip) if query.source_ip else None
        client_label = query.source_ip or "an anonymous internet client"
        port = query.port
        assert port is not None
        subnet = self.subnets[dst.subnet_id]
        groups = [self.groups[g] for g in dst.security_group_ids]
        steps: list[Step] = []
        assumptions: list[str] = []

        if dst.public_ip:
            steps.append(
                _step(
                    "public_ip", PASS, "HAS_PUBLIC_IP", f"{dst.id} has public IP {dst.public_ip}.", (dst.id,)
                )
            )
        else:
            steps.append(
                _step(
                    "public_ip",
                    FAIL,
                    "NO_PUBLIC_IP",
                    f"{dst.id} has no public IP, so the internet has no address to send traffic to.",
                    (dst.id,),
                )
            )

        table = self.tables.get(subnet.route_table_id)
        target = _lookup_route(table, client)
        if target is not None and target != "local":
            steps.append(
                _step(
                    "route_to_internet",
                    PASS,
                    "HAS_PUBLIC_ROUTE",
                    f"Subnet {subnet.id} routes {client_label} via internet gateway {target}.",
                    (subnet.id, subnet.route_table_id, target),
                )
            )
        else:
            steps.append(
                _step(
                    "route_to_internet",
                    FAIL,
                    "NO_PUBLIC_ROUTE",
                    f"Route table {subnet.route_table_id} of subnet {subnet.id} has no route to an internet "
                    f"gateway for {client_label}, so replies cannot return.",
                    (subnet.id, subnet.route_table_id),
                    matched_target=target,
                )
            )

        steps.extend(self._acl_steps(subnet.id, "in", client, query.protocol, port, "request", assumptions))
        steps.extend(self._acl_steps(subnet.id, "out", client, query.protocol, None, "reply", assumptions))

        matches = _sg_matches(groups, "ingress", query.protocol, port, client, frozenset())
        steps.append(
            self._sg_step("sg_ingress", "SG_INGRESS", matches, dst.id, client_label, query, "ingress")
        )
        return self._result(query, steps, assumptions, matches)

    # ---- instance -> instance --------------------------------------------------------------

    def _between_instances(self, query: PathQuery, src, dst) -> PathResult:
        port = query.port
        assert port is not None
        src_subnet, dst_subnet = self.subnets[src.subnet_id], self.subnets[dst.subnet_id]

        if src_subnet.vpc_id != dst_subnet.vpc_id:
            step = _step(
                "vpc_boundary",
                UNKNOWN_STEP,
                "UNSUPPORTED_CROSS_VPC",
                f"{src.id} and {dst.id} are in different VPCs. Peering and transit gateways are not "
                "supported, so this path is not evaluated.",
                (src.id, dst.id),
            )
            return self._result(query, [step], [], None)

        src_ip = ipaddress.IPv4Address(src.private_ip)
        dst_ip = ipaddress.IPv4Address(dst.private_ip)
        src_groups = [self.groups[g] for g in src.security_group_ids]
        dst_groups = [self.groups[g] for g in dst.security_group_ids]
        same_subnet = src_subnet.id == dst_subnet.id
        steps: list[Step] = []
        assumptions: list[str] = []

        # 1. source security-group egress
        egress = _sg_matches(
            src_groups, "egress", query.protocol, port, dst_ip, frozenset(dst.security_group_ids)
        )
        steps.append(self._sg_step("sg_egress", "SG_EGRESS", egress, src.id, dst.id, query, "egress"))

        if same_subnet:
            for check in (
                "nacl_egress",
                "route_forward",
                "nacl_ingress",
                "nacl_reply_egress",
                "route_return",
            ):
                steps.append(
                    _step(
                        check,
                        NOT_APPLICABLE,
                        "SAME_SUBNET",
                        f"{src.id} and {dst.id} share subnet {src_subnet.id}; the traffic never crosses a "
                        "network ACL or needs a routed hop.",
                        (src_subnet.id,),
                    )
                )
            steps.append(
                _step("nacl_reply_ingress", NOT_APPLICABLE, "SAME_SUBNET", "Same subnet; no ACL applies.")
            )
        else:
            # 2. packet leaves the source subnet
            steps.extend(
                self._acl_steps(src_subnet.id, "out", dst_ip, query.protocol, port, "request", assumptions)
            )
            steps.append(self._local_route_step("route_forward", src_subnet, dst_ip, src.id, dst.id))
            # 3. packet enters the destination subnet
            steps.extend(
                self._acl_steps(dst_subnet.id, "in", src_ip, query.protocol, port, "request", assumptions)
            )

        # 4. destination security-group ingress (stateful: the reply needs no further SG check)
        ingress = _sg_matches(
            dst_groups, "ingress", query.protocol, port, src_ip, frozenset(src.security_group_ids)
        )
        steps.append(self._sg_step("sg_ingress", "SG_INGRESS", ingress, dst.id, src.id, query, "ingress"))

        if not same_subnet:
            # 5. the stateless reply travels back
            steps.extend(
                self._acl_steps(dst_subnet.id, "out", src_ip, query.protocol, None, "reply", assumptions)
            )
            steps.append(self._local_route_step("route_return", dst_subnet, src_ip, dst.id, src.id))
            steps.extend(
                self._acl_steps(src_subnet.id, "in", dst_ip, query.protocol, None, "reply", assumptions)
            )
        return self._result(query, steps, assumptions, ingress)

    # ---- shared step builders --------------------------------------------------------------

    def _sg_step(
        self,
        check: str,
        code_prefix: str,
        matches: list[dict[str, Any]],
        owner: str,
        peer: str,
        query,
        direction: str,
    ) -> Step:
        what = _port_text(query.protocol, query.port)
        if matches:
            ids = tuple(sorted({m["security_group"] for m in matches}))
            return _step(
                check,
                PASS,
                f"{code_prefix}_ALLOWED",
                f"{', '.join(ids)} allows {what} {direction} for {owner} ({peer}).",
                ids,
                matching_rules=matches,
            )
        return _step(
            check,
            FAIL,
            f"{code_prefix}_DENIED",
            f"No {direction} rule on {owner}'s security groups allows {what} ({peer}); security groups deny "
            "by default.",
            (owner,),
            matching_rules=[],
        )

    def _local_route_step(self, check: str, subnet, target_ip, owner: str, peer: str) -> Step:
        table = self.tables.get(subnet.route_table_id)
        target = _lookup_route(table, target_ip)
        if target == "local":
            return _step(
                check,
                PASS,
                "HAS_LOCAL_ROUTE",
                f"{subnet.route_table_id} delivers {target_ip} locally.",
                (subnet.id, subnet.route_table_id),
            )
        return _step(
            check,
            FAIL,
            "NO_LOCAL_ROUTE",
            f"{subnet.route_table_id} (subnet {subnet.id}) has no local route to {target_ip}"
            + (f"; the best match is {target}." if target else "."),
            (subnet.id, subnet.route_table_id),
            matched_target=target,
        )

    def _acl_steps(
        self,
        subnet_id: str,
        direction: str,  # "in" | "out": which side of the subnet boundary the packet crosses
        peer_ip: ipaddress.IPv4Address | None,
        protocol: str,
        port: int | None,  # None -> the ephemeral reply range
        phase: str,  # "request" | "reply"
        assumptions: list[str],
    ) -> list[Step]:
        """One ACL check. Names: nacl_ingress/nacl_egress for the request, nacl_reply_* for replies."""
        side = "ingress" if direction == "in" else "egress"
        check = f"nacl_{side}" if phase == "request" else f"nacl_reply_{side}"
        deny_code = (
            f"NACL_{side.upper()}_DENIED" if phase == "request" else f"NACL_REPLY_{side.upper()}_DENIED"
        )
        acl = self.acl_by_subnet.get(subnet_id)

        if acl is None:
            code = "DEFAULT_NACL_ASSUMED"
            note = f"{subnet_id}:{code}"
            if note not in assumptions:
                assumptions.append(note)
            return [
                _step(
                    check,
                    PASS,
                    code,
                    f"Subnet {subnet_id} has no network ACL in this snapshot; evaluated as the AWS default "
                    "ACL, which allows all traffic.",
                    (subnet_id,),
                    assumed=True,
                )
            ]

        low, high = (port, port) if port is not None else EPHEMERAL_PORTS
        rules = acl.ingress if direction == "in" else acl.egress
        verdict, matched = _acl_decide(rules, protocol, peer_ip, low, high)
        span = f"{protocol}/{low}" if low == high else f"{protocol}/{low}-{high}"
        if verdict == "allow":
            return [
                _step(
                    check,
                    PASS,
                    f"NACL_{side.upper()}_ALLOWED",
                    f"{acl.id} allows {span} {side} on subnet {subnet_id}.",
                    (acl.id, subnet_id),
                    matching_rules=matched,
                )
            ]
        if verdict == "partial":
            return [
                _step(
                    check,
                    UNKNOWN_STEP,
                    "NACL_REPLY_PARTIAL",
                    f"{acl.id} allows only part of the reply port range {span} {side}; whether replies "
                    "arrive depends on the client's ephemeral port.",
                    (acl.id, subnet_id),
                    matching_rules=matched,
                )
            ]
        return [
            _step(
                check,
                FAIL,
                deny_code,
                f"{acl.id} denies {span} {side} on subnet {subnet_id}. Network ACLs are stateless, so the "
                "request and its reply are checked separately.",
                (acl.id, subnet_id),
                matching_rules=matched,
            )
        ]

    # ---- aggregation -----------------------------------------------------------------------

    def _result(
        self,
        query: PathQuery,
        steps: list[Step],
        assumptions: list[str],
        ingress_matches: list[dict[str, Any]] | None,
    ) -> PathResult:
        failed = [s for s in steps if s.status == FAIL]
        unknown = [s for s in steps if s.status == UNKNOWN_STEP]
        if failed:
            verdict, deciding = BLOCKED, failed
        elif unknown:
            verdict, deciding = UNKNOWN, unknown
        else:
            verdict, deciding = ALLOWED, []

        reason_codes: list[str] = []
        for step in deciding:
            if step.code not in reason_codes:
                reason_codes.append(step.code)

        risk = SG_RISK_OVERLY_BROAD if ingress_matches and any(m["broad"] for m in ingress_matches) else None
        label = _port_text(query.protocol, query.port)
        if verdict == ALLOWED:
            explanation = (
                f"Allowed: every modelled check passed for {query.source} -> {query.destination} on {label}."
            )
        else:
            reasons = " ".join(s.detail for s in deciding)
            explanation = f"{verdict.capitalize()}: {reasons}"
        return PathResult(
            query=query,
            result=verdict,
            reason_codes=tuple(reason_codes),
            steps=tuple(steps),
            assumptions=tuple(assumptions),
            security_group_risk=risk,
            explanation=explanation,
        )


def evaluate_path(config: NetworkConfig, query: PathQuery) -> PathResult:
    """Convenience wrapper for a single question."""
    return Reachability(config).evaluate(query)