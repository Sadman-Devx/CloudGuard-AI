"""Deterministic security rule engine (SG-001 .. SG-015).

Pure Python (no Django). Findings come from this code only; an LLM never decides whether
something is risky. Every finding carries the rule id, the affected resource, the exact rule
entries that matched (evidence) and a remediation.

Wording matters: an open security-group rule is a **risky rule** or a **potential exposure**, not
proof of an exploitable vulnerability or of internet reachability. Reachability (routes, NACLs,
return paths) is evaluated separately. Here, "exposure context" only looks at whether the attached
instances have a public IP and sit in a subnet with a route to an internet gateway.

What counts as "open to the world"
----------------------------------
* an exact ``0.0.0.0/0`` (or ``::/0``) source, **or**
* several rules for the same port whose CIDRs *together* cover the whole address space
  (for example ``0.0.0.0/1`` + ``128.0.0.0/1``). Those findings carry ``split_cidr: true`` in the
  evidence of the matching rules.

Rule families
-------------
=========  =====================================================  =====================
Family     Rules                                                  Severity (net/priv/-)
=========  =====================================================  =====================
admin      SG-001 SSH, SG-002 RDP, SG-011 SMB, SG-012 Telnet,     high / medium / low
           SG-013 FTP
remote     SG-014 Docker API (2375)                               critical / high / medium
database   SG-003 PostgreSQL, SG-004 MySQL, SG-007 MSSQL,         high / medium / low
           SG-008 MongoDB, SG-009 Redis, SG-010 Elasticsearch,
           SG-015 Memcached
all ports  SG-005                                                 critical / high / medium
egress     SG-006                                                 low / low / info
=========  =====================================================  =====================

Severity depends on context, not just on the port number: columns are internet-facing candidate,
private / no public path, unattached.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from domain.network.schema import NetworkConfig, SecurityGroup, SecurityGroupRule
from domain.network.topology import build_topology

RULES_VERSION = "1.1"

WORLD_CIDR = "0.0.0.0/0"
WORLD_CIDR_V6 = "::/0"
WORLD_CIDRS = (WORLD_CIDR, WORLD_CIDR_V6)

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

RISKY_RULE = "risky_rule"
POTENTIAL_EXPOSURE = "potential_exposure"

# Exposure context of a security group
EXPOSURE_CANDIDATE = "internet_facing_candidate"
EXPOSURE_NO_PATH = "no_public_path"
EXPOSURE_UNATTACHED = "unattached"

# rule id -> (port, service). The first four keep their original ids.
SENSITIVE_PORTS = {
    "SG-001": (22, "SSH"),
    "SG-002": (3389, "RDP"),
    "SG-003": (5432, "PostgreSQL"),
    "SG-004": (3306, "MySQL"),
    "SG-007": (1433, "Microsoft SQL Server"),
    "SG-008": (27017, "MongoDB"),
    "SG-009": (6379, "Redis"),
    "SG-010": (9200, "Elasticsearch"),
    "SG-011": (445, "SMB"),
    "SG-012": (23, "Telnet"),
    "SG-013": (21, "FTP"),
    "SG-014": (2375, "Docker API (unencrypted)"),
    "SG-015": (11211, "Memcached"),
}

# rule id -> severity family (see the table above)
RULE_FAMILY = {
    "SG-001": "admin",
    "SG-002": "admin",
    "SG-003": "database",
    "SG-004": "database",
    "SG-007": "database",
    "SG-008": "database",
    "SG-009": "database",
    "SG-010": "database",
    "SG-011": "admin",
    "SG-012": "admin",
    "SG-013": "admin",
    "SG-014": "remote",
    "SG-015": "database",
}
ADMIN_RULE_IDS = frozenset(r for r, f in RULE_FAMILY.items() if f in ("admin", "remote"))
DATABASE_RULE_IDS = frozenset(r for r, f in RULE_FAMILY.items() if f == "database")


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    category: str
    description: str
    remediation: str
    limitations: str


_COMMON_LIMITATION = (
    "Only security-group rules and instance attachment are inspected. Route tables, NACLs, host "
    "firewalls and service configuration are not evaluated here, so a finding is not proof that "
    "the service can be reached from the internet."
)

_ADMIN_FIX = (
    "Remove the 0.0.0.0/0 source. Allow the port only from a trusted CIDR (office/VPN) or a bastion "
    "security group, or use AWS Systems Manager Session Manager / a VPN instead."
)
_DB_FIX = (
    "Replace the 0.0.0.0/0 source with the security group of the application tier that needs "
    "access, and keep the service in a private subnet without a public IP."
)


def _port_rule(rule_id: str, remediation: str, category: str) -> RuleInfo:
    port, service = SENSITIVE_PORTS[rule_id]
    return RuleInfo(
        rule_id,
        f"{service} ({port}) open to the internet",
        category,
        f"An ingress rule allows TCP port {port} from 0.0.0.0/0.",
        remediation,
        _COMMON_LIMITATION,
    )


RULES: dict[str, RuleInfo] = {
    "SG-001": RuleInfo(
        "SG-001",
        "SSH (22) open to the internet",
        RISKY_RULE,
        "An ingress rule allows TCP port 22 from 0.0.0.0/0.",
        "Remove the 0.0.0.0/0 source. Allow SSH only from a trusted CIDR (office/VPN) or a bastion "
        "security group, or use AWS Systems Manager Session Manager instead of open SSH.",
        _COMMON_LIMITATION,
    ),
    "SG-002": RuleInfo(
        "SG-002",
        "RDP (3389) open to the internet",
        RISKY_RULE,
        "An ingress rule allows TCP port 3389 from 0.0.0.0/0.",
        "Remove the 0.0.0.0/0 source. Allow RDP only from a trusted CIDR or a bastion security "
        "group, or use Session Manager / a VPN.",
        _COMMON_LIMITATION,
    ),
    "SG-003": RuleInfo(
        "SG-003",
        "PostgreSQL (5432) open to the internet",
        POTENTIAL_EXPOSURE,
        "An ingress rule allows TCP port 5432 from 0.0.0.0/0.",
        "Replace the 0.0.0.0/0 source with the security group of the application tier that needs "
        "database access, and keep the database in a private subnet without a public IP.",
        _COMMON_LIMITATION,
    ),
    "SG-004": RuleInfo(
        "SG-004",
        "MySQL (3306) open to the internet",
        POTENTIAL_EXPOSURE,
        "An ingress rule allows TCP port 3306 from 0.0.0.0/0.",
        "Replace the 0.0.0.0/0 source with the security group of the application tier that needs "
        "database access, and keep the database in a private subnet without a public IP.",
        _COMMON_LIMITATION,
    ),
    "SG-005": RuleInfo(
        "SG-005",
        "All protocols/ports open to the internet",
        RISKY_RULE,
        "An ingress rule allows all protocols, or all TCP/UDP ports, from 0.0.0.0/0.",
        "Delete the catch-all rule and add one rule per required port and protocol, each limited to "
        "the narrowest source (a security group or a specific CIDR).",
        _COMMON_LIMITATION
        + " When this rule fires it covers every port rule (SG-001..SG-004 and SG-007..SG-015) for "
        "the same rule entry; those are not reported separately.",
    ),
    "SG-006": RuleInfo(
        "SG-006",
        "Unrestricted outbound traffic",
        RISKY_RULE,
        "An egress rule allows all protocols, or all TCP/UDP ports, to 0.0.0.0/0.",
        "If the workload does not need arbitrary outbound access, replace the rule with the specific "
        "destinations and ports it needs (for example the database security group on 5432).",
        "Context-dependent: unrestricted egress is the AWS default and is often intentional (package "
        "updates, third-party APIs). Treated as a low-severity hygiene warning, not a vulnerability.",
    ),
    "SG-007": _port_rule("SG-007", _DB_FIX, POTENTIAL_EXPOSURE),
    "SG-008": _port_rule("SG-008", _DB_FIX, POTENTIAL_EXPOSURE),
    "SG-009": _port_rule("SG-009", _DB_FIX, POTENTIAL_EXPOSURE),
    "SG-010": _port_rule("SG-010", _DB_FIX, POTENTIAL_EXPOSURE),
    "SG-011": _port_rule("SG-011", _ADMIN_FIX, RISKY_RULE),
    "SG-012": _port_rule("SG-012", _ADMIN_FIX, RISKY_RULE),
    "SG-013": _port_rule("SG-013", _ADMIN_FIX, RISKY_RULE),
    "SG-014": _port_rule(
        "SG-014",
        "Remove the 0.0.0.0/0 source immediately and disable the unencrypted Docker TCP socket; an "
        "exposed Docker API is usually remote code execution. Use the local socket or TLS with "
        "client certificates from a trusted CIDR only.",
        RISKY_RULE,
    ),
    "SG-015": _port_rule("SG-015", _DB_FIX, POTENTIAL_EXPOSURE),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    resource_type: str
    resource_id: str
    resource_name: str
    summary: str
    evidence: dict[str, Any]
    remediation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "summary": self.summary,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


# --------------------------------------------------------------------------
# Rule matching helpers
# --------------------------------------------------------------------------


def is_world_cidr(cidr: str | None) -> bool:
    """Exactly ``0.0.0.0/0`` or ``::/0``."""
    return cidr in WORLD_CIDRS


def _is_world(rule: SecurityGroupRule) -> bool:
    return is_world_cidr(rule.cidr)


def _covers_port(rule: SecurityGroupRule, port: int) -> bool:
    """True when the rule allows TCP ``port`` (a protocol of ``-1`` allows every port)."""
    if rule.protocol == "-1":
        return True
    if rule.protocol != "tcp" or rule.from_port is None or rule.to_port is None:
        return False
    return rule.from_port <= port <= rule.to_port


def _is_all_traffic(rule: SecurityGroupRule) -> bool:
    """All protocols, or a TCP/UDP rule spanning the whole port range."""
    if rule.protocol == "-1":
        return True
    if rule.protocol in ("tcp", "udp") and rule.from_port is not None and rule.to_port is not None:
        return rule.from_port <= 1 and rule.to_port >= 65535
    return False


def world_rule_indexes(
    rules: Sequence[SecurityGroupRule], covers: Callable[[SecurityGroupRule], bool]
) -> list[int]:
    """Indexes of the rules (that ``covers`` accepts) which open the whole address space.

    A rule counts when its source is exactly ``0.0.0.0/0`` / ``::/0``, or when the CIDRs of all
    accepted rules of one IP version *together* collapse to the whole address space (a world rule
    split into halves, quarters, ...). Rules whose source is a security group are ignored.
    """
    candidates: list[tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for index, rule in enumerate(rules):
        if not rule.cidr or not covers(rule):
            continue
        try:
            candidates.append((index, ipaddress.ip_network(rule.cidr, strict=False)))
        except ValueError:
            continue

    found = {index for index, net in candidates if net.prefixlen == 0}
    for version in (4, 6):
        group = [(i, n) for i, n in candidates if n.version == version]
        if len(group) < 2:
            continue
        collapsed = list(ipaddress.collapse_addresses(n for _, n in group))
        if len(collapsed) == 1 and collapsed[0].prefixlen == 0:
            found.update(i for i, _ in group)
    return sorted(found)


def world_open_ingress(sg: SecurityGroup, port: int) -> bool:
    """True when ``sg`` accepts TCP ``port`` from the whole address space (exact or split)."""
    return bool(world_rule_indexes(sg.ingress, lambda r: _covers_port(r, port)))


def _rule_evidence(direction: str, index: int, rule: SecurityGroupRule) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "direction": direction,
        "index": index,
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "cidr": rule.cidr,
        "description": rule.description,
    }
    if not _is_world(rule):
        evidence["split_cidr"] = True  # open to the world only together with other rules
    return evidence


def _port_text(rule: dict[str, Any]) -> str:
    if rule["protocol"] == "-1":
        return "all protocols and ports"
    if rule["from_port"] == rule["to_port"]:
        return f"{rule['protocol']}/{rule['from_port']}"
    return f"{rule['protocol']}/{rule['from_port']}-{rule['to_port']}"


# --------------------------------------------------------------------------
# Exposure context
# --------------------------------------------------------------------------


def _exposure_contexts(config: NetworkConfig) -> dict[str, dict[str, Any]]:
    """Per security group: which instances use it and whether any looks internet-facing."""
    topology = build_topology(config)
    subnet_kind = {n.id: n.data.get("kind") for n in topology.nodes if n.type == "subnet"}

    attached: dict[str, list[dict[str, Any]]] = {sg.id: [] for sg in config.security_groups}
    for inst in config.instances:
        kind = subnet_kind.get(inst.subnet_id)
        entry = {
            "id": inst.id,
            "name": inst.name or inst.id,
            "subnet_id": inst.subnet_id,
            "subnet_kind": kind,
            "has_public_ip": inst.public_ip is not None,
        }
        for sg_id in inst.security_group_ids:
            attached.setdefault(sg_id, []).append(entry)

    contexts: dict[str, dict[str, Any]] = {}
    for sg_id, instances in attached.items():
        if not instances:
            exposure = EXPOSURE_UNATTACHED
            note = "No instance uses this security group, so the rule has no effect until one is attached."
        elif any(i["has_public_ip"] and i["subnet_kind"] == "public" for i in instances):
            exposure = EXPOSURE_CANDIDATE
            note = (
                "At least one attached instance has a public IP and is in a subnet with a route to an "
                "internet gateway, so the rule may be reachable from the internet (not verified)."
            )
        else:
            exposure = EXPOSURE_NO_PATH
            note = (
                "No attached instance has both a public IP and a public subnet, so no direct internet "
                "path is visible in the modelled configuration."
            )
        contexts[sg_id] = {"exposure": exposure, "attached_instances": instances, "note": note}
    return contexts


_SEVERITY = {
    # rule family -> (internet-facing candidate, no public path, unattached)
    "admin": ("high", "medium", "low"),
    "database": ("high", "medium", "low"),
    "remote": ("critical", "high", "medium"),
    "all_ports": ("critical", "high", "medium"),
    "egress": ("low", "low", "info"),
}
_EXPOSURE_COLUMN = {EXPOSURE_CANDIDATE: 0, EXPOSURE_NO_PATH: 1, EXPOSURE_UNATTACHED: 2}


def _severity(family: str, exposure: str) -> str:
    return _SEVERITY[family][_EXPOSURE_COLUMN[exposure]]


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


def _make_finding(
    rule_id: str,
    family: str,
    sg: SecurityGroup,
    context: dict[str, Any],
    matches: list[dict[str, Any]],
    summary: str,
    extra: dict[str, Any] | None = None,
) -> Finding:
    info = RULES[rule_id]
    evidence: dict[str, Any] = {"matching_rules": matches, "context": context}
    if extra:
        evidence.update(extra)
    return Finding(
        rule_id=rule_id,
        severity=_severity(family, context["exposure"]),
        category=info.category,
        title=info.title,
        resource_type="security_group",
        resource_id=sg.id,
        resource_name=sg.name,
        summary=f"{summary} {context['note']}",
        evidence=evidence,
        remediation=info.remediation,
    )


def _world_matches(
    direction: str,
    rules: Sequence[SecurityGroupRule],
    covers: Callable[[SecurityGroupRule], bool],
    exclude: set[int] | frozenset[int] = frozenset(),
) -> list[dict[str, Any]]:
    return [
        _rule_evidence(direction, i, rules[i])
        for i in world_rule_indexes(rules, covers)
        if i not in exclude
    ]


def _evaluate_group(sg: SecurityGroup, context: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    label = f"Security group '{sg.name}' ({sg.id})"

    all_ports = _world_matches("ingress", sg.ingress, _is_all_traffic)
    if all_ports:
        findings.append(
            _make_finding(
                "SG-005",
                "all_ports",
                sg,
                context,
                all_ports,
                f"{label} allows {_port_text(all_ports[0])} from anywhere (0.0.0.0/0).",
                {"also_covers": {rid: port for rid, (port, _) in SENSITIVE_PORTS.items()}},
            )
        )

    broad_indexes = {m["index"] for m in all_ports}
    for rule_id, (port, service) in SENSITIVE_PORTS.items():
        matches = _world_matches(
            "ingress", sg.ingress, lambda r, p=port: _covers_port(r, p), broad_indexes
        )
        if not matches:
            continue
        findings.append(
            _make_finding(
                rule_id,
                RULE_FAMILY[rule_id],
                sg,
                context,
                matches,
                f"{label} allows {service} (tcp/{port}) from anywhere (0.0.0.0/0).",
                {"port": port, "service": service},
            )
        )

    egress = _world_matches("egress", sg.egress, _is_all_traffic)
    if egress:
        findings.append(
            _make_finding(
                "SG-006",
                "egress",
                sg,
                context,
                egress,
                f"{label} allows {_port_text(egress[0])} to anywhere (0.0.0.0/0).",
            )
        )
    return findings


def evaluate(config: NetworkConfig) -> list[Finding]:
    """Run every rule against a validated config. Output order is deterministic."""
    contexts = _exposure_contexts(config)
    findings: list[Finding] = []
    for sg in config.security_groups:
        findings.extend(_evaluate_group(sg, contexts[sg.id]))
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.resource_id))
    return findings


def summarize(findings: list[Finding], resource_count: int | None = None) -> dict[str, Any]:
    """Counts by severity and rule.

    When ``resource_count`` (number of evaluated security groups) is given, the summary also
    carries a ``scoring`` block: per resource only the worst finding counts in full, every
    additional finding on the same resource is reported separately. ``scoring.compute_score_from_summary``
    uses it, so two findings on one security group are not scored like two separate problems.
    """
    by_severity = {name: 0 for name in SEVERITIES}
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    summary: dict[str, Any] = {
        "total": len(findings),
        "by_severity": by_severity,
        "by_rule": dict(sorted(by_rule.items())),
    }
    if resource_count is not None:
        grouped: dict[str, list[str]] = {}
        for finding in findings:
            grouped.setdefault(finding.resource_id, []).append(finding.severity)
        worst = {name: 0 for name in SEVERITIES}
        extra = {name: 0 for name in SEVERITIES}
        for severities in grouped.values():
            ordered = sorted(severities, key=SEVERITY_RANK.__getitem__)
            worst[ordered[0]] += 1
            for severity in ordered[1:]:
                extra[severity] += 1
        summary["scoring"] = {
            "resource_count": resource_count,
            "worst_by_resource": worst,
            "additional_findings": extra,
        }
    return summary
