"""Deterministic security rule engine (SG-001 .. SG-006).

Pure Python (no Django). Findings come from this code only; an LLM never decides whether
something is risky. Every finding carries the rule id, the affected resource, the exact rule
entries that matched (evidence) and a remediation.

Wording matters: an open security-group rule is a **risky rule** or a **potential exposure**, not
proof of an exploitable vulnerability or of internet reachability. Reachability (routes, NACLs,
return paths) is evaluated separately on Day 6. Here, "exposure context" only looks at whether
the attached instances have a public IP and sit in a subnet with a route to an internet gateway.

Severity therefore depends on context, not just on the port number:

=========  ===================  ==================  ==========
Rule       internet-facing      private / no path   unattached
=========  ===================  ==================  ==========
SG-001/2   high                 medium              low
SG-003/4   high                 medium              low
SG-005     critical             high                medium
SG-006     low                  low                 info
=========  ===================  ==================  ==========
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.network.schema import NetworkConfig, SecurityGroup, SecurityGroupRule
from domain.network.topology import build_topology

RULES_VERSION = "1.0"

WORLD_CIDR = "0.0.0.0/0"

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

RISKY_RULE = "risky_rule"
POTENTIAL_EXPOSURE = "potential_exposure"

# Exposure context of a security group
EXPOSURE_CANDIDATE = "internet_facing_candidate"
EXPOSURE_NO_PATH = "no_public_path"
EXPOSURE_UNATTACHED = "unattached"

SENSITIVE_PORTS = {
    "SG-001": (22, "SSH"),
    "SG-002": (3389, "RDP"),
    "SG-003": (5432, "PostgreSQL"),
    "SG-004": (3306, "MySQL"),
}


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
        + " When this rule fires it covers SG-001..SG-004 for the same rule entry; those are not "
        "reported separately.",
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


def _is_world(rule: SecurityGroupRule) -> bool:
    return rule.cidr == WORLD_CIDR


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


def _rule_evidence(direction: str, index: int, rule: SecurityGroupRule) -> dict[str, Any]:
    return {
        "direction": direction,
        "index": index,
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "cidr": rule.cidr,
        "description": rule.description,
    }


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


def _evaluate_group(sg: SecurityGroup, context: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    label = f"Security group '{sg.name}' ({sg.id})"

    all_ports = [
        _rule_evidence("ingress", i, r)
        for i, r in enumerate(sg.ingress)
        if _is_world(r) and _is_all_traffic(r)
    ]
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
        matches = [
            _rule_evidence("ingress", i, r)
            for i, r in enumerate(sg.ingress)
            if i not in broad_indexes and _is_world(r) and _covers_port(r, port)
        ]
        if not matches:
            continue
        family = "admin" if rule_id in ("SG-001", "SG-002") else "database"
        findings.append(
            _make_finding(
                rule_id,
                family,
                sg,
                context,
                matches,
                f"{label} allows {service} (tcp/{port}) from anywhere (0.0.0.0/0).",
                {"port": port, "service": service},
            )
        )

    egress = [
        _rule_evidence("egress", i, r) for i, r in enumerate(sg.egress) if _is_world(r) and _is_all_traffic(r)
    ]
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


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_severity = {name: 0 for name in SEVERITIES}
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_rule": dict(sorted(by_rule.items()))}