"""Simulate a proposed security-group change on a clone of the configuration.

Pure Python (no Django). The input is a ``ProposedChange`` that has already been through
``proposals.validate_change`` (the model's output is untrusted; the simulator only ever sees the
validated, closed set of actions). Nothing is applied anywhere: configurations are frozen
dataclasses, so ``apply_change`` returns a *new* configuration and the original cannot change.

The simulation answers three questions, all deterministically:

1. **Does the change fix the finding?** The rule engine is re-run on the modified clone and the
   findings are diffed (resolved / remaining / introduced).
2. **What happens to connectivity?** Reachability is evaluated before and after for every
   plausible path to the instances protected by the changed group on the affected port(s).
3. **Is it safe to recommend?** Only if it improves security *and* every required path was
   verified to still work. A change whose impact on legitimate traffic could not be verified is
   never marked recommended.

Required paths
--------------
The caller can list the paths that must keep working. When none are given, they are *inferred
from the intent of the change*, because "everything that worked before" would wrongly treat the
removal of access for unrelated hosts (the whole point of least privilege) as a regression:

* ``replace_ingress_source`` -> instances in the new source group must keep reaching the instances
  protected by the changed group;
* ``restrict_ingress_cidr``  -> a representative host inside the new CIDR must keep reaching them;
* ``remove_ingress_rule``    -> nothing can be inferred; the result says so and is not
  recommended until required paths are listed.

The anonymous internet is never required by inference: reducing that exposure is the goal.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from dataclasses import dataclass
from typing import Any

from domain.network.proposals import EXTRA_ACTIONS, ProposedChange, wide_cidr_warning
from domain.network.reachability import (
    ALLOWED,
    BLOCKED,
    INTERNET,
    MODELLED_PROTOCOLS,
    PathQuery,
    PathResult,
    QueryError,
    Reachability,
    validate_query,
)
from domain.network.rules import SENSITIVE_PORTS, WORLD_CIDR, Finding, summarize
from domain.network.rules import evaluate as evaluate_rules
from domain.network.schema import NON_PUBLIC_RANGES, NaclRule, NetworkConfig, SecurityGroupRule

SIMULATION_VERSION = "1.0"

MAX_REQUIRED_PATHS = 20
MAX_CANDIDATE_PATHS = 300

# Path changes (before -> after)
PRESERVED = "preserved"
LOST = "lost"
NEWLY_ALLOWED = "newly_allowed"
STILL_BLOCKED = "still_blocked"
INCONCLUSIVE = "inconclusive"

# Path roles
ROLE_REQUIRED = "required"
ROLE_EXPOSURE = "exposure"  # the anonymous internet reaching the protected instances
ROLE_OTHER = "other"

# Outcomes (most important first)
OUTCOME_BREAKS_REQUIRED = "breaks_required_connectivity"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_REQUIRED_UNMET = "required_connectivity_unmet"
OUTCOME_NEW_RISK = "introduces_new_risk"
OUTCOME_IMPROVES = "improves_security"
OUTCOME_FIXES_CONNECTIVITY = "fixes_connectivity"
OUTCOME_NO_EFFECT = "no_effect"

_SENSITIVE_PROBES = tuple(sorted(port for port, _ in SENSITIVE_PORTS.values()))


class SimulationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# --------------------------------------------------------------------------
# Applying a change to a clone
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AppliedChange:
    config: NetworkConfig
    modifications: tuple[dict[str, Any], ...]
    warnings: tuple[dict[str, str], ...]


def _rule_view(rule: SecurityGroupRule) -> dict[str, Any]:
    return {
        "protocol": rule.protocol,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
        "cidr": rule.cidr,
        "peer_security_group_id": rule.peer_security_group_id,
    }


def _rule_key(rule: SecurityGroupRule) -> tuple:
    return (rule.protocol, rule.from_port, rule.to_port, rule.cidr, rule.peer_security_group_id)


def _is_targeted(rule: SecurityGroupRule, change: ProposedChange) -> bool:
    """A 0.0.0.0/0 ingress rule that the proposal covers (same logic as proposal validation)."""
    if rule.cidr != WORLD_CIDR:
        return False
    if rule.protocol == "-1":
        return True
    if change.protocol == "-1" or rule.protocol != change.protocol:
        return False
    if None in (rule.from_port, rule.to_port, change.from_port, change.to_port):
        return False
    return rule.from_port <= change.from_port and change.to_port <= rule.to_port


def _broader_than_proposal(rule: SecurityGroupRule, change: ProposedChange) -> bool:
    if rule.protocol == "-1":
        return change.protocol != "-1"
    return (rule.from_port, rule.to_port) != (change.from_port, change.to_port)


def apply_change(config: NetworkConfig, change: ProposedChange) -> AppliedChange:
    """Return a modified *copy* of ``config``; ``config`` itself is never touched."""
    if change.action in EXTRA_ACTIONS:
        return _apply_extended(config, change)
    sg = next((g for g in config.security_groups if g.id == change.security_group_id), None)
    if sg is None:
        raise SimulationError([f"Security group {change.security_group_id} does not exist."])

    targeted = [i for i, rule in enumerate(sg.ingress) if _is_targeted(rule, change)]
    if not targeted:
        raise SimulationError(["No ingress rule open to 0.0.0.0/0 matches the proposed change."])

    untouched_keys = {_rule_key(r) for i, r in enumerate(sg.ingress) if i not in targeted}
    new_ingress: list[SecurityGroupRule] = []
    modifications: list[dict[str, Any]] = []
    warnings: list[dict[str, str]] = []

    for index, rule in enumerate(sg.ingress):
        if index not in targeted:
            new_ingress.append(rule)
            continue
        if change.action == "remove_ingress_rule":
            replacement = None
        elif change.action == "replace_ingress_source":
            replacement = dataclasses.replace(
                rule, cidr=None, peer_security_group_id=change.new_source_security_group_id
            )
        else:  # restrict_ingress_cidr
            replacement = dataclasses.replace(rule, cidr=change.new_cidr, peer_security_group_id=None)

        merged = replacement is not None and _rule_key(replacement) in untouched_keys
        if replacement is not None and not merged:
            new_ingress.append(replacement)
            untouched_keys.add(_rule_key(replacement))
        modifications.append(
            {
                "security_group": sg.id,
                "index": index,
                "before": _rule_view(rule),
                "after": _rule_view(replacement) if replacement is not None and not merged else None,
                "note": "merged into an identical existing rule" if merged else None,
            }
        )
        if _broader_than_proposal(rule, change):
            warnings.append(
                {
                    "code": "RULE_BROADER_THAN_PROPOSAL",
                    "message": (
                        f"Ingress rule #{index} on {sg.id} is wider than the proposed "
                        f"{change.protocol} ports; the whole rule is changed, not just the proposed ports."
                    ),
                }
            )

    wide = wide_cidr_warning(change)
    if wide:
        warnings.append({"code": "WIDE_CIDR", "message": wide})

    modified_sg = dataclasses.replace(sg, ingress=tuple(new_ingress))
    groups = tuple(modified_sg if g.id == sg.id else g for g in config.security_groups)
    return AppliedChange(
        dataclasses.replace(config, security_groups=groups), tuple(modifications), tuple(warnings)
    )


def _nacl_view(rule: NaclRule) -> dict[str, Any]:
    return {
        "rule_number": rule.rule_number,
        "action": rule.action,
        "protocol": rule.protocol,
        "cidr": rule.cidr,
        "from_port": rule.from_port,
        "to_port": rule.to_port,
    }


def _apply_extended(config: NetworkConfig, change: ProposedChange) -> AppliedChange:
    """The changes beyond "narrow an open ingress rule": egress, added rules and network ACLs."""
    sg = next((g for g in config.security_groups if g.id == change.security_group_id), None)
    if sg is None:
        raise SimulationError([f"Security group {change.security_group_id} does not exist."])
    modifications: list[dict[str, Any]] = []
    warnings: list[dict[str, str]] = []
    wide = wide_cidr_warning(change)
    if wide:
        warnings.append({"code": "WIDE_CIDR", "message": wide})

    if change.action in ("restrict_egress_rule", "add_ingress_rule"):
        replacement = SecurityGroupRule(
            protocol=change.allow_protocol if change.action == "restrict_egress_rule" else change.protocol,
            from_port=change.allow_from_port if change.action == "restrict_egress_rule" else change.from_port,
            to_port=change.allow_to_port if change.action == "restrict_egress_rule" else change.to_port,
            cidr=change.new_cidr,
            peer_security_group_id=change.new_source_security_group_id,
        )
        if change.action == "add_ingress_rule":
            if any(_rule_key(r) == _rule_key(replacement) for r in sg.ingress):
                raise SimulationError(["An identical ingress rule already exists."])
            modifications.append(
                {
                    "security_group": sg.id,
                    "direction": "ingress",
                    "index": len(sg.ingress),
                    "before": None,
                    "after": _rule_view(replacement),
                    "note": "rule added",
                }
            )
            modified = dataclasses.replace(sg, ingress=(*sg.ingress, replacement))
        else:
            targeted = [i for i, r in enumerate(sg.egress) if _is_targeted(r, change)]
            if not targeted:
                raise SimulationError(["No egress rule open to 0.0.0.0/0 matches the proposed change."])
            untouched = {_rule_key(r) for i, r in enumerate(sg.egress) if i not in targeted}
            placed = _rule_key(replacement) in untouched
            new_egress: list[SecurityGroupRule] = []
            for index, rule in enumerate(sg.egress):
                if index not in targeted:
                    new_egress.append(rule)
                    continue
                note = "covered by the replacement rule" if placed else None
                if not placed:
                    new_egress.append(replacement)
                    placed = True
                modifications.append(
                    {
                        "security_group": sg.id,
                        "direction": "egress",
                        "index": index,
                        "before": _rule_view(rule),
                        "after": _rule_view(replacement) if note is None else None,
                        "note": note,
                    }
                )
            modified = dataclasses.replace(sg, egress=tuple(new_egress))
        groups = tuple(modified if g.id == sg.id else g for g in config.security_groups)
        return AppliedChange(
            dataclasses.replace(config, security_groups=groups), tuple(modifications), tuple(warnings)
        )

    acl = next((a for a in config.network_acls if a.id == change.acl_id), None)
    if acl is None:
        raise SimulationError([f"Network ACL {change.acl_id} does not exist."])
    entries = acl.ingress if change.direction == "ingress" else acl.egress
    if change.action == "remove_nacl_rule":
        existing = next((e for e in entries if e.rule_number == change.rule_number), None)
        if existing is None:
            raise SimulationError([f"{acl.id} has no {change.direction} rule number {change.rule_number}."])
        new_entries = tuple(e for e in entries if e.rule_number != change.rule_number)
        before, after = _nacl_view(existing), None
    else:
        if any(e.rule_number == change.rule_number for e in entries):
            raise SimulationError(
                [f"{acl.id} already has a {change.direction} rule number {change.rule_number}."]
            )
        added = NaclRule(
            rule_number=change.rule_number,
            action="allow",
            protocol=change.protocol,
            cidr=change.new_cidr,
            from_port=change.from_port,
            to_port=change.to_port,
        )
        new_entries = (*entries, added)
        before, after = None, _nacl_view(added)
    modified_acl = (
        dataclasses.replace(acl, ingress=new_entries)
        if change.direction == "ingress"
        else dataclasses.replace(acl, egress=new_entries)
    )
    modifications.append(
        {
            "security_group": sg.id,
            "network_acl": acl.id,
            "direction": change.direction,
            "index": change.rule_number,
            "before": before,
            "after": after,
            "note": None,
        }
    )
    acls = tuple(modified_acl if a.id == acl.id else a for a in config.network_acls)
    return AppliedChange(
        dataclasses.replace(config, network_acls=acls), tuple(modifications), tuple(warnings)
    )


# --------------------------------------------------------------------------
# Choosing which paths to compare
# --------------------------------------------------------------------------


def probe_ports(change: ProposedChange) -> tuple[tuple[str, int], ...]:
    """The (protocol, port) pairs worth testing for this change."""
    if change.protocol in MODELLED_PROTOCOLS and change.from_port is not None:
        ports = sorted({change.from_port, change.to_port})
        return tuple((change.protocol, p) for p in ports)
    if change.protocol == "-1":  # all traffic: probe the well-known sensitive ports over tcp
        return tuple(("tcp", p) for p in _SENSITIVE_PROBES)
    return ()


def parse_required_paths(raw: Any, config: NetworkConfig) -> list[PathQuery]:
    """Validate an explicit list of required paths (untrusted input)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise SimulationError(["required_paths must be a list."])
    if len(raw) > MAX_REQUIRED_PATHS:
        raise SimulationError([f"At most {MAX_REQUIRED_PATHS} required paths are allowed."])
    errors: list[str] = []
    queries: list[PathQuery] = []
    for i, item in enumerate(raw):
        try:
            query = validate_query(item, config, label=f"required_paths[{i}]")
        except QueryError as exc:
            errors.extend(exc.errors)
            continue
        if query.protocol not in MODELLED_PROTOCOLS:
            errors.append(f"required_paths[{i}]: only tcp and udp paths can be required.")
            continue
        queries.append(query)
    if errors:
        raise SimulationError(errors)
    return queries


def _group_members(config: NetworkConfig, group_id: str) -> list[str]:
    return sorted(i.id for i in config.instances if group_id in i.security_group_ids)


def _trusted_host(network: ipaddress.IPv4Network) -> str | None:
    """A representative *public* address inside ``network`` to stand in for the trusted source."""
    host = next(iter(network.hosts()), None)
    if host is None or any(host in net for net in NON_PUBLIC_RANGES):
        return None
    return str(host)


def _candidates(
    config: NetworkConfig, change: ProposedChange
) -> tuple[list[tuple[PathQuery, str]], list[tuple[PathQuery, bool]], list[dict[str, str]]]:
    """Return ``(candidates with role, inferred required paths, warnings)``.

    Each inferred path carries ``strict``: a strict path is required even if it did not work
    before (the proposal names its source group explicitly); a non-strict one is only required if
    it worked before (we are narrowing an existing allow-list, not asserting an intent).
    """
    if change.action in EXTRA_ACTIONS:
        return _extended_candidates(config, change)
    destinations = _group_members(config, change.security_group_id)
    probes = probe_ports(change)
    warnings: list[dict[str, str]] = []

    inferred_sources: list[tuple[str, str | None]] = []
    if change.action == "replace_ingress_source":
        inferred_sources = [(i, None) for i in _group_members(config, change.new_source_security_group_id)]
    elif change.action == "restrict_ingress_cidr":
        network = ipaddress.ip_network(change.new_cidr, strict=False)
        host = _trusted_host(network)
        if host is not None:
            inferred_sources.append((INTERNET, host))
        # A private CIDR (for example the VPC range) trusts the instances inside it.
        inferred_sources += [
            (i.id, None) for i in config.instances if ipaddress.ip_address(i.private_ip) in network
        ]

    sources: list[tuple[str, str | None]] = [(INTERNET, None)]
    sources += [(s, ip) for s, ip in inferred_sources if ip is not None]
    sources += [(i.id, None) for i in config.instances]
    seen_sources = list(dict.fromkeys(sources))

    candidates: list[tuple[PathQuery, str]] = []
    inferred: list[tuple[PathQuery, bool]] = []
    strict = change.action == "replace_ingress_source"
    for dst in destinations:
        for protocol, port in probes:
            for source, ip in seen_sources:
                if source == dst:
                    continue
                query = PathQuery(source, dst, protocol, port, ip)
                role = ROLE_EXPOSURE if source == INTERNET and ip is None else ROLE_OTHER
                candidates.append((query, role))
                if (source, ip) in inferred_sources:
                    inferred.append((query, strict))

    if len(candidates) > MAX_CANDIDATE_PATHS:
        keep = {q.key for q, _ in inferred}
        trimmed = [c for c in candidates if c[0].key in keep]
        trimmed += [c for c in candidates if c[0].key not in keep][
            : max(0, MAX_CANDIDATE_PATHS - len(trimmed))
        ]
        candidates = trimmed
        warnings.append(
            {
                "code": "PATHS_TRUNCATED",
                "message": f"Only the first {MAX_CANDIDATE_PATHS} candidate paths were compared.",
            }
        )
    return candidates, inferred, warnings


def _extended_candidates(
    config: NetworkConfig, change: ProposedChange
) -> tuple[list[tuple[PathQuery, str]], list[tuple[PathQuery, bool]], list[dict[str, str]]]:
    """Candidate and inferred-required paths for egress, added-rule and network-ACL changes.

    Inferred paths are always *strict*: these changes state an intent ("this source/destination
    must work"), so that path has to work after the change even if it did not before.
    """
    warnings: list[dict[str, str]] = []
    members = _group_members(config, change.security_group_id)
    everyone = [i.id for i in config.instances]
    sensitive = tuple(("tcp", p) for p in _SENSITIVE_PROBES)

    def ports(protocol: str | None, low: int | None, high: int | None) -> tuple[tuple[str, int], ...]:
        if protocol in MODELLED_PROTOCOLS and low is not None and high is not None:
            return tuple((protocol, p) for p in sorted({low, high}))
        return sensitive

    candidates: list[tuple[PathQuery, str]] = []
    inferred: list[tuple[PathQuery, bool]] = []

    def add(source: str, ip: str | None, destination: str, probes, required) -> None:
        for protocol, port in probes:
            if source == destination:
                continue
            query = PathQuery(source, destination, protocol, port, ip)
            candidates.append((query, ROLE_EXPOSURE if source == INTERNET and ip is None else ROLE_OTHER))
            if required(protocol, port):
                inferred.append((query, True))

    def inside(cidr: str | None) -> set[str]:
        if not cidr:
            return set()
        network = ipaddress.ip_network(cidr, strict=False)
        return {i.id for i in config.instances if ipaddress.ip_address(i.private_ip) in network}

    def host_of(cidr: str | None) -> str | None:
        return _trusted_host(ipaddress.ip_network(cidr, strict=False)) if cidr else None

    never = lambda _p, _n: False  # noqa: E731

    if change.action == "restrict_egress_rule":
        allowed = ports(change.allow_protocol, change.allow_from_port, change.allow_to_port)
        probes = allowed + (sensitive if change.protocol == "-1" else ())
        wanted = set(_group_members(config, change.new_source_security_group_id or "")) | inside(
            change.new_cidr
        )
        for src in members:
            for dst in everyone:
                if dst not in members:
                    add(src, None, dst, probes, lambda p, n, d=dst: d in wanted and (p, n) in allowed)
    elif change.action == "add_ingress_rule":
        probes = ports(change.protocol, change.from_port, change.to_port)
        trusted_ids = set(_group_members(config, change.new_source_security_group_id or "")) | inside(
            change.new_cidr
        )
        host = host_of(change.new_cidr)
        for dst in members:
            add(INTERNET, None, dst, probes, never)
            if host is not None:
                add(INTERNET, host, dst, probes, lambda _p, _n: True)
            for src in everyone:
                add(src, None, dst, probes, lambda _p, _n, s=src: s in trusted_ids)
    else:  # network ACL changes
        acl = next((a for a in config.network_acls if a.id == change.acl_id), None)
        in_acl = [i.id for i in config.instances if acl is not None and i.subnet_id in acl.subnet_ids]
        probes = ports(change.protocol, change.from_port, change.to_port)
        adding = change.action == "add_nacl_allow_rule"
        trusted_ids = inside(change.new_cidr) if adding else set()
        host = host_of(change.new_cidr) if adding else None
        if change.direction == "ingress":
            for dst in in_acl:
                add(INTERNET, None, dst, probes, never)
                if host is not None:
                    add(INTERNET, host, dst, probes, lambda _p, _n: True)
                for src in everyone:
                    if src not in in_acl:
                        add(src, None, dst, probes, lambda _p, _n, s=src: s in trusted_ids)
        else:
            for src in in_acl:
                for dst in everyone:
                    if dst not in in_acl:
                        add(src, None, dst, probes, lambda _p, _n, d=dst: d in trusted_ids)

    if len(candidates) > MAX_CANDIDATE_PATHS:
        keep = {q.key for q, _ in inferred}
        trimmed = [c for c in candidates if c[0].key in keep]
        trimmed += [c for c in candidates if c[0].key not in keep][
            : max(0, MAX_CANDIDATE_PATHS - len(trimmed))
        ]
        candidates = trimmed
        warnings.append(
            {
                "code": "PATHS_TRUNCATED",
                "message": f"Only the first {MAX_CANDIDATE_PATHS} candidate paths were compared.",
            }
        )
    return candidates, inferred, warnings


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


def classify_change(before: str, after: str) -> str:
    if ALLOWED == before == after:
        return PRESERVED
    if before == ALLOWED and after == BLOCKED:
        return LOST
    if before == BLOCKED and after == ALLOWED:
        return NEWLY_ALLOWED
    if before == BLOCKED and after == BLOCKED:
        return STILL_BLOCKED
    return INCONCLUSIVE


def _finding_key(finding: Finding) -> tuple[str, str]:
    return finding.rule_id, finding.resource_id


def _finding_view(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "resource_id": finding.resource_id,
        "severity": finding.severity,
        "title": finding.title,
    }


def _label(query: PathQuery) -> str:
    who = query.source if query.source_ip is None else f"{query.source} ({query.source_ip})"
    if query.source == INTERNET and query.source_ip is None:
        who = "anonymous internet"
    where = query.protocol if query.port is None else f"{query.protocol}/{query.port}"
    return f"{who} -> {query.destination} {where}"


@dataclass(frozen=True)
class SimulationResult:
    change: ProposedChange
    modifications: tuple[dict[str, Any], ...]
    outcome: str
    recommended: bool
    required_source: str  # "explicit" | "inferred" | "none"
    warnings: tuple[dict[str, str], ...]
    summary_lines: tuple[str, ...]
    findings: dict[str, Any]
    connectivity: tuple[dict[str, Any], ...]
    before: dict[str, Any]
    after: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine_version": SIMULATION_VERSION,
            "outcome": self.outcome,
            "recommended": self.recommended,
            "required_paths_source": self.required_source,
            "warnings": list(self.warnings),
            "summary_lines": list(self.summary_lines),
            "modifications": list(self.modifications),
            "findings": self.findings,
            "connectivity": list(self.connectivity),
        }


def _evaluate_paths(config: NetworkConfig, queries: list[PathQuery]) -> dict[str, PathResult]:
    engine = Reachability(config)
    return {q.key: engine.evaluate(q) for q in queries}


def simulate(
    config: NetworkConfig,
    change: ProposedChange,
    required_paths: list[PathQuery] | None = None,
) -> SimulationResult:
    """Run the full before/after comparison. ``config`` is not modified."""
    applied = apply_change(config, change)
    warnings = list(applied.warnings)

    candidates, inferred, candidate_warnings = _candidates(config, change)
    warnings.extend(candidate_warnings)
    explicit = list(required_paths or [])

    # Explicit required paths are always evaluated, even if they fall outside the candidate set.
    queries: dict[str, tuple[PathQuery, str]] = {q.key: (q, role) for q, role in candidates}
    for query in explicit:
        queries.setdefault(query.key, (query, ROLE_REQUIRED))
    ordered = [q for q, _ in queries.values()]
    before_paths = _evaluate_paths(config, ordered)

    if explicit:
        required_source, required = "explicit", explicit
    else:
        required = [q for q, strict in inferred if strict or before_paths[q.key].result == ALLOWED]
        required_source = "inferred" if required else "none"
    for query in required:
        queries[query.key] = (query, ROLE_REQUIRED)
    after_paths = _evaluate_paths(applied.config, ordered)

    connectivity: list[dict[str, Any]] = []
    for key, (query, role) in queries.items():
        before, after = before_paths[key], after_paths[key]
        connectivity.append(
            {
                "key": key,
                **query.as_dict(),
                "label": _label(query),
                "role": role,
                "required": role == ROLE_REQUIRED,
                "before": before.result,
                "after": after.result,
                "change": classify_change(before.result, after.result),
                "before_reason_codes": list(before.reason_codes),
                "after_reason_codes": list(after.reason_codes),
            }
        )

    before_findings = evaluate_rules(config)
    after_findings = evaluate_rules(applied.config)
    before_keys = {_finding_key(f) for f in before_findings}
    after_keys = {_finding_key(f) for f in after_findings}
    resolved = [f for f in before_findings if _finding_key(f) not in after_keys]
    introduced = [f for f in after_findings if _finding_key(f) not in before_keys]
    remaining = [f for f in after_findings if _finding_key(f) in before_keys]
    findings = {
        "before_summary": summarize(before_findings, len(config.security_groups)),
        "after_summary": summarize(after_findings, len(applied.config.security_groups)),
        "resolved": [_finding_view(f) for f in resolved],
        "remaining": [_finding_view(f) for f in remaining],
        "introduced": [_finding_view(f) for f in introduced],
    }

    # ---- outcome ---------------------------------------------------------------------------
    req = [c for c in connectivity if c["required"]]
    broken = [c for c in req if c["change"] == LOST]
    inconclusive = [c for c in req if c["change"] == INCONCLUSIVE]
    unmet = [c for c in req if c["change"] == STILL_BLOCKED]
    exposure_closed = [
        c for c in connectivity if c["source"] == INTERNET and not c["required"] and c["change"] == LOST
    ]
    exposure_opened = [
        c
        for c in connectivity
        if c["source"] == INTERNET and not c["required"] and c["change"] == NEWLY_ALLOWED
    ]

    if broken:
        outcome = OUTCOME_BREAKS_REQUIRED
    elif inconclusive:
        outcome = OUTCOME_INCONCLUSIVE
    elif unmet:
        outcome = OUTCOME_REQUIRED_UNMET
    elif introduced or exposure_opened:
        outcome = OUTCOME_NEW_RISK
    elif resolved or exposure_closed:
        outcome = OUTCOME_IMPROVES
    elif change.action in EXTRA_ACTIONS and any(
        c["required"] and c["change"] == NEWLY_ALLOWED for c in connectivity
    ):
        outcome = OUTCOME_FIXES_CONNECTIVITY
    else:
        outcome = OUTCOME_NO_EFFECT

    required_verified = bool(req) and all(c["after"] == ALLOWED for c in req)
    recommended = outcome in (OUTCOME_IMPROVES, OUTCOME_FIXES_CONNECTIVITY) and required_verified

    if not req:
        warnings.append(
            {
                "code": "NO_REQUIRED_PATHS",
                "message": (
                    "No required connectivity was given or could be inferred, so the effect on legitimate "
                    "traffic is not verified. List the paths that must keep working to confirm the fix."
                ),
            }
        )
    for c in req:
        if c["change"] == STILL_BLOCKED:
            warnings.append(
                {
                    "code": "REQUIRED_PATH_BLOCKED",
                    "message": f"Required path {c['label']} is blocked before and after the change.",
                }
            )
    assumed = sorted({a for r in (*before_paths.values(), *after_paths.values()) for a in r.assumptions})
    if assumed:
        warnings.append(
            {
                "code": "DEFAULT_NACL_ASSUMED",
                "message": "Subnets without a network ACL in the snapshot were evaluated as the AWS default "
                f"ACL (allow all): {', '.join(assumed)}.",
            }
        )

    # ---- human-readable evidence (deterministic, so it can also ground the AI summary) -----
    lines: list[str] = []
    for f in resolved:
        lines.append(f"Resolves {f.rule_id} on {f.resource_id}.")
    for f in introduced:
        lines.append(f"Introduces {f.rule_id} on {f.resource_id}.")
    for c in connectivity:
        verb = {
            PRESERVED: "is preserved",
            LOST: "is blocked after the change",
            NEWLY_ALLOWED: "becomes allowed",
            STILL_BLOCKED: "stays blocked",
            INCONCLUSIVE: "could not be verified",
        }[c["change"]]
        if c["required"]:
            lines.append(f"Required path {c['label']} {verb}.")
        elif c["change"] in (LOST, NEWLY_ALLOWED) and c["source"] == INTERNET:
            lines.append(f"Internet exposure {c['label']}: {c['before']} -> {c['after']}.")
        elif c["change"] == LOST:
            lines.append(f"Also removes access: {c['label']}.")
        elif c["change"] == NEWLY_ALLOWED and change.action in EXTRA_ACTIONS:
            lines.append(f"Also opens access: {c['label']}.")

    def snapshot(paths: dict[str, PathResult], found: list[Finding]) -> dict[str, Any]:
        return {
            "findings": [_finding_view(f) for f in found],
            "paths": [r.as_dict() for r in paths.values()],
        }

    return SimulationResult(
        change=change,
        modifications=applied.modifications,
        outcome=outcome,
        recommended=recommended,
        required_source=required_source,
        warnings=tuple(warnings),
        summary_lines=tuple(lines),
        findings=findings,
        connectivity=tuple(connectivity),
        before=snapshot(before_paths, before_findings),
        after=snapshot(after_paths, after_findings),
    )


__all__ = [
    "SIMULATION_VERSION",
    "AppliedChange",
    "SimulationError",
    "SimulationResult",
    "apply_change",
    "classify_change",
    "parse_required_paths",
    "probe_ports",
    "simulate",
]
