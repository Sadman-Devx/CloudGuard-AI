"""Risk overlay for the topology graph: which resources are risky, and why.

Built from the same deterministic pieces as everything else (the rule engine for *what is risky*, the
reachability engine for *is it actually reachable from the internet*), so a red node always has a
reason a person can read:

* ``nodes``  per resource: worst severity and the reasons (rule findings, or "on an internet path");
* ``paths``  per exposed instance and risky port: the chain internet -> gateway -> route table ->
  subnet -> instance -> security group, with the reachability engine's verdict and its step-by-step
  trace, so a click on the path explains it.

A path is a *modelled* possibility (routes, network ACLs and security groups as configured); it is not
a statement that the service is running or exploitable.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from domain.network.reachability import ALLOWED, INTERNET, UNKNOWN, PathQuery, Reachability
from domain.network.rules import SEVERITY_RANK, Finding, evaluate
from domain.network.schema import NetworkConfig
from domain.network.topology import INTERNET_ID, PROTECTED_BY, SG_TRAFFIC, build_topology

MAX_PATHS = 25
MAX_PORTS_PER_INSTANCE = 4
_ALL_PORT_PROBES = (22, 3389, 5432, 3306)


def _worse(a: str | None, b: str) -> str:
    return b if a is None or SEVERITY_RANK[b] < SEVERITY_RANK[a] else a


def _ports(findings: list[Finding]) -> list[int]:
    ports: set[int] = set()
    for f in findings:
        port = f.evidence.get("port")
        if isinstance(port, int):
            ports.add(port)
        elif f.rule_id == "SG-005":
            ports.update(_ALL_PORT_PROBES)
    return sorted(ports)[:MAX_PORTS_PER_INSTANCE]


def _route_to(topology, target: str) -> list[str]:
    """Shortest chain of resources from the internet to ``target`` (security groups are leaves)."""
    neighbours: dict[str, list[str]] = {}
    for edge in topology.edges:
        if edge.kind in (PROTECTED_BY, SG_TRAFFIC):
            continue
        neighbours.setdefault(edge.source, []).append(edge.target)
        neighbours.setdefault(edge.target, []).append(edge.source)
    previous: dict[str, str | None] = {INTERNET_ID: None}
    queue = deque([INTERNET_ID])
    while queue:
        node = queue.popleft()
        if node == target:
            break
        for nxt in neighbours.get(node, []):
            if nxt not in previous:
                previous[nxt] = node
                queue.append(nxt)
    if target not in previous:
        return []
    chain = []
    cursor: str | None = target
    while cursor is not None:
        chain.append(cursor)
        cursor = previous[cursor]
    return chain[::-1]


def build_risk_overlay(config: NetworkConfig) -> dict[str, Any]:
    findings = evaluate(config)
    topology = build_topology(config)
    reach = Reachability(config)
    names = {n.id: n.label for n in topology.nodes}

    nodes: dict[str, dict[str, Any]] = {}

    def mark(node_id: str, severity: str, kind: str, reason: dict[str, Any]) -> None:
        entry = nodes.setdefault(node_id, {"severity": None, "kind": kind, "reasons": []})
        entry["severity"] = _worse(entry["severity"], severity)
        if kind == "finding":
            entry["kind"] = "finding"  # a finding outranks "on a path" as the node's headline
        if reason not in entry["reasons"] and len(entry["reasons"]) < 12:
            entry["reasons"].append(reason)

    by_sg: dict[str, list[Finding]] = {}
    for finding in findings:
        by_sg.setdefault(finding.resource_id, []).append(finding)
        reason = {
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "title": finding.title,
            "text": finding.summary,
        }
        mark(finding.resource_id, finding.severity, "finding", reason)
        for inst in (finding.evidence.get("context") or {}).get("attached_instances", []):
            mark(inst["id"], finding.severity, "finding", {**reason, "via": finding.resource_id})

    paths: list[dict[str, Any]] = []
    for inst in config.instances:
        if not inst.public_ip:
            continue
        inst_findings = [f for g in inst.security_group_ids for f in by_sg.get(g, [])]
        for port in _ports(inst_findings):
            result = reach.evaluate(PathQuery(INTERNET, inst.id, "tcp", port))
            if result.result not in (ALLOWED, UNKNOWN):
                continue
            related = [
                f for f in inst_findings if f.evidence.get("port") in (port, None) or f.rule_id == "SG-005"
            ]
            severity = min((f.severity for f in related), key=SEVERITY_RANK.__getitem__, default="medium")
            chain = _route_to(topology, inst.id)
            sgs = sorted({f.resource_id for f in related})
            steps = [*chain, *[g for g in sgs if g not in chain]]
            title = f"Internet -> {names.get(inst.id, inst.id)} on tcp/{port}"
            path = {
                "id": f"{inst.id}:{port}",
                "title": title,
                "severity": severity,
                "instance_id": inst.id,
                "port": port,
                "verdict": result.result,
                "verified": result.result == ALLOWED,
                "rule_ids": sorted({f.rule_id for f in related}),
                "steps": steps,
                "explanation": result.explanation,
                "trace": result.as_dict()["trace"],
                "assumptions": list(result.assumptions),
            }
            paths.append(path)
            for step in steps:
                if step != INTERNET_ID:
                    mark(
                        step,
                        severity,
                        "path",
                        {
                            "rule_id": None,
                            "severity": severity,
                            "title": title,
                            "text": result.explanation,
                            "path_id": path["id"],
                        },
                    )

    paths.sort(key=lambda p: (SEVERITY_RANK[p["severity"]], not p["verified"], p["id"]))
    paths = paths[:MAX_PATHS]
    for entry in nodes.values():
        entry["reasons"].sort(key=lambda r: SEVERITY_RANK[r["severity"]])
    return {
        "nodes": nodes,
        "paths": paths,
        "summary": {
            "findings": len(findings),
            "risky_nodes": len(nodes),
            "paths": len(paths),
            "verified_paths": sum(1 for p in paths if p["verified"]),
        },
    }
