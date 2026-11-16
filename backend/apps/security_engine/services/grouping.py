"""Group stored findings by the instances they affect.

A security-group finding is about the *group*; what a person usually wants to know is "which of my
servers is this about?". Every finding carries, in ``evidence.context``, the instances that use the
group, so grouping needs no new analysis: a finding is listed under each affected instance, and
findings on a group nothing uses are listed separately as ``unattached``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from domain.network.rules import SEVERITY_RANK


def _compact(finding: dict[str, Any], affected: int) -> dict[str, Any]:
    return {
        "id": finding["id"],
        "rule_id": finding["rule_id"],
        "severity": finding["severity"],
        "category": finding["category"],
        "title": finding["title"],
        "resource_id": finding["resource_id"],
        "resource_name": finding["resource_name"],
        "summary": finding["summary"],
        "affected_instance_count": affected,
    }


def group_by_instance(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """``findings`` are serialised findings (dicts). Returns instances (worst first) + unattached."""
    instances: dict[str, dict[str, Any]] = {}
    unattached: list[dict[str, Any]] = []

    for finding in findings:
        context = (finding.get("evidence") or {}).get("context") or {}
        attached = context.get("attached_instances") or []
        if not attached:
            unattached.append(_compact(finding, 0))
            continue
        compact = _compact(finding, len(attached))
        for inst in attached:
            entry = instances.setdefault(
                inst["id"],
                {
                    "id": inst["id"],
                    "name": inst.get("name") or inst["id"],
                    "subnet_id": inst.get("subnet_id"),
                    "subnet_kind": inst.get("subnet_kind"),
                    "has_public_ip": bool(inst.get("has_public_ip")),
                    "security_groups": [],
                    "findings": [],
                },
            )
            if finding["resource_id"] not in entry["security_groups"]:
                entry["security_groups"].append(finding["resource_id"])
            entry["findings"].append(compact)

    result = []
    for entry in instances.values():
        entry["findings"].sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["rule_id"], f["resource_id"]))
        entry["finding_count"] = len(entry["findings"])
        entry["worst_severity"] = entry["findings"][0]["severity"]
        entry["by_severity"] = {}
        for f in entry["findings"]:
            entry["by_severity"][f["severity"]] = entry["by_severity"].get(f["severity"], 0) + 1
        result.append(entry)
    result.sort(key=lambda e: (SEVERITY_RANK[e["worst_severity"]], -e["finding_count"], e["name"]))
    unattached.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["rule_id"], f["resource_id"]))
    return {"instances": result, "unattached": unattached}
