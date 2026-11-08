"""Before/after comparison for a simulated change (roadmap Day 7).

Inputs are plain dicts produced by the Day 4 rule engine and Day 6 reachability engine:
  findings: [{"rule_id": "SG-003", "resource_ref": "sg-db", ...}]
  paths:    [{"id": "app->db:5432", "result": "allowed|blocked|unknown", ...}]
"""

VERDICT_SAFE = "safe_improvement"
VERDICT_NO_CHANGE = "no_improvement"
VERDICT_BREAKS = "breaks_required_connectivity"
VERDICT_REVIEW = "needs_review"


def _key(f):
    return (f["rule_id"], f["resource_ref"])


def compare(before, after, required_path_ids=()):
    b_keys = {_key(f): f for f in before["findings"]}
    a_keys = {_key(f): f for f in after["findings"]}

    resolved = [b_keys[k] for k in b_keys if k not in a_keys]
    remaining = [a_keys[k] for k in a_keys if k in b_keys]
    introduced = [a_keys[k] for k in a_keys if k not in b_keys]

    b_paths = {p["id"]: p for p in before["paths"]}
    a_paths = {p["id"]: p for p in after["paths"]}

    path_changes = []
    for pid in sorted(set(b_paths) | set(a_paths)):
        b = b_paths.get(pid, {}).get("result", "unknown")
        a = a_paths.get(pid, {}).get("result", "unknown")
        path_changes.append({
            "id": pid, "before": b, "after": a, "changed": a != b,
            "required": pid in required_path_ids,
        })

    warnings = []
    broken = []
    for c in path_changes:
        if c["required"] and c["after"] == "blocked":
            broken.append(c["id"])
            warnings.append({
                "code": "REQUIRED_PATH_BROKEN", "severity": "high", "path_id": c["id"],
                "message": f"Required path {c['id']} would be blocked after this change.",
            })
        elif c["required"] and c["after"] == "unknown":
            warnings.append({
                "code": "REQUIRED_PATH_UNKNOWN", "severity": "medium", "path_id": c["id"],
                "message": f"Required path {c['id']} is outside the supported model; cannot confirm it still works.",
            })
    for f in introduced:
        warnings.append({
            "code": "NEW_FINDING", "severity": "medium", "rule_id": f["rule_id"],
            "message": f"Change introduces new finding {f['rule_id']} on {f['resource_ref']}.",
        })

    if broken:
        verdict = VERDICT_BREAKS
    elif introduced or any(w["code"] == "REQUIRED_PATH_UNKNOWN" for w in warnings):
        verdict = VERDICT_REVIEW
    elif resolved:
        verdict = VERDICT_SAFE
    else:
        verdict = VERDICT_NO_CHANGE

    return {
        "verdict": verdict,
        "resolved_findings": resolved,
        "remaining_findings": remaining,
        "introduced_findings": introduced,
        "path_changes": path_changes,
        "warnings": warnings,
        "read_only": True,
        "note": "Simulation only. No real AWS resources were changed.",
    }
