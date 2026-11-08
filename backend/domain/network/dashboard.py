"""Project dashboard summary and status indicators (roadmap Day 7)."""

SEVERITIES = ("critical", "high", "medium", "low")


def build_dashboard(state):
    """state: {"project": {...}, "snapshot": {...} | None, "findings": [...],
               "ai_interactions": int, "simulations": [{"verdict":..}]}"""
    findings = state.get("findings", [])
    sims = state.get("simulations", [])
    snapshot = state.get("snapshot")

    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.get("severity") in by_sev:
            by_sev[f["severity"]] += 1

    stages = [
        {"key": "uploaded", "label": "Config uploaded", "done": snapshot is not None},
        {"key": "analyzed", "label": "Analyzed", "done": snapshot is not None and state.get("analyzed", False)},
        {"key": "explained", "label": "AI explained", "done": state.get("ai_interactions", 0) > 0},
        {"key": "simulated", "label": "Fix simulated", "done": len(sims) > 0},
    ]
    next_step = next((s["label"] for s in stages if not s["done"]), None)

    return {
        "project": state.get("project"),
        "snapshot_version": snapshot.get("version") if snapshot else None,
        "stages": stages,
        "next_step": next_step,
        "finding_counts": by_sev,
        "total_findings": len(findings),
        "simulations_run": len(sims),
        "safe_fixes": sum(1 for s in sims if s.get("verdict") == "safe_improvement"),
        "read_only": True,
    }
