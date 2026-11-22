"""Risk score and trend dashboard.

A project's score is the score of its latest analysed snapshot; the trend is the score of every
analysed snapshot, oldest first. Everything comes from stored analyses (cheap); snapshots that were
never analysed are counted and can be analysed in bulk with the refresh endpoint.
"""

from __future__ import annotations

from typing import Any

from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.cloud_resources.models import ConfigurationSnapshot
from apps.projects.models import Project
from apps.simulations.models import Simulation
from domain.network.rules import RULES, SEVERITIES
from domain.network.scoring import compute_score_from_summary

from .models import SecurityFinding
from .services.analysis import SnapshotIncompatible, analyze_snapshot

MAX_REFRESH = 25
TREND_LIMIT = 60


def _point(snapshot: ConfigurationSnapshot) -> dict[str, Any]:
    analysis = snapshot.analysis
    summary = analysis.summary or {}
    score = compute_score_from_summary(summary)
    return {
        "snapshot_id": snapshot.id,
        "version": snapshot.version,
        "name": snapshot.name or snapshot.source_name or f"v{snapshot.version}",
        "source_type": snapshot.source_type,
        "imported_at": snapshot.imported_at,
        "analyzed_at": analysis.ran_at,
        "score": score["value"],
        "grade": score["grade"],
        "total": summary.get("total", 0),
        "by_severity": {s: (summary.get("by_severity") or {}).get(s, 0) for s in SEVERITIES},
    }


def _snapshots(project: Project):
    return list(project.snapshots.select_related("analysis").order_by("version"))


def _overview(project: Project) -> dict[str, Any]:
    snapshots = _snapshots(project)
    analysed = [s for s in snapshots if hasattr(s, "analysis")]
    trend = [_point(s) for s in analysed][-TREND_LIMIT:]
    latest = trend[-1] if trend else None
    previous = trend[-2] if len(trend) > 1 else None
    return {
        "id": project.id,
        "name": project.name,
        "snapshot_count": len(snapshots),
        "analyzed_count": len(analysed),
        "unanalyzed_count": len(snapshots) - len(analysed),
        "latest": latest,
        "delta": (latest["score"] - previous["score"]) if latest and previous else None,
        "trend": trend,
    }


class DashboardView(APIView):
    """Every project with its current score and trend (the portfolio view)."""

    @extend_schema(responses={200: dict}, tags=["dashboard"])
    def get(self, request):
        projects = [_overview(p) for p in Project.objects.order_by("name")]
        scored = [p["latest"]["score"] for p in projects if p["latest"]]
        return Response(
            {
                "projects": projects,
                "totals": {
                    "projects": len(projects),
                    "analyzed_projects": len(scored),
                    "average_score": round(sum(scored) / len(scored)) if scored else None,
                    "lowest_score": min(scored) if scored else None,
                },
            }
        )


class ProjectDashboardView(APIView):
    """One project: score, trend, severity mix, the rules causing most findings and the worst resources."""

    @extend_schema(responses={200: dict}, tags=["dashboard"])
    def get(self, request, pk):
        project = get_object_or_404(Project, pk=pk)
        overview = _overview(project)
        extra: dict[str, Any] = {
            "top_rules": [],
            "worst_resources": [],
            "fixes": {"simulations": 0, "recommended": 0},
        }
        latest = overview["latest"]
        if latest:
            snapshot = next(s for s in _snapshots(project) if s.id == latest["snapshot_id"])
            by_rule = (snapshot.analysis.summary or {}).get("by_rule") or {}
            extra["top_rules"] = [
                {"rule_id": rid, "count": count, "title": RULES[rid].title if rid in RULES else rid}
                for rid, count in sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
            ]
            findings = SecurityFinding.objects.filter(snapshot=snapshot)
            order = {s: i for i, s in enumerate(SEVERITIES)}
            worst = sorted(findings, key=lambda f: (order.get(f.severity, 9), f.rule_id, f.resource_id))[:6]
            extra["worst_resources"] = [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "rule_id": f.rule_id,
                    "resource_id": f.resource_id,
                    "title": f.title,
                }
                for f in worst
            ]
        sims = Simulation.objects.filter(snapshot__project=project)
        extra["fixes"] = {"simulations": sims.count(), "recommended": sims.filter(recommended=True).count()}
        return Response({**overview, **extra})


class ProjectDashboardRefreshView(APIView):
    """Analyse the project's snapshots that have no analysis yet (oldest first, at most 25)."""

    @extend_schema(request=None, responses={200: dict}, tags=["dashboard"])
    def post(self, request, pk):
        project = get_object_or_404(Project, pk=pk)
        pending = [s for s in _snapshots(project) if not hasattr(s, "analysis")]
        analysed, skipped = 0, []
        for snapshot in pending[:MAX_REFRESH]:
            try:
                analyze_snapshot(snapshot)
                analysed += 1
            except SnapshotIncompatible as exc:
                skipped.append({"snapshot_id": snapshot.id, "version": snapshot.version, "reason": str(exc)})
        return Response(
            {"analyzed": analysed, "skipped": skipped, "remaining": max(0, len(pending) - MAX_REFRESH)}
        )
