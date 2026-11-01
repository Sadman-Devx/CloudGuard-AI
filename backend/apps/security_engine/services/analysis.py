"""Run the deterministic rule engine over a snapshot and persist the result."""

from __future__ import annotations

from django.db import transaction

from apps.cloud_resources.models import ConfigurationSnapshot
from apps.cloud_resources.services.topology import SnapshotIncompatible
from domain.network.rules import RULES_VERSION, evaluate, summarize
from domain.network.schema import ConfigValidationError, parse_config

from ..models import AnalysisRun, SecurityFinding

__all__ = ["SnapshotIncompatible", "analyze_snapshot"]


def analyze_snapshot(snapshot: ConfigurationSnapshot) -> AnalysisRun:
    """Evaluate every rule and atomically replace the snapshot's previous findings.

    Idempotent: the same snapshot always produces the same findings. The snapshot itself is never
    modified (it is immutable); nothing is applied to any cloud account.
    """
    try:
        config = parse_config(snapshot.raw_json)
    except ConfigValidationError as exc:
        raise SnapshotIncompatible([issue.as_dict() for issue in exc.errors]) from exc

    findings = evaluate(config)
    with transaction.atomic():
        AnalysisRun.objects.filter(snapshot=snapshot).delete()
        SecurityFinding.objects.filter(snapshot=snapshot).delete()
        run = AnalysisRun.objects.create(
            snapshot=snapshot, rules_version=RULES_VERSION, summary=summarize(findings)
        )
        SecurityFinding.objects.bulk_create(
            SecurityFinding(snapshot=snapshot, **finding.as_dict()) for finding in findings
        )
    return run