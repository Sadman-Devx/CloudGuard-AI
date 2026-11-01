from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.cloud_resources.models import ConfigurationSnapshot
from common.exceptions import ConfigValidationFailed
from domain.network.rules import RULES, SEVERITIES

from .models import SecurityFinding
from .serializers import AnalysisSerializer, FindingSerializer
from .services.analysis import SnapshotIncompatible, analyze_snapshot


def _payload(snapshot, analysis, findings):
    return {
        "snapshot": snapshot.id,
        "analysis": AnalysisSerializer(analysis).data if analysis else None,
        "results": FindingSerializer(findings, many=True).data,
    }


class SnapshotAnalyzeView(APIView):
    """Run the deterministic rules (SG-001..SG-006). Safe to repeat; replaces earlier results."""

    @extend_schema(request=None, responses={200: dict}, tags=["security"])
    def post(self, request, pk):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
        try:
            analysis = analyze_snapshot(snapshot)
        except SnapshotIncompatible as exc:
            raise ConfigValidationFailed(exc.errors) from exc
        return Response(_payload(snapshot, analysis, snapshot.findings.all()))


class SnapshotFindingsView(APIView):
    """Stored findings. ``analysis`` is null until the snapshot has been analysed."""

    @extend_schema(
        responses={200: dict},
        tags=["security"],
        parameters=[
            OpenApiParameter("severity", str, description=f"One of {', '.join(SEVERITIES)}"),
            OpenApiParameter("rule_id", str, description="For example SG-003"),
        ],
    )
    def get(self, request, pk):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
        findings = snapshot.findings.all()
        severity = request.query_params.get("severity")
        if severity:
            if severity not in SEVERITIES:
                raise ValidationError({"severity": [f"Must be one of {', '.join(SEVERITIES)}."]})
            findings = findings.filter(severity=severity)
        rule_id = request.query_params.get("rule_id")
        if rule_id:
            findings = findings.filter(rule_id=rule_id)
        analysis = getattr(snapshot, "analysis", None)
        return Response(_payload(snapshot, analysis, findings))


class FindingDetailView(generics.RetrieveAPIView):
    queryset = SecurityFinding.objects.all()
    serializer_class = FindingSerializer


class RuleCatalogView(APIView):
    """The rules the engine implements, with what each one does and does not tell you."""

    @extend_schema(responses={200: dict}, tags=["security"])
    def get(self, request):
        return Response(
            {
                "results": [
                    {
                        "id": r.id,
                        "title": r.title,
                        "category": r.category,
                        "description": r.description,
                        "remediation": r.remediation,
                        "limitations": r.limitations,
                    }
                    for r in RULES.values()
                ]
            }
        )