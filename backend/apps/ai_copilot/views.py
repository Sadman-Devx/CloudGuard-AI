from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.security_engine.models import SecurityFinding
from common.exceptions import ConfigValidationFailed

from .providers import provider_status
from .services.explain import SnapshotIncompatible, explain_finding, interaction_payload, latest_interaction


class CopilotStatusView(APIView):
    """Which provider answers explanation requests (so the UI can label results honestly)."""

    @extend_schema(responses={200: dict}, tags=["copilot"])
    def get(self, request):
        return Response(provider_status())


class ExplainRequestSerializer(serializers.Serializer):
    refresh = serializers.BooleanField(required=False, default=False)


class FindingExplainView(APIView):
    """GET the latest explanation (or null); POST to generate one. Proposals are never applied."""

    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_explain"

    def get_throttles(self):
        # Only generating costs money; reading the stored answer is free.
        return super().get_throttles() if self.request.method == "POST" else []

    @extend_schema(responses={200: dict}, tags=["copilot"])
    def get(self, request, pk):
        finding = get_object_or_404(SecurityFinding, pk=pk)
        return Response({"interaction": interaction_payload(latest_interaction(finding))})

    @extend_schema(request=ExplainRequestSerializer, responses={200: dict}, tags=["copilot"])
    def post(self, request, pk):
        finding = get_object_or_404(SecurityFinding.objects.select_related("snapshot__project"), pk=pk)
        body = ExplainRequestSerializer(data=request.data or {})
        body.is_valid(raise_exception=True)
        try:
            interaction, cached = explain_finding(finding, refresh=body.validated_data["refresh"])
        except SnapshotIncompatible as exc:
            raise ConfigValidationFailed(exc.errors) from exc
        return Response({"interaction": interaction_payload(interaction, cached=cached)})