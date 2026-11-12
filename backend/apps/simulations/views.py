from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.ai_copilot.models import AIInteraction
from apps.cloud_resources.models import ConfigurationSnapshot
from apps.security_engine.models import SecurityFinding
from common.exceptions import ConfigValidationFailed

from .models import Simulation
from .serializers import SimulationListSerializer, SimulationRequestSerializer, SimulationSerializer
from .services.simulate import SimulationInputError, SnapshotIncompatible, check_path, run_simulation


class SnapshotSimulationsView(generics.ListAPIView):
    """GET lists a snapshot's simulations; POST runs a new one. Nothing is ever applied."""

    serializer_class = SimulationListSerializer
    # ScopedRateThrottle reads the scope from the *view*; a scope set on a throttle subclass is
    # ignored and the limit silently never applies.
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "simulate"

    def get_throttles(self):
        return super().get_throttles() if self.request.method == "POST" else []

    def get_queryset(self):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=self.kwargs["pk"])
        return Simulation.objects.filter(snapshot=snapshot)

    @extend_schema(
        request=SimulationRequestSerializer, responses={201: SimulationSerializer}, tags=["simulation"]
    )
    def post(self, request, pk):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
        body = SimulationRequestSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data

        finding = interaction = None
        if "finding_id" in data:
            finding = SecurityFinding.objects.filter(pk=data["finding_id"]).first()
            if finding is None:
                raise ValidationError({"finding_id": ["Finding not found."]})
        if "interaction_id" in data:
            interaction = (
                AIInteraction.objects.select_related("finding").filter(pk=data["interaction_id"]).first()
            )
            if interaction is None:
                raise ValidationError({"interaction_id": ["Explanation not found."]})

        try:
            simulation = run_simulation(
                snapshot,
                proposed_change=data.get("proposed_change"),
                finding=finding,
                interaction=interaction,
                required_paths=data.get("required_paths"),
            )
        except SnapshotIncompatible as exc:
            raise ConfigValidationFailed(exc.errors) from exc
        except SimulationInputError as exc:
            raise ValidationError(exc.errors) from exc
        return Response(SimulationSerializer(simulation).data, status=status.HTTP_201_CREATED)


class SimulationDetailView(generics.RetrieveAPIView):
    """The stored evidence: findings diff, per-path before/after, and the full reachability traces."""

    queryset = Simulation.objects.all()
    serializer_class = SimulationSerializer


class SnapshotReachabilityView(APIView):
    """Ask one question of the unmodified snapshot: can X reach Y on tcp/5432?"""

    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "simulate"

    @extend_schema(request=dict, responses={200: dict}, tags=["simulation"])
    def post(self, request, pk):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
        try:
            return Response(check_path(snapshot, request.data))
        except SnapshotIncompatible as exc:
            raise ConfigValidationFailed(exc.errors) from exc
        except SimulationInputError as exc:
            raise ValidationError(exc.errors) from exc
