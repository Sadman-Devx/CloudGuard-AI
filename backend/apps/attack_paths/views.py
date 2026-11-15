"""Attack paths and blast radius.

Two groups of endpoints share one engine (``domain.network.attack_graph``):

* ``/api/snapshots/<id>/attack-path/...``  built from an imported snapshot (the real thing);
* ``/api/attack-path/...``                 a fixed synthetic demo graph, always labelled ``demo: true``.

Nothing is applied to any cloud account; simulations work on copies.
"""

from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.cloud_resources.models import ConfigurationSnapshot
from common.exceptions import ConfigValidationFailed
from common.throttles import WriteThrottle
from domain.network.attack_graph import AttackGraph, build_attack_graph, simulate_change
from domain.network.extensions import extensions_from_json
from domain.network.proposals import ProposalError, validate_change
from domain.network.schema import ConfigValidationError, parse_config
from domain.network.simulation import SimulationError

from .demo_graph import SAMPLE_GRAPH

_demo = AttackGraph.from_dict(SAMPLE_GRAPH)


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------


class PathQuerySerializer(serializers.Serializer):
    top_k = serializers.IntegerField(default=10, min_value=1, max_value=100)
    max_depth = serializers.IntegerField(default=6, min_value=1, max_value=10)


class BlastRadiusQuerySerializer(serializers.Serializer):
    max_depth = serializers.IntegerField(default=4, min_value=1, max_value=10)


class SimulationSerializer(serializers.Serializer):
    """Demo graph: remove whole nodes."""

    remove_nodes = serializers.ListField(child=serializers.CharField(min_length=1), allow_empty=True)
    max_depth = serializers.IntegerField(default=6, min_value=1, max_value=10)


class SnapshotSimulationSerializer(serializers.Serializer):
    """Snapshot graph: a validated security-group change, or nodes / edges to remove."""

    proposed_change = serializers.DictField(required=False)
    remove_nodes = serializers.ListField(
        child=serializers.CharField(min_length=1), required=False, max_length=50
    )
    remove_edges = serializers.ListField(
        child=serializers.ListField(child=serializers.CharField(min_length=1), min_length=2, max_length=2),
        required=False,
        max_length=100,
    )
    max_depth = serializers.IntegerField(default=6, min_value=1, max_value=10)

    def validate(self, attrs):
        given = [key for key in ("proposed_change", "remove_nodes", "remove_edges") if attrs.get(key)]
        if not given:
            raise serializers.ValidationError("Provide proposed_change, remove_nodes or remove_edges.")
        if "proposed_change" in given and len(given) > 1:
            raise serializers.ValidationError(
                "proposed_change cannot be combined with remove_nodes/remove_edges."
            )
        return attrs


# --------------------------------------------------------------------------
# Demo graph (legacy routes, kept for the standalone explorer)
# --------------------------------------------------------------------------


@api_view(["GET"])
def graph(request):
    return Response({**_demo.to_dict(), "demo": True})


@api_view(["GET"])
def paths(request):
    query = PathQuerySerializer(data=request.query_params)
    query.is_valid(raise_exception=True)
    result = _demo.attack_paths(**query.validated_data)
    return Response(
        {
            "paths": result,
            "choke_points": _demo.choke_points(result),
            "search": _demo.last_search,
            "demo": True,
        }
    )


@api_view(["GET"])
def blast_radius(request, node_id):
    query = BlastRadiusQuerySerializer(data=request.query_params)
    query.is_valid(raise_exception=True)
    try:
        result = _demo.blast_radius(node_id, max_depth=query.validated_data["max_depth"])
    except KeyError as exc:
        raise NotFound(f"Node '{node_id}' not found.") from exc
    return Response({**result, "demo": True})


@api_view(["POST"])
def simulate(request):
    serializer = SimulationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    missing = [n for n in serializer.validated_data["remove_nodes"] if n not in _demo.nodes]
    if missing:
        raise NotFound(f"Unknown nodes: {missing}")
    return Response({**_demo.simulate_fix(**serializer.validated_data), "demo": True})


# --------------------------------------------------------------------------
# Snapshot graph
# --------------------------------------------------------------------------


def _load(pk):
    """Parse the stored snapshot and build its attack graph (snapshots are immutable)."""
    snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
    try:
        config = parse_config(snapshot.raw_json)
    except ConfigValidationError as exc:
        raise ConfigValidationFailed([issue.as_dict() for issue in exc.errors]) from exc
    extensions = extensions_from_json(snapshot.raw_json, config)
    attack_graph, info = build_attack_graph(config, extensions)
    return snapshot, config, extensions, attack_graph, info


def _meta(snapshot, info):
    return {"demo": False, "snapshot": snapshot.id, "warnings": info.warnings}


class SnapshotAttackGraphView(APIView):
    @extend_schema(responses={200: dict}, tags=["attack-path"])
    def get(self, request, pk):
        snapshot, _, _, attack_graph, info = _load(pk)
        return Response({**attack_graph.to_dict(), **_meta(snapshot, info)})


class SnapshotAttackPathsView(APIView):
    @extend_schema(responses={200: dict}, tags=["attack-path"])
    def get(self, request, pk):
        query = PathQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        snapshot, _, _, attack_graph, info = _load(pk)
        result = attack_graph.attack_paths(**query.validated_data)
        return Response(
            {
                "paths": result,
                "choke_points": attack_graph.choke_points(result),
                "search": attack_graph.last_search,
                **_meta(snapshot, info),
            }
        )


class SnapshotBlastRadiusView(APIView):
    @extend_schema(responses={200: dict}, tags=["attack-path"])
    def get(self, request, pk, node_id):
        query = BlastRadiusQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        snapshot, _, _, attack_graph, info = _load(pk)
        try:
            result = attack_graph.blast_radius(node_id, max_depth=query.validated_data["max_depth"])
        except KeyError as exc:
            raise NotFound(f"Node '{node_id}' not found.") from exc
        return Response({**result, **_meta(snapshot, info)})


class SnapshotAttackSimulateView(APIView):
    """What happens to attack-path risk if this security-group change (or edge/node removal) is made."""

    # ScopedRateThrottle reads the scope from the view; WriteThrottle keeps the shared write budget.
    throttle_classes = [WriteThrottle, ScopedRateThrottle]
    throttle_scope = "simulate"

    @extend_schema(request=SnapshotSimulationSerializer, responses={200: dict}, tags=["attack-path"])
    def post(self, request, pk):
        body = SnapshotSimulationSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        snapshot, config, extensions, attack_graph, info = _load(pk)

        if "proposed_change" in data:
            raw = data["proposed_change"]
            try:
                change = validate_change(raw, config, str(raw.get("security_group_id", "")))
                result = simulate_change(config, extensions, change, max_depth=data["max_depth"])
            except (ProposalError, SimulationError) as exc:
                raise ValidationError({"proposed_change": exc.errors}) from exc
            return Response({**result, **_meta(snapshot, info)})

        remove_nodes = data.get("remove_nodes", [])
        remove_edges = [tuple(edge) for edge in data.get("remove_edges", [])]
        missing = [n for n in remove_nodes if n not in attack_graph.nodes]
        known_edges = {(e.source, e.target) for edges in attack_graph.adj.values() for e in edges}
        missing_edges = [list(e) for e in remove_edges if e not in known_edges]
        if missing:
            raise NotFound(f"Unknown nodes: {missing}")
        if missing_edges:
            raise NotFound(f"Unknown edges: {missing_edges}")
        result = attack_graph.simulate_fix(remove_nodes, data["max_depth"], remove_edges)
        return Response({**result, **_meta(snapshot, info)})
