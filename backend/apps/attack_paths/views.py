from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from graph import AttackGraph

from .demo_graph import SAMPLE_GRAPH

_graph = AttackGraph.from_dict(SAMPLE_GRAPH)


class PathQuerySerializer(serializers.Serializer):
    top_k = serializers.IntegerField(default=10, min_value=1, max_value=100)
    max_depth = serializers.IntegerField(default=6, min_value=1, max_value=10)


class SimulationSerializer(serializers.Serializer):
    remove_nodes = serializers.ListField(child=serializers.CharField(min_length=1), allow_empty=True)
    max_depth = serializers.IntegerField(default=6, min_value=1, max_value=10)


class BlastRadiusQuerySerializer(serializers.Serializer):
    max_depth = serializers.IntegerField(default=4, min_value=1, max_value=10)


@api_view(["GET"])
def graph(request):
    return Response(_graph.to_dict())


@api_view(["GET"])
def paths(request):
    query = PathQuerySerializer(data=request.query_params)
    query.is_valid(raise_exception=True)
    result = _graph.attack_paths(**query.validated_data)
    return Response({"paths": result, "choke_points": _graph.choke_points(result)})


@api_view(["GET"])
def blast_radius(request, node_id):
    query = BlastRadiusQuerySerializer(data=request.query_params)
    query.is_valid(raise_exception=True)
    try:
        result = _graph.blast_radius(
            node_id,
            max_depth=query.validated_data["max_depth"],
        )
    except KeyError as exc:
        raise NotFound(f"Node '{node_id}' not found.") from exc
    return Response(result)


@api_view(["POST"])
def simulate(request):
    serializer = SimulationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    missing = [
        node_id for node_id in serializer.validated_data["remove_nodes"] if node_id not in _graph.nodes
    ]
    if missing:
        raise NotFound(f"Unknown nodes: {missing}")
    return Response(_graph.simulate_fix(**serializer.validated_data))
