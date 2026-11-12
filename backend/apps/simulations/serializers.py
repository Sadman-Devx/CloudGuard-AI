from rest_framework import serializers

from domain.network.scoring import compare_scores
from domain.network.simulation import MAX_REQUIRED_PATHS

from .models import Simulation

_REQUEST_FIELDS = {"proposed_change", "interaction_id", "finding_id", "required_paths"}


class SimulationRequestSerializer(serializers.Serializer):
    """Body of ``POST /snapshots/{id}/simulations/``.

    Give either ``proposed_change`` (a security-group change) or ``interaction_id`` (use the
    proposal from a stored AI explanation). Either way the change is re-validated server-side.
    """

    proposed_change = serializers.DictField(required=False)
    interaction_id = serializers.IntegerField(required=False, min_value=1)
    finding_id = serializers.IntegerField(required=False, min_value=1)
    required_paths = serializers.ListField(
        child=serializers.DictField(), required=False, max_length=MAX_REQUIRED_PATHS
    )

    def validate(self, attrs):
        unknown = sorted(set(self.initial_data) - _REQUEST_FIELDS)
        if unknown:
            raise serializers.ValidationError(f"Unknown field(s): {', '.join(unknown)}.")
        if ("proposed_change" in attrs) == ("interaction_id" in attrs):
            raise serializers.ValidationError("Provide exactly one of proposed_change or interaction_id.")
        return attrs


class SimulationSerializer(serializers.ModelSerializer):
    """Full evidence: the diff plus the complete before/after reachability traces."""

    proposed_change = serializers.JSONField(source="proposed_change_json", read_only=True)
    required_paths = serializers.JSONField(source="required_paths_json", read_only=True)
    result = serializers.JSONField(source="result_json", read_only=True)
    before = serializers.JSONField(source="before_json", read_only=True)
    after = serializers.JSONField(source="after_json", read_only=True)
    applied_to_cloud = serializers.SerializerMethodField()
    score = serializers.SerializerMethodField()

    class Meta:
        model = Simulation
        fields = [
            "id",
            "snapshot",
            "finding",
            "ai_interaction",
            "status",
            "engine_version",
            "outcome",
            "recommended",
            "applied_to_cloud",
            "proposed_change",
            "required_paths",
            "result",
            "score",
            "before",
            "after",
            "created_at",
        ]
        read_only_fields = fields

    def get_applied_to_cloud(self, obj) -> bool:
        return False  # the MVP never modifies real infrastructure

    def get_score(self, obj) -> dict | None:
        """Security score before and after the change, derived from the stored findings summaries.

        Computed on read from ``result_json`` (not stored), so older simulations get a score too and
        there is no migration.
        """
        findings = (obj.result_json or {}).get("findings") or {}
        before = (findings.get("before_summary") or {}).get("by_severity")
        after = (findings.get("after_summary") or {}).get("by_severity")
        if before is None or after is None:
            return None
        return compare_scores(before, after)


class SimulationListSerializer(SimulationSerializer):
    """History view: no per-path traces."""

    class Meta(SimulationSerializer.Meta):
        fields = [
            "id",
            "snapshot",
            "finding",
            "ai_interaction",
            "status",
            "outcome",
            "recommended",
            "applied_to_cloud",
            "proposed_change",
            "created_at",
        ]
        read_only_fields = fields