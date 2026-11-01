from rest_framework import serializers

from .models import AnalysisRun, SecurityFinding


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityFinding
        fields = [
            "id",
            "snapshot",
            "rule_id",
            "severity",
            "category",
            "title",
            "resource_type",
            "resource_id",
            "resource_name",
            "summary",
            "evidence",
            "remediation",
        ]
        read_only_fields = fields


class AnalysisSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisRun
        fields = ["snapshot", "rules_version", "summary", "ran_at"]
        read_only_fields = fields