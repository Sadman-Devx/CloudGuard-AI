from rest_framework import serializers

from .models import CloudResource, ConfigurationSnapshot


class SnapshotSerializer(serializers.ModelSerializer):
    """Snapshot metadata. The raw input is intentionally not exposed in lists."""

    class Meta:
        model = ConfigurationSnapshot
        fields = [
            "id",
            "project",
            "version",
            "source_type",
            "source_name",
            "name",
            "region",
            "schema_version",
            "resource_counts",
            "relationship_count",
            "warnings",
            "imported_at",
        ]
        read_only_fields = fields


class CloudResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = CloudResource
        fields = ["id", "external_id", "resource_type", "name", "region", "metadata"]
        read_only_fields = fields


class FixtureImportSerializer(serializers.Serializer):
    fixture = serializers.CharField(max_length=64)
