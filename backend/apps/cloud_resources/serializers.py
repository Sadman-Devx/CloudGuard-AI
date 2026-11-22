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


class IacImportSerializer(serializers.Serializer):
    """Body of ``POST /projects/{id}/snapshots/from-iac/``."""

    format = serializers.ChoiceField(choices=["terraform", "cloudformation"])
    content = serializers.JSONField(help_text="The file's text, or its already-parsed JSON object.")
    name = serializers.CharField(required=False, allow_blank=True, max_length=128)

    def validate_content(self, value):
        if isinstance(value, str) and len(value) > 2_000_000:
            raise serializers.ValidationError("The file is larger than 2 MB.")
        if not isinstance(value, (str, dict)):
            raise serializers.ValidationError("Send the file text or a JSON object.")
        return value


class AwsImportSerializer(serializers.Serializer):
    """Body of ``POST /projects/{id}/snapshots/from-aws/``. Credentials are never accepted here."""

    region = serializers.RegexField(r"^[a-z]{2}(-[a-z]+)+-\d$", max_length=32)
    role_arn = serializers.CharField(required=False, allow_blank=True, max_length=2048)
    external_id = serializers.CharField(required=False, allow_blank=True, max_length=1224)
    vpc_ids = serializers.ListField(
        child=serializers.RegexField(r"^vpc-[0-9a-f]{8,17}$"), required=False, max_length=10
    )
    include_s3 = serializers.BooleanField(required=False, default=False)
    name = serializers.CharField(required=False, allow_blank=True, max_length=128)
