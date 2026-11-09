from rest_framework import serializers

from common.sanitize import has_control_chars

from .models import Project


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ["id", "name", "description", "created_at"]
        read_only_fields = ["id", "created_at"]

    @staticmethod
    def _plain_text(value: str) -> str:
        if has_control_chars(value):
            raise serializers.ValidationError("Control characters are not allowed.")
        return value

    def validate_name(self, value):
        return self._plain_text(value)

    def validate_description(self, value):
        return self._plain_text(value)