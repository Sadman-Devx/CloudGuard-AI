from django.db import models

from apps.projects.models import Project
from domain.network import inventory as inv


def _choices(values: tuple[str, ...]) -> list[tuple[str, str]]:
    return [(value, value.replace("_", " ").title()) for value in values]


class ConfigurationSnapshot(models.Model):
    """An immutable, validated copy of an imported network configuration.

    Re-importing never edits an existing snapshot; it creates the next version,
    so analysis results can always be reproduced from the stored input.
    """

    class SourceType(models.TextChoices):
        UPLOAD = "upload", "Upload"
        FIXTURE = "fixture", "Sample fixture"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="snapshots")
    version = models.PositiveIntegerField()
    source_type = models.CharField(max_length=16, choices=SourceType.choices)
    source_name = models.CharField(max_length=128, blank=True)
    name = models.CharField(max_length=256, blank=True)
    region = models.CharField(max_length=32)
    schema_version = models.CharField(max_length=16)
    raw_json = models.JSONField()
    warnings = models.JSONField(default=list)
    resource_counts = models.JSONField(default=dict)
    relationship_count = models.PositiveIntegerField(default=0)
    imported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-version"]
        constraints = [
            models.UniqueConstraint(fields=["project", "version"], name="uniq_snapshot_project_version")
        ]

    def __str__(self) -> str:
        return f"{self.project_id} v{self.version}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Configuration snapshots are immutable; import a new version instead.")
        super().save(*args, **kwargs)


class CloudResource(models.Model):
    snapshot = models.ForeignKey(ConfigurationSnapshot, on_delete=models.CASCADE, related_name="resources")
    external_id = models.CharField(max_length=64)
    resource_type = models.CharField(max_length=32, choices=_choices(inv.RESOURCE_TYPES))
    name = models.CharField(max_length=256, blank=True)
    region = models.CharField(max_length=32)
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "external_id"], name="uniq_resource_snapshot_external"
            )
        ]
        indexes = [models.Index(fields=["snapshot", "resource_type"])]

    def __str__(self) -> str:
        return f"{self.resource_type}:{self.external_id}"


class NetworkRelationship(models.Model):
    snapshot = models.ForeignKey(
        ConfigurationSnapshot, on_delete=models.CASCADE, related_name="relationships"
    )
    source = models.ForeignKey(CloudResource, on_delete=models.CASCADE, related_name="outgoing")
    target = models.ForeignKey(CloudResource, on_delete=models.CASCADE, related_name="incoming")
    relation_type = models.CharField(max_length=32, choices=_choices(inv.RELATION_TYPES))
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "source", "target", "relation_type"],
                name="uniq_relationship_edge",
            )
        ]

    def __str__(self) -> str:
        return f"{self.source_id} -{self.relation_type}-> {self.target_id}"
