from django.db import models

from apps.cloud_resources.models import ConfigurationSnapshot
from domain.network.rules import SEVERITIES


class AnalysisRun(models.Model):
    """The latest deterministic analysis of a snapshot.

    Separate from the findings so "never analysed" and "analysed, nothing found" are different
    states. Re-running replaces the previous run and its findings.
    """

    snapshot = models.OneToOneField(ConfigurationSnapshot, on_delete=models.CASCADE, related_name="analysis")
    rules_version = models.CharField(max_length=16)
    summary = models.JSONField(default=dict)
    ran_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"analysis of snapshot {self.snapshot_id}"


class SecurityFinding(models.Model):
    snapshot = models.ForeignKey(ConfigurationSnapshot, on_delete=models.CASCADE, related_name="findings")
    rule_id = models.CharField(max_length=16)
    severity = models.CharField(max_length=16, choices=[(s, s.title()) for s in SEVERITIES])
    category = models.CharField(max_length=32)
    title = models.CharField(max_length=200)
    resource_type = models.CharField(max_length=32)
    resource_id = models.CharField(max_length=64)
    resource_name = models.CharField(max_length=256, blank=True)
    summary = models.TextField()
    evidence = models.JSONField(default=dict)
    remediation = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "rule_id", "resource_id"], name="uniq_finding_snapshot_rule_resource"
            )
        ]
        indexes = [models.Index(fields=["snapshot", "severity"])]

    def __str__(self) -> str:
        return f"{self.rule_id} {self.resource_id}"