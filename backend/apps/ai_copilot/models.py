from django.db import models

from apps.projects.models import Project
from apps.security_engine.models import SecurityFinding


class AIInteraction(models.Model):
    """One explanation request. Stores the validated answer and usage, never credentials or prompts."""

    class Source(models.TextChoices):
        META_MODEL = "meta_model", "Meta model"
        OFFLINE_DEMO = "offline_demo", "Offline demo provider"
        FALLBACK = "deterministic_fallback", "Deterministic fallback"

    class Status(models.TextChoices):
        OK = "ok", "OK"
        FALLBACK = "fallback", "Fallback"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="ai_interactions")
    finding = models.ForeignKey(SecurityFinding, on_delete=models.CASCADE, related_name="ai_interactions")
    provider = models.CharField(max_length=16)
    model_id = models.CharField(max_length=128, blank=True)
    source = models.CharField(max_length=32, choices=Source.choices)
    status = models.CharField(max_length=16, choices=Status.choices)
    prompt_version = models.CharField(max_length=16)
    response_json = models.JSONField(default=dict)
    fallback_reason = models.TextField(blank=True)
    attempts = models.PositiveSmallIntegerField(default=1)
    latency_ms = models.PositiveIntegerField(default=0)
    usage = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["finding", "-id"]), models.Index(fields=["provider", "created_at"])]

    def __str__(self) -> str:
        return f"{self.provider}:{self.status} finding={self.finding_id}"