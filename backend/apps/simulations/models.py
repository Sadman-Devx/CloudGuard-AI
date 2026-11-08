from django.db import models

from apps.ai_copilot.models import AIInteraction
from apps.cloud_resources.models import ConfigurationSnapshot
from apps.security_engine.models import SecurityFinding


class Simulation(models.Model):
    """One what-if run: a proposed security-group change evaluated on a clone of a snapshot.

    Nothing here ever touches the snapshot (it is immutable) or any cloud account. A simulation is
    a record of evidence, so it is write-once: re-running creates a new row.
    """

    class Status(models.TextChoices):
        COMPLETED = "completed", "Completed"

    snapshot = models.ForeignKey(ConfigurationSnapshot, on_delete=models.CASCADE, related_name="simulations")
    finding = models.ForeignKey(
        SecurityFinding, null=True, blank=True, on_delete=models.SET_NULL, related_name="simulations"
    )
    ai_interaction = models.ForeignKey(
        AIInteraction, null=True, blank=True, on_delete=models.SET_NULL, related_name="simulations"
    )
    engine_version = models.CharField(max_length=16)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.COMPLETED)
    outcome = models.CharField(max_length=40)
    recommended = models.BooleanField(default=False)
    proposed_change_json = models.JSONField()
    required_paths_json = models.JSONField(default=list)
    before_json = models.JSONField(default=dict)
    after_json = models.JSONField(default=dict)
    result_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["snapshot", "-id"])]

    def __str__(self) -> str:
        return f"simulation {self.pk} of snapshot {self.snapshot_id}: {self.outcome}"

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Simulations are immutable; run a new simulation instead.")
        super().save(*args, **kwargs)