from django.db import models


class Project(models.Model):
    """A workspace that groups immutable configuration snapshots."""

    name = models.CharField(max_length=120)
    description = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return self.name
