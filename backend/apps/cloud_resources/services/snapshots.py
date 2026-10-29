"""Import service: validate -> normalize -> persist atomically."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import Max

from apps.projects.models import Project
from common.exceptions import ConfigValidationFailed
from domain.network.inventory import build_inventory
from domain.network.schema import check_json_depth, validate_config

from ..models import CloudResource, ConfigurationSnapshot, NetworkRelationship


def import_snapshot(
    project: Project,
    data: Any,
    *,
    source_type: str = ConfigurationSnapshot.SourceType.UPLOAD,
    source_name: str = "",
) -> ConfigurationSnapshot:
    """Validate ``data`` and persist it as the project's next snapshot version.

    Validation happens before any database write, and persistence is atomic, so a
    rejected upload leaves no partial rows behind. Raises ``ConfigValidationFailed``
    (rendered as HTTP 422) when the configuration is invalid.
    """
    if not check_json_depth(data, settings.MAX_JSON_DEPTH):
        raise ConfigValidationFailed(
            [
                {
                    "path": "",
                    "code": "too_deeply_nested",
                    "message": f"JSON nesting must not exceed {settings.MAX_JSON_DEPTH} levels.",
                }
            ]
        )

    result = validate_config(data)
    if not result.ok:
        raise ConfigValidationFailed([issue.as_dict() for issue in result.errors])
    config = result.config
    assert config is not None  # guaranteed by result.ok
    inventory = build_inventory(config)

    with transaction.atomic():
        # Serialize concurrent imports for the same project so versions never collide.
        Project.objects.select_for_update().get(pk=project.pk)
        latest = ConfigurationSnapshot.objects.filter(project=project).aggregate(m=Max("version"))["m"]
        snapshot = ConfigurationSnapshot.objects.create(
            project=project,
            version=(latest or 0) + 1,
            source_type=source_type,
            source_name=source_name,
            name=config.name,
            region=config.region,
            schema_version=config.schema_version,
            raw_json=data,
            warnings=[issue.as_dict() for issue in result.warnings],
            resource_counts=inventory.counts_by_type(),
            relationship_count=len(inventory.relationships),
        )
        CloudResource.objects.bulk_create(
            CloudResource(
                snapshot=snapshot,
                external_id=r.external_id,
                resource_type=r.resource_type,
                name=r.name,
                region=r.region,
                metadata=r.metadata,
            )
            for r in inventory.resources
        )
        by_external_id = {r.external_id: r for r in CloudResource.objects.filter(snapshot=snapshot)}
        NetworkRelationship.objects.bulk_create(
            NetworkRelationship(
                snapshot=snapshot,
                source=by_external_id[rel.source],
                target=by_external_id[rel.target],
                relation_type=rel.relation_type,
                metadata=rel.metadata,
            )
            for rel in inventory.relationships
        )
    return snapshot
