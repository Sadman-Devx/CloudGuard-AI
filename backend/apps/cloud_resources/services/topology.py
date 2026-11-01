"""Topology read service: rebuild the graph from a snapshot's stored, validated input."""

from __future__ import annotations

from typing import Any

from domain.network.schema import ConfigValidationError, parse_config
from domain.network.topology import build_topology

from ..models import ConfigurationSnapshot


class SnapshotIncompatible(Exception):
    """The stored input no longer validates (e.g. the schema changed after it was imported)."""

    def __init__(self, errors: list[dict[str, str]]):
        super().__init__("Stored snapshot no longer validates against the current schema.")
        self.errors = errors


def snapshot_topology(snapshot: ConfigurationSnapshot) -> dict[str, Any]:
    """Return the serialisable topology for ``snapshot``.

    The graph is derived deterministically from ``raw_json`` (immutable), so it always matches the
    stored input and needs no extra tables.
    """
    try:
        config = parse_config(snapshot.raw_json)
    except ConfigValidationError as exc:
        raise SnapshotIncompatible([issue.as_dict() for issue in exc.errors]) from exc
    topology = build_topology(config).as_dict()
    return {
        "snapshot": snapshot.id,
        "project": snapshot.project_id,
        "version": snapshot.version,
        "name": snapshot.name,
        "region": snapshot.region,
        **topology,
    }