"""Run a simulation for a snapshot and persist the evidence.

Nothing is applied anywhere. The proposed change is *re-validated here* against the stored
configuration no matter where it came from (a person, or an earlier model answer): neither the
client nor the model is trusted.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from apps.ai_copilot.models import AIInteraction
from apps.cloud_resources.models import ConfigurationSnapshot
from apps.cloud_resources.services.topology import SnapshotIncompatible
from apps.security_engine.models import SecurityFinding
from domain.network.proposals import ProposalError, validate_change
from domain.network.reachability import QueryError, evaluate_path, validate_query
from domain.network.schema import ConfigValidationError, NetworkConfig, parse_config
from domain.network.simulation import SIMULATION_VERSION, SimulationError, parse_required_paths, simulate

from ..models import Simulation

__all__ = [
    "SimulationInputError",
    "SnapshotIncompatible",
    "check_path",
    "run_simulation",
    "simulation_snapshot_config",
]


class SimulationInputError(Exception):
    """The request referred to something invalid. ``errors`` maps a request field to messages."""

    def __init__(self, errors: dict[str, list[str]]):
        super().__init__("Simulation request is invalid.")
        self.errors = errors


def simulation_snapshot_config(snapshot: ConfigurationSnapshot) -> NetworkConfig:
    try:
        return parse_config(snapshot.raw_json)
    except ConfigValidationError as exc:
        raise SnapshotIncompatible([issue.as_dict() for issue in exc.errors]) from exc


def check_path(snapshot: ConfigurationSnapshot, raw_query: Any) -> dict[str, Any]:
    """Answer one reachability question against the stored (unmodified) configuration."""
    config = simulation_snapshot_config(snapshot)
    try:
        query = validate_query(raw_query, config)
    except QueryError as exc:
        raise SimulationInputError({"path": exc.errors}) from exc
    return evaluate_path(config, query).as_dict()


def _path_identity(connectivity_entry: dict[str, Any]) -> dict[str, Any]:
    keys = ("key", "source", "source_ip", "destination", "protocol", "port")
    return {k: connectivity_entry[k] for k in keys}


def run_simulation(
    snapshot: ConfigurationSnapshot,
    *,
    proposed_change: Any = None,
    finding: SecurityFinding | None = None,
    interaction: AIInteraction | None = None,
    required_paths: Any = None,
) -> Simulation:
    config = simulation_snapshot_config(snapshot)

    if interaction is not None:
        if interaction.finding.snapshot_id != snapshot.id:
            raise SimulationInputError(
                {"interaction_id": ["That explanation belongs to a different snapshot."]}
            )
        proposed_change = (interaction.response_json or {}).get("proposed_change")
        if proposed_change is None:
            raise SimulationInputError(
                {"interaction_id": ["That explanation did not include a proposed change."]}
            )
        if finding is None:
            finding = interaction.finding
        elif finding.id != interaction.finding_id:
            raise SimulationInputError(
                {"finding_id": ["finding_id does not match the explanation's finding."]}
            )

    if finding is not None:
        if finding.snapshot_id != snapshot.id:
            raise SimulationInputError({"finding_id": ["That finding belongs to a different snapshot."]})
        if finding.resource_type != "security_group":
            raise SimulationInputError({"finding_id": ["Only security-group findings can be simulated."]})
        expected_group = finding.resource_id
    else:
        raw_group = proposed_change.get("security_group_id") if isinstance(proposed_change, dict) else None
        expected_group = raw_group if isinstance(raw_group, str) else ""

    try:
        change = validate_change(proposed_change, config, expected_group)
    except ProposalError as exc:
        raise SimulationInputError({"proposed_change": exc.errors}) from exc

    try:
        required = parse_required_paths(required_paths, config)
    except SimulationError as exc:
        raise SimulationInputError({"required_paths": exc.errors}) from exc
    try:
        result = simulate(config, change, required)
    except SimulationError as exc:
        raise SimulationInputError({"proposed_change": exc.errors}) from exc

    payload = result.as_dict()
    effective_required = [_path_identity(c) for c in result.connectivity if c["required"]]
    with transaction.atomic():
        return Simulation.objects.create(
            snapshot=snapshot,
            finding=finding,
            ai_interaction=interaction,
            engine_version=SIMULATION_VERSION,
            outcome=result.outcome,
            recommended=result.recommended,
            proposed_change_json=change.as_dict(),
            required_paths_json=effective_required,
            before_json=result.before,
            after_json=result.after,
            result_json=payload,
        )