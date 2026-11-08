"""The ONLY file that touches your Day 1-6 code. Edit the imports/bodies to match your repo.

Everything else in Day 7 is written against this small interface, so you adapt once
instead of editing the whole workflow.
"""
from dataclasses import dataclass
from typing import Callable


@dataclass
class Adapters:
    load_finding: Callable      # finding_id -> {"id", "snapshot_id", "rule_id", "resource_ref", ...}
    load_config: Callable       # snapshot_id -> normalized config dict (raw_json)
    sg_ids: Callable            # config -> set of security-group ids
    get_ai_proposal: Callable   # finding_id -> proposal dict (Day 5 output) or None
    apply_change: Callable      # (config_copy, proposal) -> new config (Day 6 simulator)
    evaluate: Callable          # config -> {"findings": [...], "paths": [...]}
    required_paths: Callable    # config -> iterable of path ids that must stay allowed
    save_simulation: Callable   # (snapshot_id, proposal, before, after, result) -> simulation id
    project_state: Callable     # project_id -> dict for build_dashboard


def default_adapters() -> Adapters:
    # TODO: replace each NotImplementedError with calls into your Day 1-6 code, e.g.
    #   from apps.security_engine.services import analyze_config
    #   from apps.simulations.services.simulator import apply_sg_change, check_paths
    #   from apps.ai_copilot.models import AIInteraction
    def todo(name):
        def _f(*a, **k):
            raise NotImplementedError(f"Wire adapters.{name} to your existing code.")
        return _f

    return Adapters(**{f: todo(f) for f in Adapters.__dataclass_fields__})
