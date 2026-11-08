"""Day 7: AI proposal -> validation -> simulation -> before/after diff."""
import copy

from domain.network.diff import compare
from domain.network.proposal import validate_proposal


def run_for_finding(finding_id, raw_proposal, adapters):
    """Validate a proposal (given, or fetched from the AI copilot) and simulate it.

    The original snapshot config is never mutated; the simulator gets a deep copy.
    Raises LookupError if the finding/proposal is missing, ProposalError if invalid.
    """
    finding = adapters.load_finding(finding_id)
    if finding is None:
        raise LookupError(f"Finding {finding_id} not found")

    if raw_proposal is None:
        raw_proposal = adapters.get_ai_proposal(finding_id)
    if raw_proposal is None:
        raise LookupError("No proposal available. Ask the AI Copilot to explain this finding first.")

    config = adapters.load_config(finding["snapshot_id"])
    proposal = validate_proposal(raw_proposal, adapters.sg_ids(config))

    before = adapters.evaluate(config)
    new_config = adapters.apply_change(copy.deepcopy(config), proposal)
    after = adapters.evaluate(new_config)

    result = compare(before, after, set(adapters.required_paths(config)))
    result.update({"finding_id": finding_id, "proposal": proposal,
                   "before": before, "after": after})
    result["simulation_id"] = adapters.save_simulation(
        finding["snapshot_id"], proposal, before, after, result)
    return result
