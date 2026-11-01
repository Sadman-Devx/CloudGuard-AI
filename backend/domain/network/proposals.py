"""Validate AI-proposed security-group changes against the actual configuration.

Pure Python (no Django). The model's output is untrusted: it is parsed into a closed set of
supported actions, then checked against the imported configuration (the security group exists,
the rule being changed really exists and is open to 0.0.0.0/0, the new source exists in the same
VPC, ...). Anything outside that subset is rejected; nothing is ever applied. A proposal is only
a *proposal*: it must be simulated (Day 6) before it is shown as a recommended fix.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from domain.network.rules import WORLD_CIDR
from domain.network.schema import NetworkConfig, SecurityGroup

ACTIONS = ("replace_ingress_source", "restrict_ingress_cidr", "remove_ingress_rule")
PROTOCOLS = ("tcp", "udp", "-1")

MAX_EXPLANATION = 1500
MAX_LIST_ITEMS = 8
MAX_ITEM = 300
MAX_UNCERTAINTY = 600
MIN_PREFIX = 8

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ProposalError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class ProposedChange:
    action: str
    security_group_id: str
    protocol: str
    from_port: int | None
    to_port: int | None
    new_source_security_group_id: str | None = None
    new_cidr: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "security_group_id": self.security_group_id,
            "protocol": self.protocol,
            "from_port": self.from_port,
            "to_port": self.to_port,
            "new_source_security_group_id": self.new_source_security_group_id,
            "new_cidr": self.new_cidr,
        }


@dataclass(frozen=True)
class Answer:
    explanation: str
    proposed_change: ProposedChange | None
    assumptions: tuple[str, ...]
    uncertainty: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "explanation": self.explanation,
            "proposed_change": self.proposed_change.as_dict() if self.proposed_change else None,
            "assumptions": list(self.assumptions),
            "uncertainty": self.uncertainty,
            "requires_simulation": True,  # always: the model cannot waive simulation
        }


def clean_text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = _CONTROL.sub("", value).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _int_port(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        return None
    return value


def _find_group(config: NetworkConfig, sg_id: Any) -> SecurityGroup | None:
    return next((sg for sg in config.security_groups if sg.id == sg_id), None)


def _world_rule_covers(sg: SecurityGroup, protocol: str, low: int | None, high: int | None) -> bool:
    for rule in sg.ingress:
        if rule.cidr != WORLD_CIDR:
            continue
        if rule.protocol == "-1":
            return True
        if rule.protocol != protocol or protocol == "-1" or low is None or high is None:
            continue
        if rule.from_port is not None and rule.to_port is not None:
            if rule.from_port <= low and high <= rule.to_port:
                return True
    return False


def validate_change(raw: Any, config: NetworkConfig, finding_sg_id: str) -> ProposedChange:
    """Validate one proposed change. Raises ``ProposalError`` listing every problem found."""
    if not isinstance(raw, dict):
        raise ProposalError(["proposed_change must be an object or null."])
    errors: list[str] = []

    action = raw.get("action")
    if action not in ACTIONS:
        errors.append(f"action must be one of {', '.join(ACTIONS)}.")

    sg_id = raw.get("security_group_id")
    sg = _find_group(config, sg_id)
    if sg is None:
        errors.append("security_group_id does not exist in this snapshot.")
    elif sg.id != finding_sg_id:
        errors.append(f"A proposal for this finding may only change {finding_sg_id}.")

    protocol = raw.get("protocol")
    if protocol not in PROTOCOLS:
        errors.append(f"protocol must be one of {', '.join(PROTOCOLS)}.")

    low = high = None
    if protocol in ("tcp", "udp"):
        shorthand = raw.get("port")
        low = _int_port(raw.get("from_port", shorthand))
        high = _int_port(raw.get("to_port", shorthand))
        if low is None or high is None or low > high:
            errors.append("tcp/udp proposals need valid port (or from_port/to_port) values in 0-65535.")
            low = high = None

    new_sg = raw.get("new_source_security_group_id")
    new_cidr = raw.get("new_cidr")

    if action == "replace_ingress_source":
        if new_cidr not in (None, ""):
            errors.append("replace_ingress_source must not set new_cidr.")
        target = _find_group(config, new_sg)
        if target is None:
            errors.append("new_source_security_group_id does not exist in this snapshot.")
        elif sg is not None and target.vpc_id != sg.vpc_id:
            errors.append("new_source_security_group_id must be in the same VPC.")
        elif sg is not None and target.id == sg.id:
            errors.append("new_source_security_group_id must differ from the group being changed.")
        new_cidr = None
    elif action == "restrict_ingress_cidr":
        if new_sg not in (None, ""):
            errors.append("restrict_ingress_cidr must not set new_source_security_group_id.")
        try:
            network = ipaddress.ip_network(str(new_cidr), strict=False)
            if network.version != 4 or str(network) == WORLD_CIDR or network.prefixlen < MIN_PREFIX:
                raise ValueError
            new_cidr = str(network)
        except ValueError:
            errors.append(f"new_cidr must be an IPv4 CIDR narrower than /{MIN_PREFIX} and not {WORLD_CIDR}.")
            new_cidr = None
        new_sg = None
    elif action == "remove_ingress_rule":
        if new_sg not in (None, "") or new_cidr not in (None, ""):
            errors.append("remove_ingress_rule must not set a new source.")
        new_sg = new_cidr = None

    if sg is not None and protocol in PROTOCOLS and not errors:
        if not _world_rule_covers(sg, protocol, low, high):
            errors.append(
                "No ingress rule open to 0.0.0.0/0 matches the proposed protocol/ports, so there is "
                "nothing to replace."
            )

    if errors:
        raise ProposalError(errors)
    return ProposedChange(
        action=action,
        security_group_id=sg.id,
        protocol=protocol,
        from_port=low,
        to_port=high,
        new_source_security_group_id=new_sg or None,
        new_cidr=new_cidr or None,
    )


def parse_answer(raw: Any, config: NetworkConfig, finding_sg_id: str) -> Answer:
    """Validate a whole model answer (explanation + optional proposal)."""
    if not isinstance(raw, dict):
        raise ProposalError(["The answer must be a JSON object."])
    errors: list[str] = []

    explanation = clean_text(raw.get("explanation"), MAX_EXPLANATION)
    if not explanation:
        errors.append("explanation is required and must be text.")

    assumptions_raw = raw.get("assumptions", [])
    assumptions: list[str] = []
    if not isinstance(assumptions_raw, list) or len(assumptions_raw) > MAX_LIST_ITEMS:
        errors.append(f"assumptions must be a list of at most {MAX_LIST_ITEMS} strings.")
    else:
        for item in assumptions_raw:
            text = clean_text(item, MAX_ITEM)
            if text is None:
                errors.append("assumptions must contain only strings.")
                break
            if text:
                assumptions.append(text)

    uncertainty = clean_text(raw.get("uncertainty", ""), MAX_UNCERTAINTY)
    if uncertainty is None:
        errors.append("uncertainty must be text.")

    change = None
    if raw.get("proposed_change") is not None:
        try:
            change = validate_change(raw["proposed_change"], config, finding_sg_id)
        except ProposalError as exc:
            errors.extend(f"proposed_change: {e}" for e in exc.errors)

    if errors:
        raise ProposalError(errors)
    return Answer(explanation or "", change, tuple(assumptions), uncertainty or "")