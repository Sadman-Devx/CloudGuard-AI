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

# What the AI copilot may propose for a finding (open-to-the-world ingress rules).
ACTIONS = ("replace_ingress_source", "restrict_ingress_cidr", "remove_ingress_rule")
# Extra changes a person can simulate through the API (never proposed by the model):
#   restrict_egress_rule  narrow an egress rule open to 0.0.0.0/0 to one destination and port range
#   add_ingress_rule      allow one more source on a port range (fixes a blocked path)
#   remove_nacl_rule      delete a *deny* entry of a network ACL that covers the group's instances
#   add_nacl_allow_rule   add an allow entry to such a network ACL
EXTRA_ACTIONS = ("restrict_egress_rule", "add_ingress_rule", "remove_nacl_rule", "add_nacl_allow_rule")
ALL_ACTIONS = ACTIONS + EXTRA_ACTIONS
DIRECTIONS = ("ingress", "egress")
NACL_RULE_NUMBERS = (1, 32766)
PROTOCOLS = ("tcp", "udp", "-1")

MAX_EXPLANATION = 1500
MAX_LIST_ITEMS = 8
MAX_ITEM = 300
MAX_UNCERTAINTY = 600
MIN_PREFIX = 8
# Below this prefix a restricted CIDR is still accepted but flagged (a /8 is 16 million addresses).
WARN_PREFIX = 16

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
    new_source_security_group_id: str | None = None  # for egress changes: the destination group
    new_cidr: str | None = None  # for egress changes: the destination CIDR
    # Only used by EXTRA_ACTIONS (None otherwise, and then left out of ``as_dict``):
    allow_protocol: str | None = None  # restrict_egress_rule: protocol of the replacement rule
    allow_from_port: int | None = None
    allow_to_port: int | None = None
    acl_id: str | None = None  # NACL actions
    direction: str | None = None  # NACL actions: "ingress" | "egress"
    rule_number: int | None = None  # NACL actions

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "action": self.action,
            "security_group_id": self.security_group_id,
            "protocol": self.protocol,
            "from_port": self.from_port,
            "to_port": self.to_port,
            "new_source_security_group_id": self.new_source_security_group_id,
            "new_cidr": self.new_cidr,
        }
        for key in (
            "allow_protocol",
            "allow_from_port",
            "allow_to_port",
            "acl_id",
            "direction",
            "rule_number",
        ):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


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


def wide_cidr_warning(change: ProposedChange) -> str | None:
    """A human-readable warning when ``new_cidr`` is broader than ``/WARN_PREFIX``."""
    if not change.new_cidr:
        return None
    try:
        network = ipaddress.ip_network(change.new_cidr, strict=False)
    except ValueError:
        return None
    if network.prefixlen >= WARN_PREFIX:
        return None
    return (
        f"{change.new_cidr} is broader than /{WARN_PREFIX} ({network.num_addresses:,} addresses). "
        "Confirm it is one trusted network (office or VPN) and not a whole private range."
    )


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


def _checked_cidr(value: Any, what: str, errors: list[str]) -> str | None:
    """An IPv4 CIDR that is neither the whole internet nor absurdly wide."""
    try:
        network = ipaddress.ip_network(str(value), strict=False)
        if network.version != 4 or str(network) == WORLD_CIDR or network.prefixlen < MIN_PREFIX:
            raise ValueError
        return str(network)
    except ValueError:
        errors.append(f"{what} must be an IPv4 CIDR narrower than /{MIN_PREFIX} and not {WORLD_CIDR}.")
        return None


def _port_range(raw: dict, prefix: str, errors: list[str]) -> tuple[int | None, int | None]:
    shorthand = raw.get(f"{prefix}port")
    low = _int_port(raw.get(f"{prefix}from_port", shorthand))
    high = _int_port(raw.get(f"{prefix}to_port", shorthand))
    if low is None or high is None or low > high:
        errors.append(f"{prefix}port (or {prefix}from_port/{prefix}to_port) must be valid ports in 0-65535.")
        return None, None
    return low, high


def _world_egress_covers(sg: SecurityGroup, protocol: str, low: int | None, high: int | None) -> bool:
    for rule in sg.egress:
        if rule.cidr != WORLD_CIDR:
            continue
        if rule.protocol == "-1":
            return True
        if rule.protocol == protocol and None not in (rule.from_port, rule.to_port, low, high):
            if rule.from_port <= low and high <= rule.to_port:
                return True
    return False


def _acl_in_scope(config: NetworkConfig, acl_subnets: tuple[str, ...], sg_id: str) -> bool:
    """A network ACL may only be changed through a group if it covers one of that group's instances."""
    return any(i.subnet_id in acl_subnets and sg_id in i.security_group_ids for i in config.instances)


def _validate_extended(raw: dict, config: NetworkConfig, finding_sg_id: str) -> ProposedChange:
    errors: list[str] = []
    action = raw["action"]
    sg = _find_group(config, raw.get("security_group_id"))
    if sg is None:
        errors.append("security_group_id does not exist in this snapshot.")
    elif sg.id != finding_sg_id:
        errors.append(f"A proposal for this finding may only change {finding_sg_id}.")

    new_sg = raw.get("new_source_security_group_id") or None
    new_cidr = raw.get("new_cidr") or None
    fields: dict[str, Any] = {"action": action, "security_group_id": sg.id if sg else None}

    def destination(label: str) -> None:
        """Exactly one of new_cidr / new_source_security_group_id."""
        nonlocal new_sg, new_cidr
        if bool(new_sg) == bool(new_cidr):
            errors.append(
                f"{action} needs exactly one of new_cidr or new_source_security_group_id ({label})."
            )
            new_sg = new_cidr = None
            return
        if new_cidr:
            new_cidr = _checked_cidr(new_cidr, "new_cidr", errors)
        else:
            other = _find_group(config, new_sg)
            if other is None:
                errors.append("new_source_security_group_id does not exist in this snapshot.")
                new_sg = None
            elif sg is not None and other.vpc_id != sg.vpc_id:
                errors.append("new_source_security_group_id must be in the same VPC.")
                new_sg = None

    protocol = raw.get("protocol")
    low = high = None

    if action in ("restrict_egress_rule", "add_ingress_rule"):
        if protocol not in PROTOCOLS or (action == "add_ingress_rule" and protocol == "-1"):
            allowed = PROTOCOLS if action == "restrict_egress_rule" else ("tcp", "udp")
            errors.append(f"protocol must be one of {', '.join(allowed)}.")
        elif protocol in ("tcp", "udp"):
            low, high = _port_range(raw, "", errors)

    if action == "restrict_egress_rule":
        destination("destination")
        allow_protocol = raw.get("allow_protocol")
        if allow_protocol not in ("tcp", "udp"):
            errors.append("allow_protocol must be tcp or udp.")
        elif protocol in ("tcp", "udp") and allow_protocol != protocol:
            errors.append(
                "allow_protocol must match protocol unless the rule being narrowed is all-traffic (-1)."
            )
        a_low, a_high = _port_range(raw, "allow_", errors)
        if low is not None and None not in (a_low, a_high) and not (low <= a_low and a_high <= high):
            errors.append("The allowed ports must lie inside the ports of the rule being narrowed.")
        if (
            sg is not None
            and protocol in PROTOCOLS
            and not errors
            and not _world_egress_covers(sg, protocol, low, high)
        ):
            errors.append(
                "No egress rule open to 0.0.0.0/0 matches the proposed protocol/ports, "
                "so there is nothing to narrow."
            )
        fields.update(allow_protocol=allow_protocol, allow_from_port=a_low, allow_to_port=a_high)
    elif action == "add_ingress_rule":
        destination("source")
        if sg is not None and not errors:
            for rule in sg.ingress:
                if (rule.protocol, rule.from_port, rule.to_port, rule.cidr, rule.peer_security_group_id) == (
                    protocol,
                    low,
                    high,
                    new_cidr,
                    new_sg,
                ):
                    errors.append("An identical ingress rule already exists.")
                    break
    else:  # NACL actions
        direction = raw.get("direction")
        if direction not in DIRECTIONS:
            errors.append(f"direction must be one of {', '.join(DIRECTIONS)}.")
        acl = next((a for a in config.network_acls if a.id == raw.get("acl_id")), None)
        if acl is None:
            errors.append("acl_id does not exist in this snapshot.")
        elif sg is not None and not _acl_in_scope(config, acl.subnet_ids, sg.id):
            errors.append(f"{acl.id} does not cover any instance that uses {sg.id}.")
        number = raw.get("rule_number")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not NACL_RULE_NUMBERS[0] <= number <= NACL_RULE_NUMBERS[1]
        ):
            errors.append(
                f"rule_number must be an integer from {NACL_RULE_NUMBERS[0]} to {NACL_RULE_NUMBERS[1]}."
            )
        entries = ()
        if acl is not None and direction in DIRECTIONS:
            entries = acl.ingress if direction == "ingress" else acl.egress
        existing = next((e for e in entries if e.rule_number == number), None)
        if action == "remove_nacl_rule":
            if acl is not None and direction in DIRECTIONS and isinstance(number, int):
                if existing is None:
                    errors.append(f"{acl.id} has no {direction} rule number {number}.")
                elif existing.action != "deny":
                    errors.append(
                        "Only deny entries can be removed; removing an allow entry would close access."
                    )
                else:
                    protocol, low, high = existing.protocol, existing.from_port, existing.to_port
                    new_cidr = None
        else:  # add_nacl_allow_rule
            if protocol not in ("tcp", "udp"):
                errors.append("protocol must be tcp or udp.")
            else:
                low, high = _port_range(raw, "", errors)
            if new_sg:
                errors.append("add_nacl_allow_rule takes new_cidr, not a security group.")
            new_cidr = _checked_cidr(new_cidr, "new_cidr", errors)
            new_sg = None
            if existing is not None:
                errors.append(f"{acl.id} already has a {direction} rule number {number}.")
        fields.update(acl_id=raw.get("acl_id"), direction=direction, rule_number=number)

    if errors:
        raise ProposalError(errors)
    return ProposedChange(
        action=action,
        security_group_id=sg.id,
        protocol=protocol,
        from_port=low,
        to_port=high,
        new_source_security_group_id=new_sg,
        new_cidr=new_cidr,
        **{k: v for k, v in fields.items() if k not in ("action", "security_group_id")},
    )


def validate_change(
    raw: Any, config: NetworkConfig, finding_sg_id: str, *, allowed: tuple[str, ...] = ACTIONS
) -> ProposedChange:
    """Validate one proposed change. Raises ``ProposalError`` listing every problem found.

    ``allowed`` is the set of actions accepted from this caller: the AI copilot gets ``ACTIONS``;
    the simulation API passes ``ALL_ACTIONS`` for changes a person built by hand.
    """
    if not isinstance(raw, dict):
        raise ProposalError(["proposed_change must be an object or null."])
    errors: list[str] = []

    action = raw.get("action")
    if action in EXTRA_ACTIONS and action in allowed:
        return _validate_extended(raw, config, finding_sg_id)
    if action not in ACTIONS or action not in allowed:
        errors.append(f"action must be one of {', '.join(allowed)}.")

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
        else:
            warning = wide_cidr_warning(change)
            if warning and len(assumptions) < MAX_LIST_ITEMS:
                assumptions.append(warning)

    if errors:
        raise ProposalError(errors)
    return Answer(explanation or "", change, tuple(assumptions), uncertainty or "")
