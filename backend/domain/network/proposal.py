"""Validation of AI-generated remediation proposals (roadmap section 10, guardrails 3-6).

Pure Python: no Django, no DB. The LLM output is untrusted, so we whitelist actions,
whitelist keys, and check every reference against the real snapshot.
"""
import ipaddress

ALLOWED_ACTIONS = {"replace_ingress_source", "remove_ingress_rule", "restrict_ingress_cidr"}
ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp", "-1"}
ALLOWED_KEYS = {
    "action", "security_group_id", "protocol", "port",
    "new_source_security_group_id", "new_cidr",
}


class ProposalError(ValueError):
    """Raised when a proposal is malformed, unsupported, or references unknown resources."""


def validate_proposal(raw, known_sg_ids):
    if not isinstance(raw, dict):
        raise ProposalError("Proposal must be a JSON object.")

    extra = set(raw) - ALLOWED_KEYS
    if extra:
        raise ProposalError(f"Unsupported fields in proposal: {sorted(extra)}")

    action = raw.get("action")
    if action not in ALLOWED_ACTIONS:
        raise ProposalError(f"Unsupported action: {action!r}")

    sg_id = raw.get("security_group_id")
    if sg_id not in known_sg_ids:
        raise ProposalError(f"Unknown security group: {sg_id!r}")

    protocol = raw.get("protocol")
    if protocol not in ALLOWED_PROTOCOLS:
        raise ProposalError(f"Unsupported protocol: {protocol!r}")

    port = raw.get("port")
    if protocol in ("tcp", "udp"):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ProposalError(f"Invalid port: {port!r}")

    clean = {"action": action, "security_group_id": sg_id, "protocol": protocol, "port": port}

    if action == "replace_ingress_source":
        new_sg = raw.get("new_source_security_group_id")
        if new_sg not in known_sg_ids:
            raise ProposalError(f"Unknown source security group: {new_sg!r}")
        clean["new_source_security_group_id"] = new_sg

    elif action == "restrict_ingress_cidr":
        try:
            net = ipaddress.ip_network(raw.get("new_cidr"), strict=False)
        except (ValueError, TypeError):
            raise ProposalError(f"Invalid CIDR: {raw.get('new_cidr')!r}")
        if net.version != 4:
            raise ProposalError("Only IPv4 CIDRs are supported.")
        if net.prefixlen == 0:
            raise ProposalError("A proposal must narrow access, not open it to 0.0.0.0/0.")
        clean["new_cidr"] = str(net)

    return clean
