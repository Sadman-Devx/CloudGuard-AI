"""Rule-based answer built only from the prompt payload.

Used (a) by the offline ``mock`` provider and (b) as the fallback when the model call fails or
returns something invalid, so the user still gets a grounded explanation. It is always labelled
as non-Meta in the API and UI.
"""

from __future__ import annotations

from typing import Any


def answer_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    finding = payload["finding"]
    sg_id = finding["security_group_id"]
    rule_id = finding["rule_id"]
    port = finding.get("port")
    exposure = finding.get("exposure")

    context = {
        "internet_facing_candidate": "An attached instance has a public IP in a public subnet, so it may be "
        "reachable from the internet (not verified).",
        "no_public_path": "No attached instance has both a public IP and a public subnet, so no direct "
        "internet path is visible in the modelled configuration.",
        "unattached": "No instance currently uses this group, so the rule has no effect yet.",
    }.get(exposure, "")

    proposal = None
    assumptions: list[str] = []
    uncertainty = (
        "Only security-group rules and instance placement were analysed; routes, NACLs and host firewalls "
        "are not part of this finding."
    )

    if rule_id in ("SG-001", "SG-002") and port:
        service = finding.get("service") or f"port {port}"
        explanation = (
            f"{sg_id} lets anyone on the internet try to connect to {service} (tcp/{port}). Administration "
            f"ports are a common target for password guessing. {context} Remove the 0.0.0.0/0 rule and "
            "reach the instance through a bastion, VPN or Session Manager instead."
        )
        proposal = _proposal("remove_ingress_rule", sg_id, port)
        assumptions.append(
            "Administrators can use a bastion host, VPN or Session Manager instead of open access."
        )
    elif rule_id in ("SG-003", "SG-004") and port:
        service = finding.get("service") or f"port {port}"
        explanation = (
            f"{sg_id} accepts {service} (tcp/{port}) connections from any address. A database should only "
            f"accept traffic from the application tier. {context}"
        )
        candidates = [
            c
            for c in payload["candidate_source_groups"]
            if c["attached_instance_count"] > 0 and not c["internet_facing"]
        ]
        if len(candidates) == 1:
            source = candidates[0]
            proposal = _proposal("replace_ingress_source", sg_id, port, new_sg=source["id"])
            assumptions.append(f"Application traffic to the database originates from {source['id']}.")
            explanation += f" Replace the 0.0.0.0/0 source with {source['id']}."
        else:
            explanation += (
                " More than one security group could be the application tier, so a person has to choose "
                "the source; no change is proposed automatically."
            )
            assumptions.append(
                "It is unknown which security group hosts the application that needs the database."
            )
    elif rule_id == "SG-005":
        explanation = (
            f"{sg_id} allows all traffic from anywhere, which also opens administration and database "
            f"ports. {context} Replace the catch-all rule with one rule per needed port, each limited to "
            "the narrowest source."
        )
        assumptions.append("The services that need to be reachable are not known from the configuration.")
    else:
        explanation = (
            f"{sg_id} allows all outbound traffic. This is the AWS default and is often intentional, but it "
            "lets a compromised instance reach any destination. Restrict it to the destinations the "
            "workload needs if you can."
        )
        assumptions.append("The outbound destinations the workload needs are not known.")

    return {
        "explanation": explanation,
        "proposed_change": proposal,
        "assumptions": assumptions,
        "uncertainty": uncertainty,
    }


def _proposal(action: str, sg_id: str, port: int, new_sg: str | None = None) -> dict[str, Any]:
    return {
        "action": action,
        "security_group_id": sg_id,
        "protocol": "tcp",
        "from_port": port,
        "to_port": port,
        "new_source_security_group_id": new_sg,
        "new_cidr": None,
    }