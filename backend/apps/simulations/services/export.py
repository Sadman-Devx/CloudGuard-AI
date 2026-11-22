"""Fix-as-code: turn a verified simulation into something a person can review and apply.

Three renderings of the same change (never executed by CloudGuard):

* ``aws-cli``    a shell script: add the new access first, then remove the old, verify, and a rollback;
* ``terraform``  a unified-diff-style patch for the security-group / network-ACL resources;
* ``pr``         a pull-request description: why, the change, the digital-twin evidence, both of the
                 above and a checklist.

Everything that reaches the output (ids, CIDRs, ports, protocols) is checked against strict patterns
first, because it ends up in a shell command: a value that does not match is refused, not escaped.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from domain.network.scoring import compare_summaries

FORMATS = ("aws-cli", "terraform", "pr")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_AWS_SG = re.compile(r"^sg-[0-9a-f]{8,17}$")
_AWS_ACL = re.compile(r"^acl-[0-9a-f]{8,17}$")
_FILENAMES = {
    "aws-cli": "fix-simulation-{id}.sh",
    "terraform": "fix-simulation-{id}.diff",
    "pr": "pr-simulation-{id}.md",
}


class ExportError(ValueError):
    pass


def _ident(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.match(value):
        raise ExportError(f"{what} '{value}' contains characters that are not safe to put in a command.")
    return value


def _cidr(value: Any) -> str:
    try:
        return str(ipaddress.ip_network(str(value), strict=False))
    except ValueError as exc:
        raise ExportError(f"'{value}' is not a valid CIDR.") from exc


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -1 <= value <= 65535:
        raise ExportError(f"'{value}' is not a valid port.")
    return value


def _protocol(value: Any) -> str:
    if value not in ("tcp", "udp", "icmp", "-1"):
        raise ExportError(f"'{value}' is not a supported protocol.")
    return value


# ---------------------------------------------------------------------------------- AWS CLI
def _ip_permission(rule: dict[str, Any]) -> str:
    protocol = _protocol(rule["protocol"])
    parts = [f"IpProtocol={protocol}"]
    if protocol != "-1" and rule.get("from_port") is not None:
        parts += [f"FromPort={_port(rule['from_port'])}", f"ToPort={_port(rule['to_port'])}"]
    if rule.get("peer_security_group_id"):
        parts.append(
            f"UserIdGroupPairs=[{{GroupId={_ident(rule['peer_security_group_id'], 'Security group id')}}}]"
        )
    elif ":" in str(rule.get("cidr")):
        parts.append(f"Ipv6Ranges=[{{CidrIpv6={_cidr(rule['cidr'])}}}]")
    else:
        parts.append(f"IpRanges=[{{CidrIp={_cidr(rule['cidr'])}}}]")
    return ",".join(parts)


def _nacl_flags(direction: str) -> str:
    return "--egress" if direction == "egress" else "--ingress"


def _sg_command(verb: str, sg: str, direction: str, rule: dict[str, Any], region: str) -> str:
    return (
        f"aws ec2 {verb}-security-group-{direction} --group-id {_ident(sg, 'Security group id')} "
        f"--ip-permissions '{_ip_permission(rule)}' --region {region}"
    )


def _nacl_command(verb: str, acl: str, direction: str, entry: dict[str, Any], region: str) -> str:
    acl_id = _ident(acl, "Network ACL id")
    base = f"aws ec2 {verb}-network-acl-entry --network-acl-id {acl_id} {_nacl_flags(direction)}"
    number = int(entry["rule_number"])
    if verb == "delete":
        return f"{base} --rule-number {number} --region {region}"
    protocol = _protocol(entry["protocol"])
    command = f"{base} --rule-number {number} --protocol {protocol}"
    if protocol in ("tcp", "udp") and entry.get("from_port") is not None:
        command += f" --port-range From={_port(entry['from_port'])},To={_port(entry['to_port'])}"
    return f"{command} --cidr-block {_cidr(entry['cidr'])} --rule-action {entry['action']} --region {region}"


def _commands(mods: list[dict[str, Any]], region: str) -> tuple[list[str], list[str], list[str]]:
    """(add, remove, rollback) commands. Adding comes first so access is never missing in between."""
    add: list[str] = []
    remove: list[str] = []
    rollback: list[str] = []
    for mod in mods:
        direction = mod.get("direction") or "ingress"
        before, after = mod.get("before"), mod.get("after")
        if mod.get("network_acl"):
            acl = mod["network_acl"]
            if after:
                add.append(
                    _nacl_command(
                        "create", acl, direction, {**after, "rule_number": after["rule_number"]}, region
                    )
                )
                rollback.append(_nacl_command("delete", acl, direction, after, region))
            if before:
                remove.append(_nacl_command("delete", acl, direction, before, region))
                rollback.append(_nacl_command("create", acl, direction, before, region))
        else:
            sg = mod["security_group"]
            if after:
                add.append(_sg_command("authorize", sg, direction, after, region))
                rollback.append(_sg_command("revoke", sg, direction, after, region))
            if before:
                remove.append(_sg_command("revoke", sg, direction, before, region))
                rollback.append(_sg_command("authorize", sg, direction, before, region))
    return add, remove, rollback


def _aws_cli(ctx: dict[str, Any]) -> str:
    add, remove, rollback = _commands(ctx["mods"], ctx["region"])
    sgs = sorted({m["security_group"] for m in ctx["mods"] if not m.get("network_acl")})
    lines = [
        "#!/usr/bin/env bash",
        f"# CloudGuard AI - proposed fix from simulation #{ctx['id']} (outcome: {ctx['outcome']})",
        "# Verified only on a digital twin of the imported snapshot. CloudGuard never runs this.",
        "# Review every line, run it with a role that may change security groups / network ACLs.",
        "set -euo pipefail",
        "",
    ]
    if add:
        lines += ["# 1. Add the new access first, so nothing that must keep working is cut off", *add, ""]
    if remove:
        lines += ["# 2. Remove the old, too-broad access", *remove, ""]
    if sgs:
        lines += [
            "# 3. Verify",
            *(
                f"aws ec2 describe-security-groups --group-ids {_ident(sg, 'Security group id')} "
                f"--region {ctx['region']} "
                "--query 'SecurityGroups[].[GroupId,IpPermissions,IpPermissionsEgress]'"
                for sg in sgs
            ),
            "",
        ]
    lines += ["# Rollback (run only if something breaks)", *(f"# {c}" for c in rollback)]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------- Terraform
def _tf_address(ctx: dict[str, Any], sg_id: str) -> tuple[str, bool]:
    """(resource address, confident). IaC imports use the address itself as the id."""
    match = re.match(r"^(aws_security_group\.[A-Za-z0-9_-]+)", sg_id)
    if match:
        return match.group(1), True
    slug = re.sub(r"[^a-z0-9_]+", "_", (ctx["sg_names"].get(sg_id) or sg_id).lower()).strip("_") or "sg"
    return f"aws_security_group.{slug}", False


def _tf_ref(sg_id: str) -> str:
    match = re.match(r"^(aws_security_group\.[A-Za-z0-9_-]+)", sg_id)
    return f"{match.group(1)}.id" if match else f'"{_ident(sg_id, "Security group id")}"'


def _tf_rule_block(kind: str, rule: dict[str, Any], indent: str = "  ") -> list[str]:
    protocol = _protocol(rule["protocol"])
    low = rule.get("from_port") if protocol != "-1" and rule.get("from_port") is not None else 0
    high = rule.get("to_port") if protocol != "-1" and rule.get("to_port") is not None else 0
    lines = [
        f"{indent}{kind} {{",
        f"{indent}  from_port = {_port(low)}",
        f"{indent}  to_port   = {_port(high)}",
        f'{indent}  protocol  = "{protocol}"',
    ]
    if rule.get("peer_security_group_id"):
        lines.append(f"{indent}  security_groups = [{_tf_ref(rule['peer_security_group_id'])}]")
    elif ":" in str(rule.get("cidr")):
        lines.append(f'{indent}  ipv6_cidr_blocks = ["{_cidr(rule["cidr"])}"]')
    else:
        lines.append(f'{indent}  cidr_blocks = ["{_cidr(rule["cidr"])}"]')
    lines.append(f"{indent}}}")
    return lines


def _tf_nacl_block(acl: str, direction: str, entry: dict[str, Any]) -> list[str]:
    protocol = _protocol(entry["protocol"])
    name = re.sub(r"[^A-Za-z0-9_]+", "_", f"{acl}_{direction}_{entry['rule_number']}")
    lines = [
        f'resource "aws_network_acl_rule" "{name}" {{',
        f"  network_acl_id = {_tf_acl_ref(acl)}",
        f"  rule_number    = {int(entry['rule_number'])}",
        f"  egress         = {'true' if direction == 'egress' else 'false'}",
        f'  protocol       = "{protocol}"',
        f'  rule_action    = "{entry["action"]}"',
        f'  cidr_block     = "{_cidr(entry["cidr"])}"',
    ]
    if protocol in ("tcp", "udp") and entry.get("from_port") is not None:
        lines += [
            f"  from_port      = {_port(entry['from_port'])}",
            f"  to_port        = {_port(entry['to_port'])}",
        ]
    return [*lines, "}"]


def _tf_acl_ref(acl: str) -> str:
    match = re.match(r"^(aws_network_acl\.[A-Za-z0-9_-]+)", acl)
    return f"{match.group(1)}.id" if match else f'"{_ident(acl, "Network ACL id")}"'


def _terraform(ctx: dict[str, Any]) -> str:
    out = [
        f"# CloudGuard AI - Terraform patch from simulation #{ctx['id']}",
        "# Illustrative: edit the files that define these resources in YOUR repository. If your rules are",
        "# separate aws_vpc_security_group_*_rule resources, change those resources instead.",
        "",
    ]
    by_sg: dict[str, list[dict[str, Any]]] = {}
    for mod in ctx["mods"]:
        if mod.get("network_acl"):
            continue
        by_sg.setdefault(mod["security_group"], []).append(mod)
    for sg_id, mods in by_sg.items():
        address, confident = _tf_address(ctx, sg_id)
        resource_type, _, resource_name = address.partition(".")
        out += [
            f"--- a/<file defining {address}>",
            f"+++ b/<file defining {address}>",
            f'@@ resource "{resource_type}" "{resource_name}" ({sg_id}) @@',
        ]
        if not confident:
            out.append(f"# address guessed from the group name; confirm it: {address}")
        for mod in mods:
            kind = mod.get("direction") or "ingress"
            for rule in [mod["before"]] if mod.get("before") else []:
                out += [f"-{line}" for line in _tf_rule_block(kind, rule)]
            for rule in [mod["after"]] if mod.get("after") else []:
                out += [f"+{line}" for line in _tf_rule_block(kind, rule)]
        out.append("")
    for mod in ctx["mods"]:
        if not mod.get("network_acl"):
            continue
        direction = mod.get("direction") or "ingress"
        out += [f"--- a/<file defining {mod['network_acl']}>", f"+++ b/<file defining {mod['network_acl']}>"]
        if mod.get("before"):
            out += [f"-{line}" for line in _tf_nacl_block(mod["network_acl"], direction, mod["before"])]
        if mod.get("after"):
            out += [f"+{line}" for line in _tf_nacl_block(mod["network_acl"], direction, mod["after"])]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------------- PR text
_OUTCOMES = {
    "improves_security": "improves security",
    "fixes_connectivity": "fixes a blocked path without opening anything new",
    "no_effect": "has no effect",
    "introduces_new_risk": "introduces new risk",
    "breaks_required_connectivity": "BREAKS required connectivity",
    "required_connectivity_unmet": "does not meet the required connectivity",
    "inconclusive": "is inconclusive",
}
_CHANGES = {
    "lost": "now blocked",
    "newly_allowed": "newly allowed",
    "still_allowed": "unchanged (allowed)",
    "still_blocked": "unchanged (blocked)",
    "preserved": "preserved",
    "inconclusive": "could not be determined",
}


def _title(change: dict[str, Any]) -> str:
    sg = change.get("security_group_id", "?")
    action = change.get("action")
    port = change.get("from_port")
    ports = f"{change.get('protocol')}/{port}" if port is not None else "all traffic"
    if action == "restrict_ingress_cidr":
        return f"restrict {ports} on {sg} to {change.get('new_cidr')}"
    if action == "replace_ingress_source":
        return f"limit {ports} on {sg} to {change.get('new_source_security_group_id')}"
    if action == "remove_ingress_rule":
        return f"remove the internet-open {ports} rule from {sg}"
    if action == "restrict_egress_rule":
        return f"narrow outbound access of {sg}"
    if action == "add_ingress_rule":
        return f"allow {ports} into {sg}"
    return f"update network access around {sg}"


def _pr(ctx: dict[str, Any]) -> str:
    sim = ctx["simulation"]
    result = ctx["result"]
    findings = result.get("findings") or {}
    score = ctx["score"]
    lines = [
        f"# fix(security): {_title(ctx['change'])}",
        "",
        "> Verified on a digital twin of the imported configuration by CloudGuard AI. "
        "**It has not been applied to any cloud account.**",
        "",
        "## Why",
    ]
    resolved = findings.get("resolved") or []
    lines += [f"- Resolves **{f['rule_id']}** on `{f['resource_id']}`: {f['title']}" for f in resolved] or [
        "- Changes network access as described below."
    ]
    lines += ["", "## Change", *(f"- {line}" for line in result.get("summary_lines") or [])]
    lines += [
        "",
        "## Verification (digital twin)",
        f"- Outcome: this change {_OUTCOMES.get(ctx['outcome'], ctx['outcome'])}.",
    ]
    lines.append(
        f"- Recommended by the simulator: {'yes' if sim.recommended else 'no, review before applying'}."
    )
    if score:
        old, new = score["before"], score["after"]
        lines.append(f"- Security score: {old['value']} ({old['grade']}) -> {new['value']} ({new['grade']}).")
    before_summary, after_summary = (
        (findings.get("before_summary") or {}),
        (findings.get("after_summary") or {}),
    )
    if before_summary.get("total") is not None:
        lines.append(f"- Findings: {before_summary['total']} -> {after_summary.get('total')}.")
    for path in result.get("connectivity") or []:
        if path["change"] in ("still_blocked", "still_allowed") and not path.get("required"):
            continue  # unchanged paths are noise in a review
        what = _CHANGES.get(path["change"], path["change"])
        lines.append(f"- {path['label']}: {what}{' (required)' if path.get('required') else ''}")
    for warning in result.get("warnings") or []:
        lines.append(f"- Warning: {warning['message']}")
    lines += [
        "",
        "## Terraform",
        "```diff",
        _terraform(ctx).rstrip(),
        "```",
        "",
        "<details><summary>AWS CLI equivalent</summary>",
        "",
        "```bash",
        _aws_cli(ctx).rstrip(),
        "```",
        "",
        "</details>",
        "",
        "## Rollback",
        "Revert this PR (Terraform) or run the rollback commands at the end of the CLI script.",
        "",
        "## Checklist",
        "- [ ] The required paths listed above still work in a non-production environment",
        "- [ ] Someone who owns the affected workloads has approved the change",
        "- [ ] The change was applied during an agreed window",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------- entry point
def build_export(simulation, fmt: str) -> dict[str, Any]:
    if fmt not in FORMATS:
        raise ExportError(f"format must be one of {', '.join(FORMATS)}.")
    result = simulation.result_json or {}
    mods = [m for m in result.get("modifications") or [] if isinstance(m, dict)]
    if not mods or all(not m.get("before") and not m.get("after") for m in mods):
        raise ExportError("This simulation changes nothing, so there is nothing to export.")

    snapshot = simulation.snapshot
    sg_names = {g["id"]: g.get("name", "") for g in (snapshot.raw_json or {}).get("security_groups", [])}
    findings = result.get("findings") or {}
    score = None
    if isinstance(findings.get("before_summary"), dict) and isinstance(findings.get("after_summary"), dict):
        score = compare_summaries(findings["before_summary"], findings["after_summary"])

    ctx = {
        "id": simulation.pk,
        "simulation": simulation,
        "result": result,
        "mods": mods,
        "change": simulation.proposed_change_json or {},
        "region": snapshot.region,
        "outcome": simulation.outcome,
        "sg_names": sg_names,
        "score": score,
    }

    warnings: list[str] = []
    if not simulation.recommended:
        warnings.append(
            "The simulator did NOT recommend this change. Read the verification section before applying."
        )
    sg_ids = {m["security_group"] for m in mods if not m.get("network_acl")}
    acl_ids = {m["network_acl"] for m in mods if m.get("network_acl")}
    if any(not _AWS_SG.match(s) for s in sg_ids) or any(not _AWS_ACL.match(a) for a in acl_ids):
        warnings.append(
            "Some ids are not real AWS ids (they come from a sample or an IaC import), so the AWS CLI "
            "commands cannot run as they are. Replace them with the real ids or use the Terraform patch."
        )
    if snapshot.source_type in ("terraform", "cloudformation"):
        warnings.append(
            "This snapshot came from infrastructure-as-code: change the code and let your pipeline apply it; "
            "running the CLI commands by hand would cause drift."
        )

    render = {"aws-cli": _aws_cli, "terraform": _terraform, "pr": _pr}[fmt]
    return {
        "format": fmt,
        "filename": _FILENAMES[fmt].format(id=simulation.pk),
        "content": render(ctx),
        "warnings": warnings,
        "recommended": simulation.recommended,
    }
