export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_STYLES = {
  critical: "bg-red-700 text-white",
  high: "bg-orange-100 text-orange-900 ring-1 ring-orange-300",
  medium: "bg-amber-100 text-amber-900 ring-1 ring-amber-300",
  low: "bg-sky-100 text-sky-900 ring-1 ring-sky-300",
  info: "bg-slate-100 text-slate-700 ring-1 ring-slate-300",
};

export const CATEGORY_LABELS = {
  risky_rule: "Risky rule",
  potential_exposure: "Potential exposure",
};

export const EXPOSURE_LABELS = {
  internet_facing_candidate: "Possibly internet-facing (not verified)",
  no_public_path: "No public path visible",
  unattached: "Not attached to any instance",
};

export const portText = (rule) => {
  if (rule.protocol === "-1") return "all traffic";
  if (rule.from_port === rule.to_port)
    return `${rule.protocol}/${rule.from_port}`;
  return `${rule.protocol}/${rule.from_port}-${rule.to_port}`;
};

/** "ingress rule #2: tcp/22 from 0.0.0.0/0" */
export function describeRuleEntry(entry) {
  const preposition = entry.direction === "egress" ? "to" : "from";
  return `${entry.direction} rule #${entry.index + 1}: ${portText(entry)} ${preposition} ${entry.cidr}`;
}

export const ACTION_LABELS = {
  replace_ingress_source: "Replace the open source with a security group",
  restrict_ingress_cidr: "Restrict the source to a narrower CIDR",
  remove_ingress_rule: "Remove the rule open to 0.0.0.0/0",
  restrict_egress_rule: "Narrow an outbound rule to one destination",
  add_ingress_rule: "Allow one more source on a port",
  remove_nacl_rule: "Remove a deny entry of a network ACL",
  add_nacl_allow_rule: "Add an allow entry to a network ACL",
};

export function describeChange(change) {
  const target = `${change.security_group_id} · ${portText(change)}`;
  if (change.action === "replace_ingress_source")
    return `${target}: allow only ${change.new_source_security_group_id}`;
  if (change.action === "restrict_ingress_cidr")
    return `${target}: allow only ${change.new_cidr}`;
  if (change.action === "restrict_egress_rule")
    return `${target}: outbound only to ${change.new_cidr ?? change.new_source_security_group_id} on ${change.allow_protocol}/${change.allow_from_port}${change.allow_to_port !== change.allow_from_port ? `-${change.allow_to_port}` : ""}`;
  if (change.action === "add_ingress_rule")
    return `${target}: also allow ${change.new_cidr ?? change.new_source_security_group_id}`;
  if (change.action === "remove_nacl_rule")
    return `${change.acl_id} ${change.direction}: remove deny rule ${change.rule_number}`;
  if (change.action === "add_nacl_allow_rule")
    return `${change.acl_id} ${change.direction}: allow ${change.new_cidr} (rule ${change.rule_number})`;
  return `${target}: remove the 0.0.0.0/0 entry`;
}
