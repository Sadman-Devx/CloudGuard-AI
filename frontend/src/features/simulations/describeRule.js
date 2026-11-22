// One-line text of a security-group rule or network-ACL entry from a simulation result.

const PROTOCOL = { "-1": "all traffic" };

function ports(rule) {
  if (rule.protocol === "-1" || rule.from_port == null) return "";
  return rule.from_port === rule.to_port
    ? `${rule.from_port}`
    : `${rule.from_port}-${rule.to_port}`;
}

export function describeRule(rule) {
  if (!rule) return "";
  const proto = PROTOCOL[rule.protocol] ?? rule.protocol;
  const where = ports(rule);
  const traffic = where ? `${proto}/${where}` : proto;
  if (rule.action) {
    // network ACL entry
    return `#${rule.rule_number} ${rule.action} ${traffic} ${rule.cidr ? `· ${rule.cidr}` : ""}`.trim();
  }
  const peer = rule.peer_security_group_id ?? rule.cidr;
  return `${traffic} · ${peer ?? "?"}`;
}
