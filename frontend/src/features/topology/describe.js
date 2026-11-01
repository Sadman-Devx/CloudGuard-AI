// Human-readable renderings of resource metadata for the detail panel.

export function portText(rule) {
  if (rule.protocol === "-1") return "all traffic";
  if (rule.from_port == null) return rule.protocol;
  const ports = rule.from_port === rule.to_port ? `${rule.from_port}` : `${rule.from_port}-${rule.to_port}`;
  return `${rule.protocol}/${ports}`;
}

export function describeSgRule(rule, direction) {
  const peer = direction === "ingress" ? rule.source_security_group_id : rule.destination_security_group_id;
  const target = peer ?? rule.cidr;
  const arrow = direction === "ingress" ? "from" : "to";
  return `${portText(rule)} ${arrow} ${target}`;
}

export function describeNaclRule(rule) {
  return `#${rule.rule_number} ${rule.action} ${portText(rule)} ${rule.cidr}`;
}

export function describeRoute(route) {
  return `${route.destination_cidr} → ${route.target}`;
}

const FIELD_LABELS = {
  cidr: "CIDR",
  vpc_id: "VPC",
  route_table_id: "Route table",
  availability_zone: "Availability zone",
  private_ip: "Private IP",
  public_ip: "Public IP",
  security_group_ids: "Security groups",
  subnet_id: "Subnet",
  subnet_ids: "Subnets",
  kind: "Subnet kind",
  internet_gateway_id: "Internet gateway",
  has_internet_route: "Default route to internet gateway",
  has_public_ip: "Has public IP",
  subnet_kind: "Subnet kind",
  description: "Description",
  tags: "Tags",
};

const LIST_FIELDS = {
  routes: ["Routes", (r) => describeRoute(r)],
  ingress: ["Ingress rules", null],
  egress: ["Egress rules", null],
};

// Shown elsewhere (graph node subtitle) or redundant with the full rule lists below.
const HIDDEN_FIELDS = new Set(["ingress_rule_count", "egress_rule_count"]);

/** Returns [{label, values: string[]}] for the facts worth showing, in a stable order. */
export function detailRows(node) {
  const data = node.data ?? {};
  const rows = [];
  for (const [key, value] of Object.entries(data)) {
    if (HIDDEN_FIELDS.has(key) || value === null || value === undefined || value === "") continue;
    if (key in LIST_FIELDS) {
      const [label, fn] = LIST_FIELDS[key];
      const format =
        fn ??
        (node.type === "network_acl" ? describeNaclRule : (rule) => describeSgRule(rule, key));
      if (value.length) rows.push({ label, values: value.map(format) });
      continue;
    }
    const label = FIELD_LABELS[key] ?? key;
    if (Array.isArray(value)) rows.push({ label, values: value.map(String) });
    else if (typeof value === "object") rows.push({ label, values: Object.entries(value).map(([k, v]) => `${k}: ${v}`) });
    else if (typeof value === "boolean") rows.push({ label, values: [value ? "yes" : "no"] });
    else rows.push({ label, values: [String(value)] });
  }
  return rows;
}

export const SIDES_TEXT = {
  both: "Both sides declare this rule (the source allows sending and the target allows receiving).",
  ingress_only:
    "Only the target declares an ingress rule for the source group. The source has no rule that names the target group.",
  egress_only:
    "Only the source declares an egress rule for the target group. The target has no ingress rule that names the source group, so this traffic is not allowed in by a group reference.",
};