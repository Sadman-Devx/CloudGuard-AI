// A small topology in the exact shape returned by GET /api/snapshots/{id}/topology/.
const node = (id, type, label, data = {}, parent = "vpc-main") => ({ id, type, label, parent, data });

export const TOPOLOGY = {
  snapshot: 5,
  project: 1,
  version: 2,
  name: "App cannot reach database",
  region: "us-east-1",
  nodes: [
    node("internet", "internet", "Internet", {}, null),
    node("vpc-main", "vpc", "main", { cidr: "10.0.0.0/16" }, null),
    node("igw-main", "internet_gateway", "igw-main", { vpc_id: "vpc-main" }),
    node("subnet-public", "subnet", "public", { cidr: "10.0.1.0/24", kind: "public", internet_gateway_id: "igw-main" }),
    node("subnet-private", "subnet", "private", { cidr: "10.0.2.0/24", kind: "private", internet_gateway_id: null }),
    node("i-web-1", "instance", "web-1", {
      private_ip: "10.0.1.10",
      public_ip: "203.0.113.10",
      has_public_ip: true,
      subnet_kind: "public",
      tags: { tier: "web" },
    }),
    node("i-app-1", "instance", "app-1", { private_ip: "10.0.2.10", has_public_ip: false, subnet_kind: "private" }),
    node("sg-web", "security_group", "web", {
      description: "HTTPS from the internet to the web tier",
      ingress_rule_count: 1,
      egress_rule_count: 1,
      ingress: [{ protocol: "tcp", from_port: 443, to_port: 443, cidr: "0.0.0.0/0", description: "" }],
      egress: [{ protocol: "tcp", from_port: 5432, to_port: 5432, destination_security_group_id: "sg-db" }],
    }),
    node("sg-app", "security_group", "app", { ingress_rule_count: 0, egress_rule_count: 1, ingress: [], egress: [] }),
    node("sg-db", "security_group", "db", { ingress_rule_count: 1, egress_rule_count: 0, ingress: [], egress: [] }),
  ],
  edges: [
    { id: "attached:internet->igw-main", source: "internet", target: "igw-main", kind: "attached", label: "attached", data: {} },
    { id: "placed_in_subnet:i-web-1->subnet-public", source: "i-web-1", target: "subnet-public", kind: "placed_in_subnet", label: "", data: {} },
    { id: "protected_by:i-web-1->sg-web", source: "i-web-1", target: "sg-web", kind: "protected_by", label: "", data: {} },
    {
      id: "sg_traffic:sg-web->sg-db",
      source: "sg-web",
      target: "sg-db",
      kind: "sg_traffic",
      label: "tcp/5432",
      data: {
        sides: "both",
        ingress_rules: [{ protocol: "tcp", from_port: 5432, to_port: 5432, description: "" }],
        egress_rules: [{ protocol: "tcp", from_port: 5432, to_port: 5432, description: "" }],
      },
    },
    {
      id: "sg_traffic:sg-app->sg-db",
      source: "sg-app",
      target: "sg-db",
      kind: "sg_traffic",
      label: "tcp/5432",
      data: {
        sides: "egress_only",
        ingress_rules: [],
        egress_rules: [{ protocol: "tcp", from_port: 5432, to_port: 5432, description: "" }],
      },
    },
  ],
  issues: [],
  summary: {
    node_count: 10,
    edge_count: 5,
    public_subnets: ["subnet-public"],
    private_subnets: ["subnet-private"],
    instances_with_public_ip: ["i-web-1"],
    one_sided_sg_flows: ["sg-app->sg-db"],
  },
};