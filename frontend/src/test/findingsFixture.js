export const FINDINGS = {
  snapshot: 5,
  analysis: {
    snapshot: 5,
    rules_version: "1.0",
    ran_at: "2026-11-01T00:00:00Z",
    summary: {
      total: 2,
      by_severity: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
      by_rule: { "SG-001": 1, "SG-003": 1 },
    },
  },
  results: [
    {
      id: 11,
      snapshot: 5,
      rule_id: "SG-001",
      severity: "high",
      category: "risky_rule",
      title: "SSH (22) open to the internet",
      resource_type: "security_group",
      resource_id: "sg-web",
      resource_name: "web",
      summary:
        "Security group 'web' (sg-web) allows SSH (tcp/22) from anywhere (0.0.0.0/0).",
      evidence: {
        port: 22,
        matching_rules: [
          {
            direction: "ingress",
            index: 1,
            protocol: "tcp",
            from_port: 22,
            to_port: 22,
            cidr: "0.0.0.0/0",
            description: "temporary SSH",
          },
        ],
        context: {
          exposure: "internet_facing_candidate",
          note: "n",
          attached_instances: [
            {
              id: "i-web-1",
              name: "web-1",
              subnet_id: "s",
              subnet_kind: "public",
              has_public_ip: true,
            },
          ],
        },
      },
      remediation: "Remove the 0.0.0.0/0 source.",
    },
    {
      id: 12,
      snapshot: 5,
      rule_id: "SG-003",
      severity: "medium",
      category: "potential_exposure",
      title: "PostgreSQL (5432) open to the internet",
      resource_type: "security_group",
      resource_id: "sg-db",
      resource_name: "db",
      summary:
        "Security group 'db' (sg-db) allows PostgreSQL (tcp/5432) from anywhere (0.0.0.0/0).",
      evidence: {
        port: 5432,
        matching_rules: [
          {
            direction: "ingress",
            index: 0,
            protocol: "tcp",
            from_port: 5432,
            to_port: 5432,
            cidr: "0.0.0.0/0",
            description: "",
          },
        ],
        context: {
          exposure: "no_public_path",
          note: "n",
          attached_instances: [],
        },
      },
      remediation: "Replace the 0.0.0.0/0 source.",
    },
  ],
};

export const RULES = [
  {
    id: "SG-001",
    title: "SSH",
    category: "risky_rule",
    description: "d",
    remediation: "r",
    limitations: "Not proof of reachability.",
  },
  {
    id: "SG-003",
    title: "PG",
    category: "potential_exposure",
    description: "d",
    remediation: "r",
    limitations: "Not proof either.",
  },
];

export const INTERACTION = {
  id: 1,
  finding: 11,
  status: "ok",
  source: "meta_model",
  provider: "meta",
  model: "muse-spark-1.3",
  is_meta_model: true,
  fallback_reason: null,
  cached: false,
  attempts: 1,
  latency_ms: 800,
  prompt_version: "1",
  created_at: "2026-11-01T00:00:00Z",
  explanation: "Anyone on the internet can try to log in over SSH.",
  proposed_change: {
    action: "remove_ingress_rule",
    security_group_id: "sg-web",
    protocol: "tcp",
    from_port: 22,
    to_port: 22,
    new_source_security_group_id: null,
    new_cidr: null,
  },
  assumptions: ["Admins can use Session Manager."],
  uncertainty: "Routes were not evaluated.",
  requires_simulation: true,
};