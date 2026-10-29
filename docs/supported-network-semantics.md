# Supported network model and input schema (v1.0)

CloudGuard analyses a **normalized, AWS-inspired JSON snapshot**, not raw AWS API output. The importer
validates strictly and rejects anything it cannot model correctly. Unsupported constructs are errors, not
approximations. Reachability semantics (Day 6) will be documented here as they are implemented.

## Top level

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | Must be `"1.0"` |
| `vpcs` | yes | At least one |
| `name` | no | Free text, ≤ 256 chars |
| `region` | no | e.g. `us-east-1` (default) |
| `internet_gateways`, `route_tables`, `subnets`, `security_groups`, `network_acls`, `instances` | no | Lists |

Unknown fields are rejected so typos are caught instead of silently ignored.

## Resources

- **vpc** `{id, cidr, name?}` — IPv4, prefix /16–/28.
- **internet_gateway** `{id, vpc_id}` — at most one per VPC.
- **route_table** `{id, vpc_id, routes[], name?}` — routes `{destination_cidr, target}`; target is `local`
  (must equal the VPC CIDR) or an internet gateway of the same VPC. NAT, peering, transit gateway, VPN,
  endpoints and ENI targets are **rejected as unsupported**. Duplicate destinations are rejected.
- **subnet** `{id, vpc_id, cidr, route_table_id, availability_zone?, name?}` — must lie inside its VPC; subnets
  of one VPC must not overlap; the route table must belong to the same VPC.
- **security_group** `{id, vpc_id, name, ingress[], egress[], description?}` — rule
  `{protocol, from_port?, to_port?, cidr | source_security_group_id (ingress) | destination_security_group_id (egress), description?}`.
  Exactly one of CIDR or peer group. Peer groups must exist in the same VPC.
- **network_acl** `{id, vpc_id, subnet_ids[], ingress[], egress[], name?}` — rules
  `{rule_number 1–32766 (unique per direction), action allow|deny, protocol, cidr, from_port?, to_port?}`.
  A subnet may be associated with at most one ACL. Subnets with no ACL are treated as "not modeled".
- **instance** `{id, subnet_id, private_ip, security_group_ids[1..5], public_ip?, name?, tags?}` — private IP must be inside
  the subnet and not one of AWS's reserved addresses (first four, last); unique per VPC. Public IP must be
  a public address (RFC 5737 documentation ranges are allowed so fixtures can use safe synthetic IPs).

Protocols: `tcp`, `udp`, `icmp`, `-1` (all; ports must be omitted). Ports are 0–65535 with `from ≤ to`.

## Identifiers and limits

- IDs: 1–64 chars of letters, digits, `.`, `_`, `-`, starting with a letter or digit; unique across the file.
- ≤ 500 resources total, ≤ 200 rules per list, ≤ 100 routes per table, ≤ 50 tags per instance.
- Text ≤ 256 chars, no control characters. Body ≤ `MAX_UPLOAD_BYTES` (1 MB), nesting ≤ `MAX_JSON_DEPTH` (12).
- Validation reports at most 100 errors (then a `too_many_errors` marker).

## Warnings (non-blocking)

`unassociated_route_table`, `unused_security_group`.

## Explicitly out of scope

IPv6, multi-region/multi-account, peering/transit gateways/VPN, load balancers, NAT, prefix lists,
IAM, Kubernetes. AWS semantics to respect in later milestones: security groups are stateful, NACLs are
stateless and ordered, and an `0.0.0.0/0` ingress rule alone does **not** prove internet reachability.
