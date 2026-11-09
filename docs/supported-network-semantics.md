# Supported network model and input schema (v1.0)

CloudGuard analyses a **normalized, AWS-inspired JSON snapshot**, not raw AWS API output. The importer
validates strictly and rejects anything it cannot model correctly. Unsupported constructs are errors, not
approximations. Reachability and simulation semantics are documented in the sections below.

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

## Reachability (engine v1.0)

`domain/network/reachability.py` answers "can X reach Y on tcp/5432?" with `allowed`, `blocked` or
`unknown`, an ordered **trace** of every check, and **all** failing reason codes (not just the first).
It is deterministic Python; no model is involved. `confidence_type` is always
`deterministic_supported_subset`: this is **not** an authoritative AWS reachability proof.

| Path | Checks (in packet order) |
|---|---|
| **internet → instance** | public IP · route back via an internet gateway · subnet ACL ingress (request) · subnet ACL egress (reply) · security-group ingress |
| **instance → instance** (same VPC) | source SG egress · source-subnet ACL egress · local route · dest-subnet ACL ingress · dest SG ingress · dest-subnet ACL egress (reply) · return local route · source-subnet ACL ingress (reply) |

AWS semantics respected: security groups are **stateful** (no return rule needed; a rule naming a peer
group matches only instances in that group); network ACLs are **stateless** and **ordered** (lowest rule
number wins, implicit final deny) so the reply is checked separately over the ephemeral range
1024-65535; traffic **inside one subnet never crosses an ACL**; an empty security-group egress list
denies all outbound traffic; `0.0.0.0/0` ingress alone does **not** make an instance reachable.

Reason codes: `NO_PUBLIC_IP`, `NO_PUBLIC_ROUTE`, `NO_LOCAL_ROUTE`, `SG_INGRESS_DENIED`, `SG_EGRESS_DENIED`,
`NACL_INGRESS_DENIED`, `NACL_EGRESS_DENIED`, `NACL_REPLY_INGRESS_DENIED`, `NACL_REPLY_EGRESS_DENIED`,
and for `unknown`: `NACL_REPLY_PARTIAL`, `UNSUPPORTED_PROTOCOL`, `UNSUPPORTED_CROSS_VPC`.

`security_group_risk: OVERLY_BROAD_INGRESS` is set when the rule that matched is open to `0.0.0.0/0`
and is all-traffic or covers SSH/RDP/PostgreSQL/MySQL. It is independent of the verdict, which is how
the product tells a **risky rule** (finding) from a **verified reachable path** (`allowed`).

### Modelling decisions you should know about

- **The anonymous internet client** (no `source_ip`) matches only `0.0.0.0/0` rules; a narrower CIDR
  (an office range) does not cover it. Pass `source_ip` (a public IPv4 address) to ask about one
  specific client instead.
- **A subnet with no network ACL** is evaluated as AWS's *default* ACL (allow all) and the result lists
  `<subnet>:DEFAULT_NACL_ASSUMED` under `assumptions`. This replaces the earlier "not modeled" wording,
  because a snapshot that omits ACLs would otherwise make every path `unknown`. A configured ACL is
  always evaluated exactly.
- **Partial ephemeral-port coverage** on a reply is `unknown`, not a guess.

### Not modelled (returned as `unknown`, never guessed)

ICMP, paths between VPCs, NAT, peering, transit gateways, VPN, load balancers, host firewalls, IPv6,
return-path asymmetry beyond the checks above, and instance → internet paths (a destination of
`internet` is rejected).

## Simulation (engine v1.0)

`domain/network/simulation.py` applies a **validated** proposal to a *clone* of the configuration
(frozen dataclasses: the original cannot change) and re-runs both the rule engine and reachability.
Supported actions are exactly those of `proposals.py`: `replace_ingress_source`,
`restrict_ingress_cidr`, `remove_ingress_rule`. A rule open to `0.0.0.0/0` that is wider than the
proposal is changed as a whole and flagged `RULE_BROADER_THAN_PROPOSAL`.

**Required connectivity.** Pass `required_paths`, or it is inferred from the *intent* of the change
(not "everything that worked before", which would call least privilege a regression):
`replace_ingress_source` requires the new source group's instances to reach the protected instances;
`restrict_ingress_cidr` requires a representative public host (or in-CIDR instances) that worked before;
`remove_ingress_rule` infers nothing. The anonymous internet is never required.

**Outcome** (first match wins): `breaks_required_connectivity` · `inconclusive` ·
`required_connectivity_unmet` · `introduces_new_risk` · `improves_security` · `no_effect`.
`recommended` is true **only** when the outcome is `improves_security` *and* at least one required path
exists and every required path is `allowed` afterwards. A fix whose effect on legitimate traffic cannot be
verified is never recommended, and nothing is ever applied to a cloud account.
## Unsupported scenarios and known limitations

- Rules that split the internet into several ranges (for example `0.0.0.0/1` plus `128.0.0.0/1`) are not flagged as
  "open to the world"; only a literal `0.0.0.0/0` is.
- Only TCP, UDP and "all traffic" are modelled. ICMP and other IP protocols are not evaluated.
- IPv6, prefix lists, VPC peering, transit gateways, VPNs, load balancers and NAT are not modelled.
- When a NACL covers only part of the ephemeral return-port range the result is `unknown`, never "allowed".
- Results are a simplified model, not an authoritative AWS reachability proof.