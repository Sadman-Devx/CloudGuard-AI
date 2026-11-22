# Rule registry, new change types, grouping and answer cache

## Rule registry (backend/domain/network/rules.py)
* Port rules are data: `backend/domain/network/rule_catalog.json` (id, port, service, severity family,
  remediation, CIS mapping). Add your own by pointing `CLOUDGUARD_RULES_FILE` at a JSON file with a
  `port_rules` list in the same shape; a bad file is rejected as a whole (nothing is half-loaded).
* In code: `register_port_rule(...)` and `@register_check(info, family)` (custom per-security-group
  checks). Severity always comes from the family table (admin, database, remote, all_ports, egress).
* `GET /api/rules/` now also returns `family` and `cis`.
* CIS mapping lists only controls checked against the CIS AWS Foundations Benchmark v3.0.0, section 5:
  5.2 (security groups, 0.0.0.0/0) and 5.3 (security groups, ::/0), for SG-001, SG-002 and SG-005. An
  empty `cis` list means "no direct CIS control", not "unknown".

## Findings by instance
`GET /api/snapshots/<id>/findings/by-instance/` lists each instance with the findings of the security
groups it uses (worst first); findings on groups no instance uses are returned as `unattached`.
Findings tab: **By finding / By instance** toggle.

## Explain cache
`AIInteraction.cache_key` = sha256(prompt version, provider, model, the exact finding payload). The same
question about the same configuration reuses the answer even after the snapshot is re-analysed (a copy
is attached to the new finding row, no model call, not counted against the budget). A new
`PROMPT_VERSION`, model or configuration gives a different key. Run `python manage.py migrate`.

## New change types (simulation API only, never proposed by the model)
`POST /api/snapshots/<id>/simulations/` with `proposed_change.action` one of:

| action | meaning | key fields |
|---|---|---|
| `restrict_egress_rule` | narrow an egress rule open to 0.0.0.0/0 | `protocol`, `allow_protocol`, `allow_port` (or `allow_from_port`/`allow_to_port`), one of `new_cidr` / `new_source_security_group_id` (the destination) |
| `add_ingress_rule` | allow one more source | `protocol`, `port`, one of `new_cidr` / `new_source_security_group_id` |
| `remove_nacl_rule` | remove a *deny* entry | `acl_id`, `direction`, `rule_number` |
| `add_nacl_allow_rule` | add an allow entry | `acl_id`, `direction`, `rule_number`, `protocol`, `port`, `new_cidr` |

All need `security_group_id` (the group the change is about; an ACL must cover one of its instances).
New outcome: `fixes_connectivity` (a required path starts working, nothing new is exposed).

## IPv6 (partial)
`::/0` and other IPv6 CIDRs are accepted in security-group rules and ACL entries and are detected by
the rules. They are never matched against the IPv4 clients and addresses the reachability engine
models, and VPC/subnet/route IPv6 is still rejected. NAT gateways and VPC peerings are validated in
`extensions` but do not yet change reachability.
