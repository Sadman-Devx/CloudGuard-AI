# Architecture

## ADR-001: Modular Django monolith + React SPA

**Status:** accepted (Day 1)

**Context.** Ten-day hackathon, small team, one deployable demo. We need clear boundaries between
deterministic security logic and the AI layer, without the operational cost of microservices.

**Decision.** One Django deployment, one PostgreSQL database, independent domain apps, a pure-Python
domain package, and a separate React SPA.

**Consequences.** Simple deploy and local setup; boundaries enforced by package layout and tests rather
than by network calls. If a domain outgrows the monolith it can be extracted along the existing seams.

## Principles

1. **Deterministic truth.** Findings and connectivity decisions come from tested Python, not an LLM.
2. **LLM as advisor.** Meta AI explains findings and proposes changes; proposals are schema-validated
   and simulated before being shown as recommendations. Nothing is ever auto-applied.
3. **Pure domain core.** `backend/domain/network/` has no Django imports, so it is trivially unit-testable.
4. **Reproducibility.** Imported input is stored verbatim as immutable, versioned snapshots.
5. **Fail closed on unknowns.** Unsupported constructs are rejected at import (or reported `unknown`
   later) instead of being silently approximated.
6. **Least privilege.** The MVP has no cloud credentials and no write path to AWS.

## Layout and responsibilities

| Package | Responsibility |
|---|---|
| `domain/network/schema.py` | Typed model + validator for the untrusted input JSON (collects all errors, never executes input) |
| `domain/network/inventory.py` | Flattens a validated config into resources and relationships |
| `apps/projects` | Projects (workspaces) |
| `apps/cloud_resources` | Snapshots, normalized resources/relationships, import service, upload API |
| `common/` | Error envelope, request IDs, bounded JSON parser, health view |
| `config/settings/` | `base`, `development`, `production`, `test` |

| `domain/network/{topology,rules,proposals}.py` | Topology graph, SG-001..006 rule engine, validation of AI-proposed changes (Days 3-5) |
| `domain/network/reachability.py` | Deterministic path evaluation with reason trace (Day 6) |
| `domain/network/simulation.py` | Apply a validated change to a clone; diff findings and paths; outcome + `recommended` (Day 6) |
| `apps/security_engine`, `apps/ai_copilot` | Persisted findings; provider-adapter AI explanations (Days 4-5) |
| `apps/simulations` | `Simulation` evidence rows, request validation, REST API (Day 6) |

## Simulation data flow (Day 6)

```text
POST /api/snapshots/{id}/simulations/   {proposed_change | interaction_id, required_paths?}
  -> serializer          exactly one source of the change; unknown fields rejected
  -> proposals.validate_change   re-validated against the stored config (client/model untrusted)
  -> simulation.simulate         clone -> evaluate rules + reachability before/after -> diff
  -> Simulation row (write-once); snapshot and findings untouched; applied_to_cloud=false
```

## Import data flow (Days 1–2)

```text
POST /api/projects/{id}/snapshots/            (JSON body = the configuration)
  -> BoundedJSONParser    size cap (read limit+1), RecursionError -> 400
  -> check_json_depth     nesting cap -> 422
  -> validate_config      typed NetworkConfig or ALL errors -> 422 (nothing written)
  -> build_inventory      resources + relationships (pure)
  -> transaction.atomic   lock project row, next version, bulk insert snapshot/resources/edges
  <- 201 snapshot summary (counts, warnings)
```

## Data model (implemented)

- `Project(name, description, created_at)`
- `ConfigurationSnapshot(project, version, source_type, source_name, name, region, schema_version, raw_json, warnings, resource_counts, relationship_count, imported_at)`
  — unique `(project, version)`; `save()` refuses updates (immutable).
- `CloudResource(snapshot, external_id, resource_type, name, region, metadata)` — unique `(snapshot, external_id)`.
- `NetworkRelationship(snapshot, source, target, relation_type, metadata)` — unique `(snapshot, source, target, relation_type)`.

Relationship types: `member_of_vpc`, `associated_route_table`, `associated_network_acl`,
`placed_in_subnet`, `protected_by`, `routes_to`, `allows_ingress_from`, `allows_egress_to`.

## Decisions worth knowing

- **Upload format:** the request body *is* the configuration JSON (no multipart), so the same call works
  from `curl`, the UI and tests.
- **Version allocation:** the project row is locked (`SELECT … FOR UPDATE` on PostgreSQL) while the next
  version is computed, so concurrent imports cannot collide.
- **Fixtures** are selected by name against an allow-list of files in `FIXTURES_DIR`; names are never used
  as paths.
- **No authentication in the MVP.** Endpoints are open; add accounts only if time permits (see roadmap
  cut order). Do not expose this deployment with real customer data.