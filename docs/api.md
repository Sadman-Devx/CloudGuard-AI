# API reference (v0.6.0)

Interactive docs: `/api/docs/` (Swagger UI), schema: `/api/schema/`. All bodies are JSON. Lists are paginated
(`count`, `next`, `previous`, `results`; `?page=`, `?page_size=` ≤ 200).

## Error envelope

```json
{"error": {"code": "invalid_configuration", "message": "…", "details": [...], "request_id": "…"}}
```

Every response carries `X-Request-ID` (a well-formed client-supplied ID is echoed; otherwise one is generated).

| HTTP | `code` | When |
|---|---|---|
| 400 | `validation_error` / `parse_error` | Bad request fields / malformed or too deeply nested JSON |
| 404 | `not_found` | Unknown project / snapshot |
| 413 | `payload_too_large` | Body larger than `MAX_UPLOAD_BYTES` |
| 404 | `not_found` | Unknown URL or object (JSON for every `/api/` path) |
| 429 | `throttled` | Rate limit hit; honour the `Retry-After` header |
| 500 | `internal_error` | Unexpected server error; quote the `request_id` when reporting it |
| 415 | `unsupported_media_type` | Not `application/json` |
| 422 | `invalid_configuration` | Config failed validation; `details` = `[{path, code, message}]`. **Nothing is stored.** |

## Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/api/health/` | `200 {"status":"ok","service","version","database":"ok"}` or `503` with `"status":"degraded"` |
| GET/POST | `/api/projects/` | List / create (`{"name": "…", "description"?}`) |
| GET | `/api/projects/{id}/` | Project detail |
| GET | `/api/fixtures/` | Bundled sample configurations `{results:[{name,title}]}` |
| GET | `/api/projects/{id}/snapshots/` | Snapshots, newest first |
| POST | `/api/projects/{id}/snapshots/` | **Body = the configuration JSON.** Optional `X-Source-Name` header. `201` snapshot summary |
| POST | `/api/projects/{id}/snapshots/from-fixture/` | `{"fixture": "exposed_database"}` → `201` |
| GET | `/api/snapshots/{id}/` | Snapshot metadata |
| GET | `/api/snapshots/{id}/resources/` | Normalized inventory; filter `?type=security_group` |
| GET | `/api/attack-path/graph/` | Read-only demo attack-path graph |
| GET | `/api/attack-path/paths/?top_k=8&max_depth=6` | Ranked demo attack paths and choke points |
| GET | `/api/attack-path/blast-radius/{node_id}/?max_depth=4` | Demo graph blast radius for a node |
| POST | `/api/attack-path/simulate/` | Demo graph what-if; body `{"remove_nodes":["role_admin"],"max_depth":6}` |

| POST | `/api/snapshots/{id}/reachability/` | One question: `{source, destination, protocol, port, source_ip?}` → verdict, reason codes, full trace |
| POST | `/api/snapshots/{id}/simulations/` | Run a what-if. Body: exactly one of `proposed_change` / `interaction_id`, plus optional `finding_id`, `required_paths[]` (≤ 20). `201` |
| GET | `/api/snapshots/{id}/simulations/` | History (paginated, no traces) |
| GET | `/api/simulations/{id}/` | Full evidence: `result` (diff), `before` / `after` (findings + per-path traces) |

Simulations are write-once, never modify the snapshot or its stored findings, always report
`applied_to_cloud: false`, and are throttled (`SIMULATE_RATE`, default `60/min`). The change is
re-validated server-side even when it comes from a stored AI explanation. Request errors are `400`
with `details` keyed by field (`proposed_change`, `required_paths`, `interaction_id`, `finding_id`).

Topology, analysis and copilot endpoints: see `/api/docs/`.

The attack-path explorer uses a bundled synthetic demo graph; it is not derived
from imported snapshots and does not query or modify a cloud account.

## Example

```bash
curl -s -X POST localhost:8000/api/projects/1/snapshots/from-fixture/ \
  -H 'Content-Type: application/json' -d '{"fixture":"exposed_database"}'
```

```json
{"id": 1, "project": 1, "version": 1, "source_type": "fixture", "source_name": "exposed_database",
 "name": "Exposed database rules", "region": "us-east-1", "schema_version": "1.0",
 "resource_counts": {"vpc": 1, "subnet": 2, "internet_gateway": 1, "route_table": 2,
                     "security_group": 3, "network_acl": 0, "instance": 3},
 "relationship_count": 19, "warnings": [], "imported_at": "2026-10-27T04:39:26.132819Z"}
```

Rejected upload (`422`):

```json
{"error": {"code": "invalid_configuration", "message": "The uploaded configuration is invalid.",
 "details": [{"path": "vpcs[0].cidr", "code": "invalid_cidr", "message": "Invalid CIDR '10.0.0.0/99': …"}],
 "request_id": "a4fcf62fd26342a0a9a6be22d9baf035"}}
```

### Simulation example

```bash
curl -s -X POST localhost:8000/api/snapshots/1/simulations/ -H 'Content-Type: application/json' -d '{
  "proposed_change": {"action":"replace_ingress_source","security_group_id":"sg-db",
                      "protocol":"tcp","port":5432,"new_source_security_group_id":"sg-app"}}'
```

```json
{"id": 1, "outcome": "improves_security", "recommended": true, "applied_to_cloud": false,
 "result": {"required_paths_source": "inferred",
   "summary_lines": ["Resolves SG-003 on sg-db.",
     "Internet exposure anonymous internet -> i-db-1 tcp/5432: allowed -> blocked.",
     "Required path i-app-1 -> i-db-1 tcp/5432 is preserved."]}}
```