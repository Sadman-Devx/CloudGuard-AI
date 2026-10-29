# API reference (v0.2.0)

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

Planned (later days): `/topology/`, `/analyze/`, `/findings/`, `/explain/`, `/simulations/` per the roadmap.

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
