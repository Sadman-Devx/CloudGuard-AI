# Security model

## Posture

CloudGuard is **read-only by design**: no AWS credentials, no write path to cloud APIs, and AI output
(Day 5+) can only *propose* changes that are simulated on a copy.

## Untrusted input handling (implemented)

| Threat | Control |
|---|---|
| Oversized body | Parser reads at most `MAX_UPLOAD_BYTES + 1` bytes (works without `Content-Length`) → 413 |
| Deeply nested JSON / recursion crash | Iterative depth check (`MAX_JSON_DEPTH`) and `RecursionError` → 400 |
| `NaN`/`Infinity` JSON constants | Strict JSON parsing rejects them |
| Resource exhaustion | Caps on resources, rules, routes, tags, text length, reported errors |
| Injection via identifiers (later flows into graph IDs, URLs, LLM prompts) | Conservative ID charset; control characters rejected in all text |
| Code execution | Input is only parsed as data; never evaluated, templated or run |
| Path traversal via fixture names | Names matched against an allow-list of files; never used as paths |
| Partial/corrupt writes | Validate first, then one atomic transaction |
| Tampering with history | Snapshots immutable at the model layer; inputs stored verbatim |
| Trace/log forging | Client request IDs accepted only if they match `[A-Za-z0-9._-]{8,64}` |

## Secrets and deployment

- `.env` is git-ignored; only `.env.example` is committed. No real keys or customer configs in the repo.
- `production.py` refuses to start without a real `DJANGO_SECRET_KEY` and explicit `DJANGO_ALLOWED_HOSTS`.
- Production enables SSL redirect, secure cookies, nosniff and `X-Frame-Options: DENY`. HSTS stays at 0 until HTTPS is
  confirmed (Day 9); run `python manage.py check --deploy` before release.

## Known gaps (tracked)

- No authentication or per-project authorization yet (single-demo-workspace MVP). Do not store sensitive data.
- No rate limiting yet (planned Day 8, required before the AI endpoint ships).
- The simplified model is not an authoritative AWS reachability proof.
