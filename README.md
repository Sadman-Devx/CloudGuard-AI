# CloudGuard AI

**AI-powered cloud network security copilot with digital twin simulation.**
Built for the Meta Global AI Developer Hackathon 2026 (theme: *Build for Your World*).

CloudGuard helps developers and small teams understand AWS network security risks, see how their
resources connect, and (in later milestones) ask a Meta model to explain risks and propose fixes that
are **simulated against a digital twin before anything is changed**. The MVP is software-only and
**never modifies real AWS resources**.

> **Status: Milestone A (Days 1–2) complete.** Foundation, normalized input schema, validated import,
> persisted inventory. Topology graph, security rules, Meta AI copilot, and the simulator land in
> Days 3–7. See [docs/architecture.md](docs/architecture.md) for the plan and
> [docs/supported-network-semantics.md](docs/supported-network-semantics.md) for exactly what is modeled.

## What works today

- Import an AWS-inspired JSON snapshot (upload a file or pick a bundled sample).
- Strict validation of CIDRs, IPs, ports, protocols, identifiers and every cross-reference, with **all**
  problems reported at once and a precise JSON path for each.
- Atomic persistence as an immutable, versioned snapshot plus a normalized inventory
  (resources and relationships) — a rejected upload writes nothing.
- REST API with OpenAPI docs (`/api/docs/`), error envelope with request IDs, upload size/nesting limits.
- React UI: backend status screen and an import screen with validation feedback.

## Quick start

### Option A — Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Frontend: <http://localhost:5173> · API: <http://localhost:8000/api/health/> · Docs: <http://localhost:8000/api/docs/>

### Option B — local

Requirements: Python 3.12+ (developed on 3.13), Node 22+, PostgreSQL 16 (optional; SQLite is the dev fallback).

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements/development.txt
export DATABASE_URL=postgresql://cloudguard:change-me@localhost:5432/cloudguard   # omit to use SQLite
python manage.py migrate
python manage.py runserver            # http://localhost:8000

# Frontend (second terminal)
cd frontend
npm install
npm run dev                           # http://localhost:5173 (proxies /api to :8000)
```

Try the API without the UI:

```bash
curl -s -X POST localhost:8000/api/projects/ -H 'Content-Type: application/json' -d '{"name":"Demo"}'
curl -s -X POST localhost:8000/api/projects/1/snapshots/from-fixture/ \
     -H 'Content-Type: application/json' -d '{"fixture":"exposed_database"}'
```

## Tests and quality gates

```bash
cd backend  && pytest && ruff check . && ruff format --check .
cd frontend && npm run lint && npm test && npm run build
# Run the backend suite on PostgreSQL instead of in-memory SQLite:
TEST_DATABASE_URL=postgresql://cloudguard:change-me@localhost:5432/cloudguard pytest
```

CI (`.github/workflows/ci.yml`) runs all of the above, plus a migrations check, against PostgreSQL.

## Repository layout

```
backend/    Django + DRF (apps/ = Django apps, domain/ = pure-Python network logic, common/ = shared API plumbing)
frontend/   React + Vite + Tailwind
sample_data/aws/   Three synthetic fixtures (safe, exposed database, broken app→DB connectivity)
docs/       Architecture, supported semantics, API, security model, onboarding
```

## Meta AI usage

Planned for Day 5: a supported Meta model (selected after API access is confirmed) explains
deterministic findings and proposes structured fixes behind a replaceable provider adapter. Findings
and reachability come from tested Python logic, never from the LLM. This section will name the exact
model and its role once integrated. Nothing in the current build calls a model.

## Honest limitations

CloudGuard models a documented **subset** of AWS networking (VPC, subnets, route tables with local and
internet-gateway routes, security groups, and basic NACLs). Anything outside that subset is reported as
`unknown/unsupported` rather than guessed. It is not a penetration test or a compliance tool, and it
does not prove real-world exploitability. All bundled data is synthetic.

## License

MIT — see [LICENSE](LICENSE).
