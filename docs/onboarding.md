# Developer onboarding

1. Follow **Quick start** in the [README](../README.md).
2. Run the checks: `cd backend && pytest && ruff check .` and `cd frontend && npm run lint && npm test`.
3. Read [architecture.md](architecture.md), then [supported-network-semantics.md](supported-network-semantics.md).

## Conventions

- **Layers:** views handle HTTP, serializers validate requests, `services/` orchestrate, `domain/` evaluates
  rules. Keep `domain/` free of Django imports.
- **New Django app:** `mkdir -p apps/<name> && python manage.py startapp <name> apps/<name>`, set
  `name = "apps.<name>"` in `apps.py`, and add `apps.<name>.apps.<Name>Config` to `INSTALLED_APPS`.
- **Tests:** every feature needs at least one positive and one negative automated test. Use the shared
  fixtures in `backend/conftest.py` (`valid_config`, `sample_fixture`).
- **Commits:** conventional (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`); short-lived `feature/*` branches; `main` stays deployable.
- **Never commit** `.env`, API keys, AWS credentials, or real customer configurations.

## Useful commands

| Task | Command |
|---|---|
| Backend tests on PostgreSQL | `TEST_DATABASE_URL=postgresql://… pytest` |
| Validate the OpenAPI schema | `python manage.py spectacular --validate --fail-on-warn --file /dev/null` |
| Check migrations are in sync | `python manage.py makemigrations --check --dry-run` |
| Production sanity check | `DJANGO_SETTINGS_MODULE=config.settings.production … python manage.py check --deploy` |
