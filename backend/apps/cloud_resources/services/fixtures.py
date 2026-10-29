"""Read-only access to the bundled sample configurations.

Callers pass a fixture *name*; it is only ever matched against the allow-list of
files found in ``FIXTURES_DIR``, so it can never be used to read arbitrary paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from django.conf import settings

MAX_FIXTURE_BYTES = 1_000_000


class FixtureNotFound(Exception):
    pass


def _available() -> dict[str, Path]:
    directory = Path(settings.FIXTURES_DIR)
    if not directory.is_dir():
        return {}
    return {p.stem: p for p in sorted(directory.glob("*.json")) if p.is_file()}


def _read(path: Path) -> Any:
    if path.stat().st_size > MAX_FIXTURE_BYTES:
        raise ValueError(f"Fixture {path.name} is too large.")
    return json.loads(path.read_text(encoding="utf-8"))


def list_fixtures() -> list[dict[str, str]]:
    items = []
    for name, path in _available().items():
        data = _read(path)
        title = data.get("name", name) if isinstance(data, dict) else name
        items.append({"name": name, "title": str(title)})
    return items


def load_fixture(name: str) -> Any:
    path = _available().get(name)
    if path is None:
        raise FixtureNotFound(name)
    return _read(path)
