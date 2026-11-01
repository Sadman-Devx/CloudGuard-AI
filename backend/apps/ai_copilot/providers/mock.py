"""Offline demo provider. Deterministic, no network. Always labelled as NOT a Meta model."""

from __future__ import annotations

import json

from apps.ai_copilot.deterministic import answer_from_payload
from apps.ai_copilot.prompts import extract_payload

from .base import ProviderResult


class MockProvider:
    name = "mock"
    model = "offline-demo"

    def complete(self, system: str, user: str) -> ProviderResult:
        answer = answer_from_payload(extract_payload(user))
        return ProviderResult(text=json.dumps(answer), model=self.model)