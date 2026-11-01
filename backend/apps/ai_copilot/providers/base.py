"""Provider adapter interface. Business code depends only on this, never on a vendor SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class ProviderError(Exception):
    """A provider call failed. ``retryable`` says whether trying again could help."""

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class ProviderNotConfigured(ProviderError):
    pass


@dataclass(frozen=True)
class ProviderResult:
    text: str
    model: str
    usage: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    name: str  # "meta" | "mock"
    model: str

    def complete(self, system: str, user: str) -> ProviderResult: ...