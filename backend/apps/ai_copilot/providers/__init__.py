from django.conf import settings

from .base import LLMProvider, ProviderError, ProviderNotConfigured, ProviderResult
from .meta import MetaModelProvider
from .mock import MockProvider

__all__ = [
    "LLMProvider",
    "MetaModelProvider",
    "MockProvider",
    "ProviderError",
    "ProviderNotConfigured",
    "ProviderResult",
    "get_provider",
    "provider_status",
]


def get_provider() -> LLMProvider:
    """Build the configured provider (replaceable: add a class and a branch here)."""
    if settings.AI_PROVIDER == "meta":
        return MetaModelProvider(
            api_key=settings.META_API_KEY,
            model=settings.META_MODEL_ID,
            base_url=settings.META_API_BASE_URL,
            path=settings.META_CHAT_PATH,
            timeout=settings.AI_TIMEOUT_SECONDS,
            json_mode=settings.META_JSON_MODE,
        )
    return MockProvider()


def provider_status() -> dict:
    meta = settings.AI_PROVIDER == "meta"
    configured = bool(settings.META_API_KEY and settings.META_MODEL_ID)
    return {
        "provider": "meta" if meta else "mock",
        "model": settings.META_MODEL_ID if meta else MockProvider.model,
        "configured": configured if meta else True,
        "is_meta_model": meta,
    }