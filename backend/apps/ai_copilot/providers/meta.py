"""Meta Model API adapter (OpenAI-style chat completions over HTTPS, stdlib only).

Base URL, path, model and key are all configuration. The request/response shape follows the
chat-completions protocol; verify it against your hackathon account (``docs/ai-copilot.md``).
The API key is only ever sent in the Authorization header and never logged or stored.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .base import ProviderError, ProviderNotConfigured, ProviderResult

MAX_RESPONSE_BYTES = 1_000_000


class MetaModelProvider:
    name = "meta"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str,
        path: str,
        timeout: float,
        json_mode: bool = False,
    ):
        if not api_key or not model:
            raise ProviderNotConfigured("META_API_KEY and META_MODEL_ID must both be set.")
        self.model = model
        self._key = api_key
        self._url = base_url.rstrip("/") + "/" + path.lstrip("/")
        self._timeout = timeout
        self._json_mode = json_mode

    def complete(self, system: str, user: str) -> ProviderResult:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}
        request = urllib.request.Request(  # noqa: S310 - fixed https base URL from settings
            self._url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self._key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            retryable = status in (408, 409, 425, 429) or status >= 500
            raise ProviderError(f"Meta API returned HTTP {status}.", retryable=retryable) from None
        except TimeoutError:
            raise ProviderError("The Meta API request timed out.", retryable=True) from None
        except urllib.error.URLError as exc:
            raise ProviderError(
                f"Could not reach the Meta API ({type(exc.reason).__name__}).", retryable=True
            ) from None
        except OSError as exc:
            raise ProviderError(
                f"Network error calling the Meta API ({type(exc).__name__}).", retryable=True
            ) from None

        if len(body) > MAX_RESPONSE_BYTES:
            raise ProviderError("The Meta API response was too large.")
        try:
            data = json.loads(body)
        except ValueError:
            raise ProviderError("The Meta API returned a non-JSON response.", retryable=True) from None
        return ProviderResult(
            text=_extract_text(data), model=str(data.get("model") or self.model), usage=_usage(data)
        )


def _extract_text(data: object) -> str:
    """Pull the assistant text out of a chat-completions (or messages-style) response."""
    if isinstance(data, dict):
        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            message = choices[0].get("message")
            if isinstance(message, dict):
                text = _content_text(message.get("content"))
                if text:
                    return text
            text = _content_text(choices[0].get("text"))
            if text:
                return text
        text = _content_text(data.get("content"))
        if text:
            return text
    raise ProviderError("The Meta API response did not contain any text.", retryable=True)


def _content_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)]
        return "".join(parts)
    return ""


def _usage(data: object) -> dict:
    usage = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(usage, dict):
        return {}
    return {k: v for k, v in usage.items() if isinstance(v, int) and not isinstance(v, bool)}