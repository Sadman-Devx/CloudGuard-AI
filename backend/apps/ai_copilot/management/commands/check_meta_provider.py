"""Make one real call to the configured Meta model API and report what came back.

    python manage.py check_meta_provider

Use it after setting META_API_KEY, META_MODEL_ID and META_API_BASE_URL (and META_CHAT_PATH if your
endpoint differs). It prints the URL it called (never the key), the HTTP outcome, the model the API
says it used, the latency, and whether the reply parsed as a JSON object, which is what the copilot
needs. Exit status is non-zero on any failure, so it can gate a deploy.
"""

import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.ai_copilot.providers import MetaModelProvider, ProviderError
from apps.ai_copilot.services.explain import parse_model_json


class Command(BaseCommand):
    help = "Call the configured Meta model API once and verify the response shape."

    def handle(self, *args, **options):
        missing = [
            name
            for name in ("META_API_KEY", "META_MODEL_ID", "META_API_BASE_URL")
            if not getattr(settings, name, "")
        ]
        if missing:
            raise CommandError(f"Not configured: {', '.join(missing)}. The app would use the offline mock.")

        provider = MetaModelProvider(
            api_key=settings.META_API_KEY,
            model=settings.META_MODEL_ID,
            base_url=settings.META_API_BASE_URL,
            path=settings.META_CHAT_PATH,
            timeout=settings.AI_TIMEOUT_SECONDS,
            json_mode=settings.META_JSON_MODE,
        )
        url = settings.META_API_BASE_URL.rstrip("/") + "/" + settings.META_CHAT_PATH.lstrip("/")
        self.stdout.write(f"POST {url}  (model id: {settings.META_MODEL_ID}, json_mode={settings.META_JSON_MODE})")

        started = time.monotonic()
        try:
            result = provider.complete(
                "Reply with one JSON object and nothing else.",
                'Return exactly {"ok": true, "echo": "cloudguard"}.',
            )
        except ProviderError as exc:
            raise CommandError(f"Call failed: {exc} (retryable: {exc.retryable})") from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)

        self.stdout.write(self.style.SUCCESS(f"HTTP call succeeded in {elapsed_ms} ms"))
        self.stdout.write(f"model reported by the API: {result.model}")
        self.stdout.write(f"usage: {result.usage or 'not reported'}")
        self.stdout.write(f"reply (first 200 chars): {result.text[:200]!r}")
        try:
            parsed = parse_model_json(result.text)
        except ValueError as exc:
            raise CommandError(
                f"The reply is not a JSON object ({exc}). Try META_JSON_MODE=true or check the model id."
            ) from exc
        self.stdout.write(self.style.SUCCESS(f"reply parsed as JSON: {parsed}"))
