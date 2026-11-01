"""Explain a finding with the configured model, validate the output, never apply anything."""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import timedelta

from django.conf import settings
from django.db.models import Sum
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import APIException

from apps.cloud_resources.services.topology import SnapshotIncompatible
from apps.security_engine.models import SecurityFinding
from domain.network.proposals import ProposalError, parse_answer
from domain.network.schema import ConfigValidationError, parse_config
from domain.network.topology import build_topology

from ..deterministic import answer_from_payload
from ..models import AIInteraction
from ..prompts import PROMPT_VERSION, build_messages, build_payload
from ..providers import ProviderError, get_provider

logger = logging.getLogger(__name__)

MAX_MODEL_TEXT = 50_000
_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")

__all__ = [
    "AIBudgetExceeded",
    "SnapshotIncompatible",
    "explain_finding",
    "interaction_payload",
    "latest_interaction",
]


class AIBudgetExceeded(APIException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = "The hourly limit for Meta model calls has been reached. Try again later."
    default_code = "ai_budget_exceeded"


def parse_model_json(text: str) -> dict:
    """Extract one JSON object from model text (tolerates markdown fences and chatter)."""
    if len(text) > MAX_MODEL_TEXT:
        raise ValueError("model output too long")
    cleaned = _FENCE.sub("", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("model output contains no JSON object")
    value = json.loads(cleaned[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("model output is not a JSON object")
    return value


def latest_interaction(finding: SecurityFinding) -> AIInteraction | None:
    return finding.ai_interactions.first()


def interaction_payload(interaction: AIInteraction | None, *, cached: bool = False) -> dict | None:
    if interaction is None:
        return None
    return {
        "id": interaction.id,
        "finding": interaction.finding_id,
        "status": interaction.status,
        "source": interaction.source,
        "provider": interaction.provider,
        "model": interaction.model_id,
        "is_meta_model": interaction.source == AIInteraction.Source.META_MODEL,
        "fallback_reason": interaction.fallback_reason or None,
        "cached": cached,
        "attempts": interaction.attempts,
        "latency_ms": interaction.latency_ms,
        "prompt_version": interaction.prompt_version,
        "created_at": interaction.created_at,
        **interaction.response_json,
    }


def _check_budget(provider_name: str) -> None:
    if provider_name != "meta":
        return
    since = timezone.now() - timedelta(hours=1)
    used = (
        AIInteraction.objects.filter(provider="meta", created_at__gte=since).aggregate(n=Sum("attempts"))["n"]
        or 0
    )
    if used >= settings.AI_MAX_REQUESTS_PER_HOUR:
        raise AIBudgetExceeded()


def explain_finding(finding: SecurityFinding, *, refresh: bool = False) -> tuple[AIInteraction, bool]:
    """Return ``(interaction, cached)``. Reuses a previous valid answer unless ``refresh``."""
    provider = get_provider()

    if not refresh:
        previous = (
            finding.ai_interactions.filter(
                status=AIInteraction.Status.OK, prompt_version=PROMPT_VERSION, provider=provider.name
            )
            .order_by("-id")
            .first()
        )
        if previous is not None:
            return previous, True

    snapshot = finding.snapshot
    try:
        config = parse_config(snapshot.raw_json)
    except ConfigValidationError as exc:
        raise SnapshotIncompatible([issue.as_dict() for issue in exc.errors]) from exc

    subnet_public = {
        n.id: n.data.get("kind") == "public" for n in build_topology(config).nodes if n.type == "subnet"
    }
    finding_dict = {
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity,
        "resource_id": finding.resource_id,
        "evidence": finding.evidence,
    }
    payload = build_payload(finding_dict, config, subnet_public)

    _check_budget(provider.name)

    started = time.monotonic()
    attempts = 0
    usage: dict = {}
    repair: list[str] | None = None
    reason = ""
    answer = None
    model_id = provider.model

    for _ in range(max(1, settings.AI_MAX_ATTEMPTS)):
        attempts += 1
        system, user = build_messages(payload, repair)
        try:
            result = provider.complete(system, user)
        except ProviderError as exc:
            reason = str(exc)
            logger.warning("AI provider error (attempt %s): %s", attempts, reason)
            if not exc.retryable:
                break
            continue
        usage, model_id = result.usage, result.model or model_id
        try:
            answer = parse_answer(parse_model_json(result.text), config, finding.resource_id)
            break
        except (ValueError, ProposalError) as exc:
            repair = exc.errors if isinstance(exc, ProposalError) else [str(exc)]
            reason = "The model's answer failed validation: " + "; ".join(repair)[:500]
            logger.warning("AI output rejected (attempt %s): %s", attempts, reason)

    elapsed = int((time.monotonic() - started) * 1000)

    if answer is not None:
        source = (
            AIInteraction.Source.META_MODEL if provider.name == "meta" else AIInteraction.Source.OFFLINE_DEMO
        )
        record_status, stored_reason = AIInteraction.Status.OK, ""
    else:
        answer = parse_answer(answer_from_payload(payload), config, finding.resource_id)
        source, record_status = AIInteraction.Source.FALLBACK, AIInteraction.Status.FALLBACK
        stored_reason = reason or "The model did not return a usable answer."
        model_id = ""

    interaction = AIInteraction.objects.create(
        project=snapshot.project,
        finding=finding,
        provider=provider.name,
        model_id=model_id[:128],
        source=source,
        status=record_status,
        prompt_version=PROMPT_VERSION,
        response_json=answer.as_dict(),
        fallback_reason=stored_reason,
        attempts=attempts,
        latency_ms=elapsed,
        usage=usage,
    )
    return interaction, False