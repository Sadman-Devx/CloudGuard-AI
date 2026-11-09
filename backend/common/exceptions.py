"""Predictable API error envelope.

Every error response has the shape:
    {"error": {"code": "<machine_code>", "message": "<human text>",
               "details": <optional>, "request_id": "<id>"}}

That includes failures nobody planned for: an unhandled exception becomes a generic
``internal_error`` (the traceback goes to the log with the request id, never to the client).
"""

import logging
from typing import Any

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import RequestDataTooBig
from django.http import Http404
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import exception_handler, set_rollback

logger = logging.getLogger(__name__)


class ConfigValidationFailed(Exception):
    """Raised by services when an uploaded configuration is invalid."""

    def __init__(self, errors: list[dict]):
        super().__init__("Configuration validation failed")
        self.errors = errors


class PayloadTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = "Request body is too large."
    default_code = "payload_too_large"


def error_body(code: str, message: str, request_id: str | None = None, details: Any = None) -> dict:
    """The one place that builds the envelope, shared by DRF and plain Django responses."""
    error: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    if request_id:
        error["request_id"] = request_id
    return {"error": error}


def _request_id(context) -> str | None:
    request = context.get("request") if context else None
    return getattr(getattr(request, "_request", request), "request_id", None)


def api_exception_handler(exc, context):
    request_id = _request_id(context)

    if isinstance(exc, ConfigValidationFailed):
        body = error_body(
            "invalid_configuration", "The uploaded configuration is invalid.", request_id, exc.errors
        )
        return Response(body, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    if isinstance(exc, RequestDataTooBig):
        body = error_body("payload_too_large", "Request body is too large.", request_id)
        return Response(body, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    response = exception_handler(exc, context)
    if response is None:
        # Not an API error: a genuine bug. Keep the details in the log, give the client an id.
        logger.error("Unhandled error (request_id=%s)", request_id, exc_info=exc)
        set_rollback()
        body = error_body("internal_error", "An unexpected error occurred.", request_id)
        return Response(body, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # DRF converts Django's Http404/PermissionDenied internally; mirror that here so the
    # envelope carries the right machine code instead of a generic "error".
    if isinstance(exc, Http404):
        exc = NotFound()
    elif isinstance(exc, DjangoPermissionDenied):
        exc = PermissionDenied()

    if isinstance(exc, ValidationError):
        code, message = "validation_error", "Request validation failed."
        details = response.data
    else:
        code = getattr(exc, "default_code", "error")
        message = str(getattr(exc, "detail", "Request failed."))
        details = None

    response.data = error_body(code, message, request_id, details)
    return response