"""Predictable API error envelope.

Every error response has the shape:
    {"error": {"code": "<machine_code>", "message": "<human text>",
               "details": <optional>, "request_id": "<id>"}}
"""

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.http import Http404
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import exception_handler


class ConfigValidationFailed(Exception):
    """Raised by services when an uploaded configuration is invalid."""

    def __init__(self, errors: list[dict]):
        super().__init__("Configuration validation failed")
        self.errors = errors


class PayloadTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = "Request body is too large."
    default_code = "payload_too_large"


def _request_id(context) -> str | None:
    request = context.get("request") if context else None
    return getattr(getattr(request, "_request", request), "request_id", None)


def api_exception_handler(exc, context):
    request_id = _request_id(context)

    if isinstance(exc, ConfigValidationFailed):
        error = {
            "code": "invalid_configuration",
            "message": "The uploaded configuration is invalid.",
            "details": exc.errors,
        }
        if request_id:
            error["request_id"] = request_id
        return Response({"error": error}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

    response = exception_handler(exc, context)
    if response is None:
        return None

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

    error = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    if request_id:
        error["request_id"] = request_id
    response.data = {"error": error}
    return response
