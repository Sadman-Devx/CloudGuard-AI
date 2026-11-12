from django.conf import settings
from django.db import connection
from django.http import JsonResponse
from django.views import defaults
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers, status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response

from common.exceptions import error_body

HealthResponse = inline_serializer(
    "HealthResponse",
    fields={
        "status": serializers.ChoiceField(choices=["ok", "degraded"]),
        "service": serializers.CharField(),
        "version": serializers.CharField(),
        "database": serializers.ChoiceField(choices=["ok", "error"]),
    },
)


@extend_schema(responses={200: HealthResponse, 503: HealthResponse}, auth=[], tags=["health"])
@api_view(["GET"])
@authentication_classes([])
@permission_classes([])
def health(request):
    """Liveness + database connectivity check used by the UI, Docker and CI."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        database = "ok"
    except Exception:  # noqa: BLE001 - any DB failure means "degraded"
        database = "error"

    healthy = database == "ok"
    return Response(
        {
            "status": "ok" if healthy else "degraded",
            "service": "cloudguard-api",
            "version": settings.APP_VERSION,
            "database": database,
        },
        status=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def api_not_found(request, exception=None):
    """404 handler: JSON envelope under /api/ (unknown path, malformed id), Django's page elsewhere."""
    if request.path.startswith("/api/"):
        body = error_body("not_found", "No such API endpoint.", getattr(request, "request_id", None))
        return JsonResponse(body, status=404)
    return defaults.page_not_found(request, exception)


def api_server_error(request):
    """500 handler for failures outside DRF views (DRF views are handled by the exception handler)."""
    if request.path.startswith("/api/"):
        body = error_body(
            "internal_error", "An unexpected error occurred.", getattr(request, "request_id", None)
        )
        return JsonResponse(body, status=500)
    return defaults.server_error(request)
