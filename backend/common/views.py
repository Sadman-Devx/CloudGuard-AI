from django.conf import settings
from django.db import connection
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework import serializers, status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response

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
