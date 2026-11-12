from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from common.views import health

handler404 = "common.views.api_not_found"
handler500 = "common.views.api_server_error"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/health/", health, name="health"),
    path("api/", include("apps.projects.urls")),
    path("api/", include("apps.cloud_resources.urls")),
    path("api/", include("apps.security_engine.urls")),
    path("api/", include("apps.ai_copilot.urls")),
    path("api/", include("apps.simulations.urls")),
    path("api/attack-path/", include("apps.attack_paths.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="docs"),
]
