from django.urls import path

from . import views

urlpatterns = [
    path("copilot/status/", views.CopilotStatusView.as_view(), name="copilot-status"),
    path("findings/<int:pk>/explain/", views.FindingExplainView.as_view(), name="finding-explain"),
]