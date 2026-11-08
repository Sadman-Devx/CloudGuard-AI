# In config/urls.py add:  path("api/", include("apps.simulations.workflow_urls")),
from django.urls import path

from .workflow_views import ProjectDashboardView, SimulateProposalView

urlpatterns = [
    path("findings/<int:finding_id>/simulate-proposal/", SimulateProposalView.as_view()),
    path("projects/<int:project_id>/dashboard/", ProjectDashboardView.as_view()),
]
