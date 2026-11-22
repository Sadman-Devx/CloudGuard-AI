from django.urls import path

from . import dashboard, views

urlpatterns = [
    path("rules/", views.RuleCatalogView.as_view(), name="rule-catalog"),
    path("snapshots/<int:pk>/analyze/", views.SnapshotAnalyzeView.as_view(), name="snapshot-analyze"),
    path("snapshots/<int:pk>/findings/", views.SnapshotFindingsView.as_view(), name="snapshot-findings"),
    path("dashboard/", dashboard.DashboardView.as_view(), name="dashboard"),
    path("projects/<int:pk>/dashboard/", dashboard.ProjectDashboardView.as_view(), name="project-dashboard"),
    path(
        "projects/<int:pk>/dashboard/refresh/",
        dashboard.ProjectDashboardRefreshView.as_view(),
        name="project-dashboard-refresh",
    ),
    path(
        "snapshots/<int:pk>/findings/by-instance/",
        views.SnapshotFindingsByInstanceView.as_view(),
        name="snapshot-findings-by-instance",
    ),
    path("findings/<int:pk>/", views.FindingDetailView.as_view(), name="finding-detail"),
]
