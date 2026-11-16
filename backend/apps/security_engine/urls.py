from django.urls import path

from . import views

urlpatterns = [
    path("rules/", views.RuleCatalogView.as_view(), name="rule-catalog"),
    path("snapshots/<int:pk>/analyze/", views.SnapshotAnalyzeView.as_view(), name="snapshot-analyze"),
    path("snapshots/<int:pk>/findings/", views.SnapshotFindingsView.as_view(), name="snapshot-findings"),
    path(
        "snapshots/<int:pk>/findings/by-instance/",
        views.SnapshotFindingsByInstanceView.as_view(),
        name="snapshot-findings-by-instance",
    ),
    path("findings/<int:pk>/", views.FindingDetailView.as_view(), name="finding-detail"),
]
