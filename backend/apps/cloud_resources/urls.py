from django.urls import path

from . import views

urlpatterns = [
    path("fixtures/", views.FixtureListView.as_view(), name="fixture-list"),
    path(
        "projects/<int:project_id>/snapshots/",
        views.ProjectSnapshotsView.as_view(),
        name="project-snapshots",
    ),
    path(
        "projects/<int:project_id>/snapshots/from-fixture/",
        views.ProjectFixtureImportView.as_view(),
        name="project-snapshot-from-fixture",
    ),
    path("snapshots/<int:pk>/", views.SnapshotDetailView.as_view(), name="snapshot-detail"),
    path("snapshots/<int:pk>/topology/", views.SnapshotTopologyView.as_view(), name="snapshot-topology"),
    path(
        "snapshots/<int:snapshot_id>/resources/",
        views.SnapshotResourcesView.as_view(),
        name="snapshot-resources",
    ),
]