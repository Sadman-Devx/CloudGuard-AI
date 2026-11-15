from django.urls import path

from . import views

urlpatterns = [
    path(
        "snapshots/<int:pk>/attack-path/graph/",
        views.SnapshotAttackGraphView.as_view(),
        name="snapshot-attack-graph",
    ),
    path(
        "snapshots/<int:pk>/attack-path/paths/",
        views.SnapshotAttackPathsView.as_view(),
        name="snapshot-attack-paths",
    ),
    path(
        "snapshots/<int:pk>/attack-path/blast-radius/<str:node_id>/",
        views.SnapshotBlastRadiusView.as_view(),
        name="snapshot-attack-blast-radius",
    ),
    path(
        "snapshots/<int:pk>/attack-path/simulate/",
        views.SnapshotAttackSimulateView.as_view(),
        name="snapshot-attack-simulate",
    ),
]
