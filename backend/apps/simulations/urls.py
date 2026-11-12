from django.urls import path

from . import views

urlpatterns = [
    path(
        "snapshots/<int:pk>/simulations/",
        views.SnapshotSimulationsView.as_view(),
        name="snapshot-simulations",
    ),
    path(
        "snapshots/<int:pk>/reachability/",
        views.SnapshotReachabilityView.as_view(),
        name="snapshot-reachability",
    ),
    path("simulations/<int:pk>/", views.SimulationDetailView.as_view(), name="simulation-detail"),
]
