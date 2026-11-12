from django.urls import path

from . import views

urlpatterns = [
    path("graph/", views.graph, name="attack-path-graph"),
    path("paths/", views.paths, name="attack-path-paths"),
    path("blast-radius/<str:node_id>/", views.blast_radius, name="attack-path-blast-radius"),
    path("simulate/", views.simulate, name="attack-path-simulate"),
]
