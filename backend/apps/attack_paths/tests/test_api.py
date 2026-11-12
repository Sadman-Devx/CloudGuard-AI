import pytest
from rest_framework.test import APIClient


@pytest.fixture
def client():
    return APIClient()


def test_graph_and_attack_paths_are_available(client):
    graph = client.get("/api/attack-path/graph/")
    paths = client.get("/api/attack-path/paths/?top_k=8")

    assert graph.status_code == 200
    assert len(graph.json()["nodes"]) == 11
    assert paths.status_code == 200
    assert paths.json()["paths"]
    assert "choke_points" in paths.json()


def test_blast_radius_for_known_node(client):
    response = client.get("/api/attack-path/blast-radius/internet/")

    assert response.status_code == 200
    assert response.json()["start"]["id"] == "internet"
    assert {"alb", "jenkins"} <= {node["id"] for node in response.json()["reachable"]}


def test_blast_radius_for_unknown_node_returns_not_found(client):
    response = client.get("/api/attack-path/blast-radius/unknown/")

    assert response.status_code == 404


def test_simulation_returns_risk_comparison(client):
    response = client.post(
        "/api/attack-path/simulate/",
        {"remove_nodes": ["role_admin"]},
        format="json",
    )

    assert response.status_code == 200
    assert response.json()["risk_after"] < response.json()["risk_before"]


def test_simulation_rejects_unknown_nodes(client):
    response = client.post(
        "/api/attack-path/simulate/",
        {"remove_nodes": ["unknown"]},
        format="json",
    )

    assert response.status_code == 404
