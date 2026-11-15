import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

from apps.projects.models import Project


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    cache.clear()


@pytest.fixture
def client():
    return APIClient()


def _snapshot(client, fixture):
    project = Project.objects.create(name="Demo")
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": fixture}, format="json"
    )
    assert response.status_code == 201
    return response.json()["id"]


@pytest.fixture
def snapshot_id(client, db):
    return _snapshot(client, "attack_path_demo")


def test_graph_comes_from_the_snapshot_not_the_demo(client, snapshot_id):
    data = client.get(f"/api/snapshots/{snapshot_id}/attack-path/graph/").json()
    ids = {n["id"] for n in data["nodes"]}
    assert data["demo"] is False and data["snapshot"] == snapshot_id
    assert {"i-web-1", "db-customers"} <= ids
    assert "jenkins" not in ids


def test_paths_and_choke_points(client, snapshot_id):
    data = client.get(f"/api/snapshots/{snapshot_id}/attack-path/paths/?top_k=5").json()
    assert data["paths"] and "choke_points" in data and "truncated" in data["search"]


def test_blast_radius_and_unknown_node(client, snapshot_id):
    ok = client.get(f"/api/snapshots/{snapshot_id}/attack-path/blast-radius/internet/")
    assert ok.status_code == 200 and ok.json()["start"]["id"] == "internet"
    missing = client.get(f"/api/snapshots/{snapshot_id}/attack-path/blast-radius/nope/")
    assert missing.status_code == 404


def test_simulate_a_security_group_change(client, snapshot_id):
    body = {
        "proposed_change": {
            "action": "replace_ingress_source",
            "security_group_id": "sg-db",
            "protocol": "tcp",
            "port": 5432,
            "new_source_security_group_id": "sg-app",
        }
    }
    response = client.post(f"/api/snapshots/{snapshot_id}/attack-path/simulate/", body, format="json")
    assert response.status_code == 200
    data = response.json()
    assert data["applied_to_cloud"] is False
    assert data["risk_after"] <= data["risk_before"]


def test_simulate_rejects_an_invalid_change(client, snapshot_id):
    body = {"proposed_change": {"action": "delete_everything", "security_group_id": "sg-db"}}
    response = client.post(f"/api/snapshots/{snapshot_id}/attack-path/simulate/", body, format="json")
    assert response.status_code == 400


def test_simulate_needs_something_to_simulate(client, snapshot_id):
    response = client.post(f"/api/snapshots/{snapshot_id}/attack-path/simulate/", {}, format="json")
    assert response.status_code == 400


def test_unknown_snapshot_is_404(client, db):
    assert client.get("/api/snapshots/999999/attack-path/paths/").status_code == 404


def test_demo_routes_are_labelled_demo(client):
    assert client.get("/api/attack-path/graph/").json()["demo"] is True
