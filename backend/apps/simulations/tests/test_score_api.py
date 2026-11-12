import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

from apps.projects.models import Project

FIX = {
    "action": "replace_ingress_source",
    "security_group_id": "sg-db",
    "protocol": "tcp",
    "port": 5432,
    "new_source_security_group_id": "sg-app",
}


@pytest.fixture(autouse=True)
def _clear_throttle_cache():
    cache.clear()


@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def snapshot_id(client, db):
    project = Project.objects.create(name="Demo")
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/",
        {"fixture": "public_database"},
        format="json",
    )
    assert response.status_code == 201, response.json()
    return response.json()["id"]


def test_simulation_response_includes_before_and_after_score(client, snapshot_id):
    response = client.post(
        f"/api/snapshots/{snapshot_id}/simulations/", {"proposed_change": FIX}, format="json"
    )
    assert response.status_code == 201, response.json()
    score = response.json()["score"]
    assert score["before"]["value"] < score["after"]["value"]
    assert score["delta"] == score["after"]["value"] - score["before"]["value"]
    assert score["before"]["grade"] in {"A", "B", "C", "D", "F"}


def test_stored_simulation_detail_also_has_the_score(client, snapshot_id):
    created = client.post(
        f"/api/snapshots/{snapshot_id}/simulations/", {"proposed_change": FIX}, format="json"
    ).json()
    detail = client.get(f"/api/simulations/{created['id']}/").json()
    assert detail["score"] == created["score"]


def test_findings_payload_has_score_only_after_analysis(client, snapshot_id):
    before = client.get(f"/api/snapshots/{snapshot_id}/findings/").json()
    assert before["analysis"] is None
    assert before["score"] is None

    analysed = client.post(f"/api/snapshots/{snapshot_id}/analyze/").json()
    assert analysed["score"]["value"] < 100
    assert analysed["score"]["max"] == 100

    stored = client.get(f"/api/snapshots/{snapshot_id}/findings/").json()
    assert stored["score"] == analysed["score"]


def test_score_ignores_the_severity_filter(client, snapshot_id):
    full = client.post(f"/api/snapshots/{snapshot_id}/analyze/").json()["score"]
    filtered = client.get(f"/api/snapshots/{snapshot_id}/findings/?severity=info").json()
    assert filtered["score"] == full
