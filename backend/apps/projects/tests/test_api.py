import pytest
from rest_framework.test import APIClient

from apps.projects.models import Project


@pytest.fixture
def client():
    return APIClient()


def test_create_and_list_projects(client, db):
    created = client.post("/api/projects/", {"name": "Demo", "description": "hackathon"}, format="json")
    assert created.status_code == 201
    body = created.json()
    assert body["name"] == "Demo" and body["id"] and body["created_at"]

    listing = client.get("/api/projects/")
    assert listing.status_code == 200
    data = listing.json()
    assert data["count"] == 1
    assert data["results"][0]["id"] == body["id"]


def test_projects_listed_newest_first(client, db):
    Project.objects.create(name="first")
    Project.objects.create(name="second")
    names = [p["name"] for p in client.get("/api/projects/").json()["results"]]
    assert names == ["second", "first"]


@pytest.mark.parametrize("payload", [{}, {"name": ""}, {"name": "   "}, {"name": "x" * 121}])
def test_create_project_rejects_bad_name(client, db, payload):
    response = client.post("/api/projects/", payload, format="json")
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert "name" in error["details"]
    assert Project.objects.count() == 0


def test_project_detail_and_404(client, db):
    project = Project.objects.create(name="Demo")
    assert client.get(f"/api/projects/{project.id}/").json()["name"] == "Demo"
    missing = client.get("/api/projects/9999/")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"


def test_read_only_fields_cannot_be_set(client, db):
    response = client.post(
        "/api/projects/", {"name": "Demo", "id": 999, "created_at": "2000-01-01T00:00:00Z"}, format="json"
    )
    assert response.status_code == 201
    assert response.json()["id"] != 999
    assert not response.json()["created_at"].startswith("2000")
