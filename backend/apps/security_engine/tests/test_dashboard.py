import pytest
from rest_framework.test import APIClient

from apps.projects.models import Project


@pytest.fixture
def client():
    return APIClient()


def import_fixture(client, project, name):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": name}, format="json"
    )
    assert response.status_code == 201, response.json()
    return response.json()["id"]


def test_project_score_and_trend_come_from_the_analysed_snapshots(client, db):
    project = Project.objects.create(name="Demo")
    risky = import_fixture(client, project, "exposed_database")
    safe = import_fixture(client, project, "safe_network")
    client.post(f"/api/snapshots/{risky}/analyze/")
    client.post(f"/api/snapshots/{safe}/analyze/")

    body = client.get(f"/api/projects/{project.id}/dashboard/").json()
    assert [p["version"] for p in body["trend"]] == [1, 2]
    assert body["latest"]["snapshot_id"] == safe and body["analyzed_count"] == 2
    assert body["trend"][1]["score"] > body["trend"][0]["score"]  # the safe network scores higher
    assert body["delta"] == body["trend"][1]["score"] - body["trend"][0]["score"]


def test_top_rules_and_worst_findings_describe_the_latest_snapshot(client, db):
    project = Project.objects.create(name="Demo")
    sid = import_fixture(client, project, "exposed_database")
    client.post(f"/api/snapshots/{sid}/analyze/")
    body = client.get(f"/api/projects/{project.id}/dashboard/").json()
    assert body["top_rules"] and all(r["title"] for r in body["top_rules"])
    assert body["worst_resources"][0]["severity"] in ("critical", "high", "medium", "low")


def test_refresh_analyses_only_the_snapshots_that_have_no_analysis(client, db):
    project = Project.objects.create(name="Demo")
    first = import_fixture(client, project, "exposed_database")
    import_fixture(client, project, "safe_network")
    client.post(f"/api/snapshots/{first}/analyze/")

    before = client.get(f"/api/projects/{project.id}/dashboard/").json()
    assert before["unanalyzed_count"] == 1
    done = client.post(f"/api/projects/{project.id}/dashboard/refresh/").json()
    assert done["analyzed"] == 1 and done["remaining"] == 0
    after = client.get(f"/api/projects/{project.id}/dashboard/").json()
    assert after["unanalyzed_count"] == 0 and len(after["trend"]) == 2


def test_portfolio_lists_every_project_with_totals(client, db):
    analysed = Project.objects.create(name="A")
    Project.objects.create(name="B")
    sid = import_fixture(client, analysed, "exposed_database")
    client.post(f"/api/snapshots/{sid}/analyze/")
    body = client.get("/api/dashboard/").json()
    assert [p["name"] for p in body["projects"]] == ["A", "B"]
    assert body["projects"][1]["latest"] is None
    assert body["totals"]["projects"] == 2 and body["totals"]["analyzed_projects"] == 1


def test_unknown_project_is_404(client, db):
    assert client.get("/api/projects/999/dashboard/").status_code == 404
    assert client.post("/api/projects/999/dashboard/refresh/").status_code == 404
