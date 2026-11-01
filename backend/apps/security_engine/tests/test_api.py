import pytest
from rest_framework.test import APIClient

from apps.cloud_resources.models import ConfigurationSnapshot
from apps.projects.models import Project
from apps.security_engine.models import AnalysisRun, SecurityFinding


@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def project(db):
    return Project.objects.create(name="Demo")


def import_fixture(client, project, name):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": name}, format="json"
    )
    assert response.status_code == 201, response.json()
    return response.json()["id"]


def test_findings_before_analysis_is_null_not_empty_success(client, project):
    sid = import_fixture(client, project, "exposed_database")
    body = client.get(f"/api/snapshots/{sid}/findings/").json()
    assert body == {"snapshot": sid, "analysis": None, "results": []}


def test_analyze_exposed_database_persists_findings(client, project):
    sid = import_fixture(client, project, "exposed_database")
    response = client.post(f"/api/snapshots/{sid}/analyze/")
    assert response.status_code == 200
    body = response.json()
    assert body["analysis"]["rules_version"] == "1.0"
    assert body["analysis"]["summary"]["total"] == 4
    assert [(f["rule_id"], f["resource_id"]) for f in body["results"]] == [
        ("SG-001", "sg-web"),
        ("SG-003", "sg-db"),
        ("SG-004", "sg-db"),
        ("SG-006", "sg-app"),
    ]
    assert SecurityFinding.objects.filter(snapshot_id=sid).count() == 4

    stored = client.get(f"/api/snapshots/{sid}/findings/").json()
    assert stored["results"] == body["results"]
    assert stored["analysis"]["summary"]["by_severity"]["high"] == 1


def test_analyze_safe_network_is_analysed_with_zero_findings(client, project):
    sid = import_fixture(client, project, "safe_network")
    body = client.post(f"/api/snapshots/{sid}/analyze/").json()
    assert body["results"] == []
    assert body["analysis"]["summary"]["total"] == 0
    # "analysed, nothing found" is distinguishable from "never analysed"
    assert client.get(f"/api/snapshots/{sid}/findings/").json()["analysis"] is not None


def test_analyze_is_idempotent(client, project):
    sid = import_fixture(client, project, "exposed_database")
    first = client.post(f"/api/snapshots/{sid}/analyze/").json()["results"]
    second = client.post(f"/api/snapshots/{sid}/analyze/").json()["results"]
    assert [f["rule_id"] for f in first] == [f["rule_id"] for f in second]
    assert SecurityFinding.objects.filter(snapshot_id=sid).count() == 4
    assert AnalysisRun.objects.filter(snapshot_id=sid).count() == 1


def test_analysis_does_not_modify_snapshot(client, project):
    sid = import_fixture(client, project, "exposed_database")
    before = ConfigurationSnapshot.objects.get(pk=sid).raw_json
    client.post(f"/api/snapshots/{sid}/analyze/")
    assert ConfigurationSnapshot.objects.get(pk=sid).raw_json == before


def test_snapshots_are_analysed_independently(client, project):
    risky = import_fixture(client, project, "exposed_database")
    safe = import_fixture(client, project, "safe_network")
    client.post(f"/api/snapshots/{risky}/analyze/")
    assert client.get(f"/api/snapshots/{safe}/findings/").json()["analysis"] is None
    client.post(f"/api/snapshots/{safe}/analyze/")
    assert SecurityFinding.objects.filter(snapshot_id=risky).count() == 4


def test_filter_by_severity_and_rule(client, project):
    sid = import_fixture(client, project, "exposed_database")
    client.post(f"/api/snapshots/{sid}/analyze/")
    medium = client.get(f"/api/snapshots/{sid}/findings/?severity=medium").json()["results"]
    assert {f["rule_id"] for f in medium} == {"SG-003", "SG-004"}
    only = client.get(f"/api/snapshots/{sid}/findings/?rule_id=SG-006").json()["results"]
    assert [f["resource_id"] for f in only] == ["sg-app"]


def test_invalid_severity_filter_is_400(client, project):
    sid = import_fixture(client, project, "exposed_database")
    response = client.get(f"/api/snapshots/{sid}/findings/?severity=severe")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


def test_unknown_snapshot_is_404_envelope(client, db):
    for method, url in (("post", "/api/snapshots/999/analyze/"), ("get", "/api/snapshots/999/findings/")):
        response = getattr(client, method)(url)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


def test_finding_detail(client, project):
    sid = import_fixture(client, project, "exposed_database")
    first = client.post(f"/api/snapshots/{sid}/analyze/").json()["results"][0]
    detail = client.get(f"/api/findings/{first['id']}/")
    assert detail.status_code == 200
    body = detail.json()
    assert body["rule_id"] == "SG-001"
    assert body["evidence"]["matching_rules"][0]["from_port"] == 22
    assert body["remediation"]
    assert client.get("/api/findings/999999/").status_code == 404


def test_rule_catalog(client, db):
    body = client.get("/api/rules/").json()
    assert [r["id"] for r in body["results"]] == [f"SG-00{i}" for i in range(1, 7)]
    assert all(r["limitations"] and r["remediation"] for r in body["results"])


def test_deleting_snapshot_cascades(client, project):
    sid = import_fixture(client, project, "exposed_database")
    client.post(f"/api/snapshots/{sid}/analyze/")
    ConfigurationSnapshot.objects.filter(pk=sid).delete()
    assert not SecurityFinding.objects.exists() and not AnalysisRun.objects.exists()