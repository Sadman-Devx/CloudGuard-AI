import pytest
from rest_framework.test import APIClient

from apps.cloud_resources.models import ConfigurationSnapshot
from apps.projects.models import Project


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


def test_topology_for_imported_fixture(client, project):
    snapshot_id = import_fixture(client, project, "exposed_database")
    response = client.get(f"/api/snapshots/{snapshot_id}/topology/")
    assert response.status_code == 200
    body = response.json()
    assert body["snapshot"] == snapshot_id and body["version"] == 1
    assert body["name"] == "Exposed database rules"
    assert body["issues"] == []
    assert body["summary"]["node_count"] == len(body["nodes"]) == 13
    assert body["summary"]["edge_count"] == len(body["edges"])
    assert body["summary"]["public_subnets"] == ["subnet-public"]
    types = {n["type"] for n in body["nodes"]}
    assert types == {
        "internet",
        "vpc",
        "internet_gateway",
        "route_table",
        "subnet",
        "security_group",
        "instance",
    }
    subnet = next(n for n in body["nodes"] if n["id"] == "subnet-private")
    assert subnet["data"]["kind"] == "private" and subnet["parent"] == "vpc-main"
    ids = {n["id"] for n in body["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in body["edges"])


def test_topology_reports_one_sided_flow(client, project):
    snapshot_id = import_fixture(client, project, "broken_app_connectivity")
    body = client.get(f"/api/snapshots/{snapshot_id}/topology/").json()
    assert body["summary"]["one_sided_sg_flows"] == ["sg-app->sg-db"]
    flow = next(e for e in body["edges"] if e["id"] == "sg_traffic:sg-app->sg-db")
    assert flow["data"]["sides"] == "egress_only"


def test_topology_is_stable_across_requests_and_versions(client, project):
    first = import_fixture(client, project, "safe_network")
    second = import_fixture(client, project, "safe_network")
    a = client.get(f"/api/snapshots/{first}/topology/").json()
    b = client.get(f"/api/snapshots/{second}/topology/").json()
    assert (a["version"], b["version"]) == (1, 2)
    assert a["nodes"] == b["nodes"] and a["edges"] == b["edges"]
    assert client.get(f"/api/snapshots/{first}/topology/").json() == a


def test_topology_unknown_snapshot_returns_404_envelope(client, db):
    response = client.get("/api/snapshots/9999/topology/")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_topology_is_read_only(client, project):
    snapshot_id = import_fixture(client, project, "safe_network")
    assert client.post(f"/api/snapshots/{snapshot_id}/topology/", {}, format="json").status_code == 405
    assert ConfigurationSnapshot.objects.count() == 1


def test_topology_does_not_modify_snapshot(client, project):
    snapshot_id = import_fixture(client, project, "safe_network")
    before = ConfigurationSnapshot.objects.get(pk=snapshot_id).raw_json
    client.get(f"/api/snapshots/{snapshot_id}/topology/")
    assert ConfigurationSnapshot.objects.get(pk=snapshot_id).raw_json == before


def test_incompatible_stored_snapshot_returns_422_not_500(client, project):
    snapshot_id = import_fixture(client, project, "safe_network")
    # Simulate a future schema change: bypass the immutable save() the way a data migration would.
    ConfigurationSnapshot.objects.filter(pk=snapshot_id).update(raw_json={"schema_version": "0.1"})
    response = client.get(f"/api/snapshots/{snapshot_id}/topology/")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_configuration"