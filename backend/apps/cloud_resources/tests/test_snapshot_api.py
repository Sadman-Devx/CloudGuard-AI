import json

import pytest
from rest_framework.test import APIClient

from apps.cloud_resources.models import CloudResource, ConfigurationSnapshot, NetworkRelationship
from apps.projects.models import Project


@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def project(db):
    return Project.objects.create(name="Demo")


def upload(client, project, data, **extra):
    return client.post(f"/api/projects/{project.id}/snapshots/", data, format="json", **extra)


def row_counts():
    return (
        ConfigurationSnapshot.objects.count(),
        CloudResource.objects.count(),
        NetworkRelationship.objects.count(),
    )


# --------------------------------------------------------------------------- success


def test_upload_fixture_creates_validated_inventory(client, project, sample_fixture):
    name, data = sample_fixture
    response = upload(client, project, data)
    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["version"] == 1
    assert body["project"] == project.id
    assert body["source_type"] == "upload"
    assert body["resource_counts"] == {
        "vpc": 1,
        "subnet": 2,
        "internet_gateway": 1,
        "route_table": 2,
        "security_group": 3,
        "network_acl": 0,
        "instance": 3,
    }
    assert body["warnings"] == []
    assert "raw_json" not in body

    snapshot = ConfigurationSnapshot.objects.get(pk=body["id"])
    assert snapshot.raw_json == data  # exact input preserved for reproducibility
    assert snapshot.resources.count() == 12
    assert snapshot.relationships.count() == body["relationship_count"]


def test_versions_increment_per_project(client, project, db, valid_config):
    other = Project.objects.create(name="Other")
    assert upload(client, project, valid_config).json()["version"] == 1
    assert upload(client, project, valid_config).json()["version"] == 2
    assert upload(client, other, valid_config).json()["version"] == 1


def test_warnings_are_returned_and_stored(client, project, valid_config):
    valid_config["security_groups"].append(
        {"id": "sg-idle", "vpc_id": "vpc-1", "name": "idle", "ingress": [], "egress": []}
    )
    body = upload(client, project, valid_config).json()
    assert [w["code"] for w in body["warnings"]] == ["unused_security_group"]


def test_same_external_id_allowed_across_snapshots(client, project, valid_config):
    upload(client, project, valid_config)
    upload(client, project, valid_config)
    assert CloudResource.objects.filter(external_id="vpc-1").count() == 2


def test_source_name_header_is_recorded_and_truncated(client, project, valid_config):
    body = upload(client, project, valid_config, HTTP_X_SOURCE_NAME="n" * 500).json()
    assert len(body["source_name"]) == 128


def test_relationships_point_at_resources_of_same_snapshot(client, project, valid_config):
    upload(client, project, valid_config)
    upload(client, project, valid_config)
    for rel in NetworkRelationship.objects.select_related("source", "target"):
        assert rel.source.snapshot_id == rel.snapshot_id == rel.target.snapshot_id


# --------------------------------------------------------------------------- rejection


def test_invalid_config_returns_422_and_persists_nothing(client, project, valid_config):
    valid_config["vpcs"][0]["cidr"] = "not-a-cidr"
    valid_config["instances"][0]["private_ip"] = "300.1.1.1"
    response = upload(client, project, valid_config)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_configuration"
    assert {"vpcs[0].cidr", "instances[0].private_ip"} <= {d["path"] for d in error["details"]}
    assert all({"path", "code", "message"} <= set(d) for d in error["details"])
    assert row_counts() == (0, 0, 0)


def test_failed_upload_does_not_consume_a_version(client, project, valid_config):
    assert upload(client, project, valid_config).json()["version"] == 1
    bad = json.loads(json.dumps(valid_config))
    bad["vpcs"] = []
    assert upload(client, project, bad).status_code == 422
    assert upload(client, project, valid_config).json()["version"] == 2


def test_non_object_json_is_rejected(client, project):
    response = upload(client, project, [1, 2, 3])
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["code"] == "invalid_type"


def test_malformed_json_returns_400(client, project):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/", data="{not json", content_type="application/json"
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "parse_error"
    assert row_counts() == (0, 0, 0)


def test_non_json_content_type_returns_415(client, project):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/", data="a=b", content_type="application/x-www-form-urlencoded"
    )
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_media_type"


def test_nan_constants_are_rejected(client, project):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/",
        data='{"schema_version": NaN}',
        content_type="application/json",
    )
    assert response.status_code == 400


def test_oversized_body_returns_413(client, project, valid_config, settings):
    settings.MAX_UPLOAD_BYTES = 200
    response = upload(client, project, valid_config)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"
    assert row_counts() == (0, 0, 0)


def test_deeply_nested_json_rejected_cleanly(client, project, settings):
    settings.MAX_JSON_DEPTH = 6
    nested = {
        "schema_version": "1.0",
        "vpcs": [{"id": "vpc-1", "cidr": "10.0.0.0/16", "name": [[[[[[1]]]]]]}],
    }
    response = upload(client, project, nested)
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["code"] == "too_deeply_nested"


def test_pathologically_nested_json_does_not_crash_server(client, project):
    body = "[" * 200_000 + "]" * 200_000
    response = client.post(
        f"/api/projects/{project.id}/snapshots/", data=body, content_type="application/json"
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "parse_error"


def test_upload_to_missing_project_returns_404(client, db, valid_config):
    response = client.post("/api/projects/9999/snapshots/", valid_config, format="json")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_database_failure_mid_import_rolls_back(client, project, valid_config, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(NetworkRelationship.objects, "bulk_create", boom)
    client.raise_request_exception = False
    response = upload(client, project, valid_config)
    assert response.status_code == 500
    assert row_counts() == (0, 0, 0)


# --------------------------------------------------------------------------- reading


def test_snapshot_list_and_detail_and_project_isolation(client, project, db, valid_config):
    other = Project.objects.create(name="Other")
    first = upload(client, project, valid_config).json()
    upload(client, project, valid_config)
    upload(client, other, valid_config)

    listing = client.get(f"/api/projects/{project.id}/snapshots/").json()
    assert listing["count"] == 2
    assert [s["version"] for s in listing["results"]] == [2, 1]  # newest first
    assert all(s["project"] == project.id for s in listing["results"])

    detail = client.get(f"/api/snapshots/{first['id']}/")
    assert detail.status_code == 200
    assert detail.json()["version"] == 1
    assert client.get("/api/snapshots/9999/").status_code == 404
    assert client.get("/api/projects/9999/snapshots/").status_code == 404


def test_resource_listing_and_type_filter(client, project, valid_config):
    snapshot_id = upload(client, project, valid_config).json()["id"]
    everything = client.get(f"/api/snapshots/{snapshot_id}/resources/").json()
    assert everything["count"] == 8  # vpc, igw, route table, subnet, 2 SGs, ACL, instance
    only_sg = client.get(f"/api/snapshots/{snapshot_id}/resources/?type=security_group").json()
    assert {r["external_id"] for r in only_sg["results"]} == {"sg-1", "sg-2"}
    assert all(r["resource_type"] == "security_group" for r in only_sg["results"])
    instance = client.get(f"/api/snapshots/{snapshot_id}/resources/?type=instance").json()["results"][0]
    assert instance["metadata"]["private_ip"] == "10.0.1.10"
    assert instance["metadata"]["tags"] == {"tier": "web"}


def test_resources_of_unknown_snapshot_is_404(client, db):
    assert client.get("/api/snapshots/9999/resources/").status_code == 404


def test_snapshot_is_immutable(client, project, valid_config):
    snapshot = ConfigurationSnapshot.objects.get(pk=upload(client, project, valid_config).json()["id"])
    snapshot.name = "changed"
    with pytest.raises(ValueError, match="immutable"):
        snapshot.save()


def test_deleting_project_cascades(client, project, valid_config):
    upload(client, project, valid_config)
    project.delete()
    assert row_counts() == (0, 0, 0)


# --------------------------------------------------------------------------- fixtures


def test_fixture_listing(client, db):
    names = {f["name"] for f in client.get("/api/fixtures/").json()["results"]}
    assert names == {"safe_network", "exposed_database", "broken_app_connectivity"}


def test_import_from_fixture(client, project):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": "exposed_database"}, format="json"
    )
    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["source_type"] == "fixture"
    assert body["source_name"] == "exposed_database"
    assert body["name"] == "Exposed database rules"
    assert body["resource_counts"]["security_group"] == 3


@pytest.mark.parametrize(
    "name",
    ["nope", "../../etc/passwd", "safe_network.json", "/etc/passwd", "safe_network/../exposed_database"],
)
def test_unknown_or_traversal_fixture_names_rejected(client, project, name):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": name}, format="json"
    )
    assert response.status_code == 400
    assert "fixture" in response.json()["error"]["details"]
    assert row_counts() == (0, 0, 0)


def test_fixture_import_requires_name(client, project):
    response = client.post(f"/api/projects/{project.id}/snapshots/from-fixture/", {}, format="json")
    assert response.status_code == 400


def test_fixture_import_into_missing_project(client, db):
    response = client.post(
        "/api/projects/9999/snapshots/from-fixture/", {"fixture": "safe_network"}, format="json"
    )
    assert response.status_code == 404
