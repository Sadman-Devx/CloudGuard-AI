import json
from pathlib import Path

import pytest
from rest_framework.test import APIClient

from apps.projects.models import Project

DATA = Path(__file__).resolve().parents[3] / "domain" / "network" / "tests" / "data"


@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def project(db):
    return Project.objects.create(name="Demo")


def test_terraform_plan_import_creates_a_snapshot_with_the_importer_notes(client, project):
    plan = json.loads((DATA / "terraform_plan.json").read_text())
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-iac/",
        {"format": "terraform", "content": plan, "name": "plan.json"},
        format="json",
    )
    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["source_type"] == "terraform"
    assert any(w["code"] == "UNSUPPORTED_ROUTE_TARGET" for w in body["import_report"]["warnings"])
    assert client.post(f"/api/snapshots/{body['id']}/analyze/").status_code == 200


def test_cloudformation_text_import(client, project):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-iac/",
        {"format": "cloudformation", "content": (DATA / "stack.yaml").read_text()},
        format="json",
    )
    assert response.status_code == 201, response.json()
    assert response.json()["source_type"] == "cloudformation"


def test_a_file_that_is_not_iac_is_rejected_with_a_message(client, project):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-iac/",
        {"format": "terraform", "content": "this is not json"},
        format="json",
    )
    assert response.status_code in (400, 422)
    assert "terraform show -json" in json.dumps(response.json())


def test_live_aws_import_is_off_by_default(client, project):
    status = client.get("/api/aws-import/status/").json()
    assert status["enabled"] is False
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-aws/", {"region": "us-east-1"}, format="json"
    )
    assert response.status_code == 403


def test_live_aws_import_validates_its_input_before_touching_aws(client, project, settings):
    settings.AWS_IMPORT_ENABLED = True
    url = f"/api/projects/{project.id}/snapshots/from-aws/"
    assert client.post(url, {"region": "not a region"}, format="json").status_code == 400
    bad_role = client.post(url, {"region": "us-east-1", "role_arn": "arn:aws:iam::1:role/x"}, format="json")
    assert bad_role.status_code == 400
    settings.AWS_IMPORT_ALLOWED_ROLE_ARNS = ["arn:aws:iam::123456789012:role/CloudGuardReadOnly"]
    other = client.post(
        url, {"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/Other"}, format="json"
    )
    assert other.status_code == 400
