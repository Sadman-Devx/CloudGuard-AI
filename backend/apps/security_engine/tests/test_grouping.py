import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

from apps.projects.models import Project
from apps.security_engine.services.grouping import group_by_instance


def _finding(fid, rule, severity, sg, instances, exposure="internet_facing_candidate"):
    return {
        "id": fid,
        "rule_id": rule,
        "severity": severity,
        "category": "risky_rule",
        "title": f"{rule} title",
        "resource_id": sg,
        "resource_name": sg,
        "summary": "s",
        "evidence": {"context": {"exposure": exposure, "attached_instances": instances}},
    }


def _inst(iid, public=True):
    return {"id": iid, "name": iid, "subnet_id": "s1", "subnet_kind": "public", "has_public_ip": public}


def test_a_shared_group_lists_its_finding_under_every_instance():
    shared = _finding(1, "SG-001", "high", "sg-web", [_inst("i-1"), _inst("i-2")])
    result = group_by_instance([shared])
    assert [i["id"] for i in result["instances"]] == ["i-1", "i-2"]
    assert all(i["findings"][0]["affected_instance_count"] == 2 for i in result["instances"])
    assert result["unattached"] == []


def test_instances_are_sorted_worst_first_and_findings_by_severity():
    findings = [
        _finding(1, "SG-006", "low", "sg-a", [_inst("i-low")]),
        _finding(2, "SG-004", "medium", "sg-b", [_inst("i-mid")]),
        _finding(3, "SG-001", "high", "sg-b", [_inst("i-mid")]),
    ]
    result = group_by_instance(findings)
    assert [i["id"] for i in result["instances"]] == ["i-mid", "i-low"]
    mid = result["instances"][0]
    assert mid["worst_severity"] == "high"
    assert [f["severity"] for f in mid["findings"]] == ["high", "medium"]
    assert mid["finding_count"] == 2 and mid["security_groups"] == ["sg-b"]


def test_findings_on_unused_groups_are_listed_separately():
    unused = _finding(9, "SG-001", "low", "sg-unused", [], exposure="unattached")
    result = group_by_instance([unused])
    assert result["instances"] == []
    assert [f["id"] for f in result["unattached"]] == [9]


@pytest.fixture
def client():
    cache.clear()
    return APIClient()


def test_api_groups_the_stored_findings(client, db):
    project = Project.objects.create(name="Demo")
    snap = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": "exposed_database"}, format="json"
    ).json()["id"]
    assert client.post(f"/api/snapshots/{snap}/analyze/").status_code == 200

    flat = client.get(f"/api/snapshots/{snap}/findings/").json()["results"]
    grouped = client.get(f"/api/snapshots/{snap}/findings/by-instance/").json()
    assert grouped["snapshot"] == snap and grouped["score"] is not None

    listed = {f["id"] for i in grouped["instances"] for f in i["findings"]}
    listed |= {f["id"] for f in grouped["unattached"]}
    assert listed == {f["id"] for f in flat}  # nothing lost, nothing invented
    for instance in grouped["instances"]:
        assert instance["finding_count"] == len(instance["findings"])


def test_api_for_an_unknown_snapshot_is_404(client, db):
    assert client.get("/api/snapshots/999/findings/by-instance/").status_code == 404
