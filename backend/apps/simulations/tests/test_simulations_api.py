import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

from apps.cloud_resources.models import CloudResource, ConfigurationSnapshot
from apps.projects.models import Project
from apps.security_engine.models import SecurityFinding
from apps.simulations.models import Simulation

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
def project(db):
    return Project.objects.create(name="Demo")


def import_fixture(client, project, name):
    response = client.post(
        f"/api/projects/{project.id}/snapshots/from-fixture/", {"fixture": name}, format="json"
    )
    assert response.status_code == 201, response.json()
    return response.json()["id"]


@pytest.fixture
def public_db(client, project):
    return import_fixture(client, project, "public_database")


def simulate(client, sid, body):
    return client.post(f"/api/snapshots/{sid}/simulations/", body, format="json")


# ---- reachability endpoint ----------------------------------------------------------------


def test_reachability_reports_a_verified_exposure_with_trace(client, public_db):
    response = client.post(
        f"/api/snapshots/{public_db}/reachability/",
        {"source": "internet", "destination": "i-db-1", "protocol": "tcp", "port": 5432},
        format="json",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "allowed"
    assert body["security_group_risk"] == "OVERLY_BROAD_INGRESS"
    assert body["confidence_type"] == "deterministic_supported_subset"
    assert [s["check"] for s in body["trace"]][0] == "public_ip"


def test_reachability_distinguishes_risky_rule_from_reachable_path(client, project):
    sid = import_fixture(client, project, "exposed_database")
    body = client.post(
        f"/api/snapshots/{sid}/reachability/",
        {"source": "internet", "destination": "i-db-1", "protocol": "tcp", "port": 5432},
        format="json",
    ).json()
    assert body["result"] == "blocked"
    assert body["reason_codes"] == ["NO_PUBLIC_IP", "NO_PUBLIC_ROUTE"]
    assert body["security_group_risk"] == "OVERLY_BROAD_INGRESS"


def test_reachability_validation_and_not_found(client, public_db):
    bad = client.post(
        f"/api/snapshots/{public_db}/reachability/",
        {"source": "ghost", "destination": "i-db-1", "protocol": "tcp", "port": 1},
        format="json",
    )
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "validation_error"
    assert "source must be" in bad.json()["error"]["details"]["path"][0]
    assert client.post("/api/snapshots/99999/reachability/", {}, format="json").status_code == 404


def test_reachability_on_an_incompatible_stored_snapshot_is_422(client, public_db):
    ConfigurationSnapshot.objects.filter(pk=public_db).update(raw_json={"schema_version": "9"})
    response = client.post(
        f"/api/snapshots/{public_db}/reachability/",
        {"source": "internet", "destination": "i-db-1", "protocol": "tcp", "port": 5432},
        format="json",
    )
    assert response.status_code == 422


# ---- simulations --------------------------------------------------------------------------


def test_simulation_end_to_end_and_nothing_is_modified(client, public_db):
    client.post(f"/api/snapshots/{public_db}/analyze/")
    snapshot = ConfigurationSnapshot.objects.get(pk=public_db)
    raw_before = snapshot.raw_json
    resources_before = CloudResource.objects.filter(snapshot=snapshot).count()
    findings_before = list(SecurityFinding.objects.filter(snapshot=snapshot).values_list("id", "rule_id"))

    response = simulate(client, public_db, {"proposed_change": FIX})
    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["outcome"] == "improves_security"
    assert body["recommended"] is True
    assert body["applied_to_cloud"] is False
    assert body["status"] == "completed"
    assert body["result"]["required_paths_source"] == "inferred"
    assert body["required_paths"][0]["key"] == "i-app-1>i-db-1:tcp/5432"
    internet = next(c for c in body["result"]["connectivity"] if c["key"] == "internet>i-db-1:tcp/5432")
    assert (internet["before"], internet["after"]) == ("allowed", "blocked")
    assert body["before"]["paths"] and body["after"]["paths"]

    # The snapshot, its inventory and its stored findings are exactly as they were.
    snapshot.refresh_from_db()
    assert snapshot.raw_json == raw_before
    assert CloudResource.objects.filter(snapshot=snapshot).count() == resources_before
    assert (
        list(SecurityFinding.objects.filter(snapshot=snapshot).values_list("id", "rule_id"))
        == findings_before
    )

    detail = client.get(f"/api/simulations/{body['id']}/").json()
    assert detail == body


def test_simulation_history_is_paginated_and_omits_traces(client, public_db):
    first = simulate(client, public_db, {"proposed_change": FIX}).json()["id"]
    second = simulate(client, public_db, {"proposed_change": FIX}).json()["id"]
    listing = client.get(f"/api/snapshots/{public_db}/simulations/").json()
    assert listing["count"] == 2
    assert [r["id"] for r in listing["results"]] == [second, first]
    assert "before" not in listing["results"][0] and "result" not in listing["results"][0]
    assert client.get("/api/snapshots/99999/simulations/").status_code == 404


def test_explicit_required_path_that_would_break_is_reported_not_recommended(client, public_db):
    remove = {"action": "remove_ingress_rule", "security_group_id": "sg-db", "protocol": "tcp", "port": 5432}
    body = simulate(
        client,
        public_db,
        {
            "proposed_change": remove,
            "required_paths": [
                {"source": "i-app-1", "destination": "i-db-1", "protocol": "tcp", "port": 5432}
            ],
        },
    ).json()
    assert body["outcome"] == "breaks_required_connectivity"
    assert body["recommended"] is False


def test_simulation_from_a_stored_ai_explanation(client, project):
    sid = import_fixture(client, project, "exposed_database")
    findings = client.post(f"/api/snapshots/{sid}/analyze/").json()["results"]
    sg003 = next(f for f in findings if f["rule_id"] == "SG-003")
    interaction = client.post(f"/api/findings/{sg003['id']}/explain/", {}, format="json").json()[
        "interaction"
    ]
    assert interaction["proposed_change"] is not None

    response = simulate(client, sid, {"interaction_id": interaction["id"]})
    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["ai_interaction"] == interaction["id"]
    assert body["finding"] == sg003["id"]
    assert body["outcome"] == "improves_security"


def test_interaction_without_a_proposal_is_rejected(client, project):
    sid = import_fixture(client, project, "exposed_database")
    findings = client.post(f"/api/snapshots/{sid}/analyze/").json()["results"]
    sg006 = next(f for f in findings if f["rule_id"] == "SG-006")
    interaction = client.post(f"/api/findings/{sg006['id']}/explain/", {}, format="json").json()[
        "interaction"
    ]
    response = simulate(client, sid, {"interaction_id": interaction["id"]})
    assert response.status_code == 400
    assert "did not include a proposed change" in response.json()["error"]["details"]["interaction_id"][0]
    assert Simulation.objects.count() == 0


def test_a_proposal_from_another_snapshot_is_rejected(client, project):
    one = import_fixture(client, project, "exposed_database")
    two = import_fixture(client, project, "exposed_database")
    findings = client.post(f"/api/snapshots/{one}/analyze/").json()["results"]
    sg003 = next(f for f in findings if f["rule_id"] == "SG-003")
    interaction = client.post(f"/api/findings/{sg003['id']}/explain/", {}, format="json").json()[
        "interaction"
    ]
    response = simulate(client, two, {"interaction_id": interaction["id"]})
    assert response.status_code == 400
    assert "different snapshot" in response.json()["error"]["details"]["interaction_id"][0]


def test_finding_scopes_the_proposal_to_its_own_security_group(client, project):
    sid = import_fixture(client, project, "exposed_database")
    findings = client.post(f"/api/snapshots/{sid}/analyze/").json()["results"]
    sg001 = next(f for f in findings if f["rule_id"] == "SG-001")  # on sg-web
    response = simulate(client, sid, {"proposed_change": FIX, "finding_id": sg001["id"]})
    assert response.status_code == 400
    assert "may only change sg-web" in response.json()["error"]["details"]["proposed_change"][0]


@pytest.mark.parametrize(
    "body, field",
    [
        ({}, "non_field_errors"),
        ({"proposed_change": FIX, "interaction_id": 1}, "non_field_errors"),
        ({"proposed_change": FIX, "surprise": 1}, "non_field_errors"),
        ({"proposed_change": {**FIX, "security_group_id": "sg-ghost"}}, "proposed_change"),
        ({"proposed_change": {**FIX, "action": "delete_everything"}}, "proposed_change"),
        ({"proposed_change": FIX, "required_paths": [{"source": "x"}]}, "required_paths"),
        ({"proposed_change": FIX, "finding_id": 99999}, "finding_id"),
        ({"interaction_id": 99999}, "interaction_id"),
        ({"proposed_change": "nope"}, "proposed_change"),
    ],
)
def test_bad_requests_are_400_and_persist_nothing(client, public_db, body, field):
    response = simulate(client, public_db, body)
    assert response.status_code == 400, response.json()
    assert response.json()["error"]["code"] == "validation_error"
    assert field in response.json()["error"]["details"]
    assert Simulation.objects.count() == 0


def test_simulation_on_an_incompatible_snapshot_is_422(client, public_db):
    ConfigurationSnapshot.objects.filter(pk=public_db).update(raw_json={"schema_version": "9"})
    assert simulate(client, public_db, {"proposed_change": FIX}).status_code == 422


def test_unknown_resources_are_404(client, db):
    assert simulate(client, 99999, {"proposed_change": FIX}).status_code == 404
    assert client.get("/api/simulations/99999/").status_code == 404


def test_simulations_are_write_once(public_db):
    snapshot = ConfigurationSnapshot.objects.get(pk=public_db)
    sim = Simulation.objects.create(
        snapshot=snapshot, engine_version="1.0", outcome="no_effect", proposed_change_json={}
    )
    sim.outcome = "improves_security"
    with pytest.raises(ValueError, match="immutable"):
        sim.save()
