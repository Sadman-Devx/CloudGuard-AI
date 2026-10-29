import pytest
from rest_framework.test import APIClient


@pytest.fixture
def client():
    return APIClient()


def test_health_ok(client, db):
    response = client.get("/api/health/")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["service"] == "cloudguard-api"
    assert body["version"]


def test_health_reports_degraded_when_database_fails(client, monkeypatch):
    class BrokenConnection:
        def cursor(self):
            raise RuntimeError("database down")

    monkeypatch.setattr("common.views.connection", BrokenConnection())
    response = client.get("/api/health/")
    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["database"] == "error"


def test_health_rejects_post(client):
    response = client.post("/api/health/", {})
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


def test_response_carries_generated_request_id(client, db):
    response = client.get("/api/health/")
    assert len(response["X-Request-ID"]) == 32


def test_well_formed_client_request_id_is_echoed(client, db):
    response = client.get("/api/health/", headers={"X-Request-ID": "trace-12345678"})
    assert response["X-Request-ID"] == "trace-12345678"


def test_malformed_request_id_is_replaced(client, db):
    response = client.get("/api/health/", headers={"X-Request-ID": "bad id <script>"})
    assert response["X-Request-ID"] != "bad id <script>"
    assert len(response["X-Request-ID"]) == 32


def test_error_envelope_includes_request_id(client, db):
    response = client.post("/api/health/", {}, headers={"X-Request-ID": "trace-12345678"})
    assert response.json()["error"]["request_id"] == "trace-12345678"
