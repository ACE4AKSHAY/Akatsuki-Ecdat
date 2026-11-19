"""Enterprise hardening: request context, health probes, security headers, audit trail."""
from __future__ import annotations

import json
import math

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.database import SessionLocal, engine, init_db
from backend.engine.orchestrator import run_scan_pipeline_sync
from backend.main import app
from backend.models.db_models import AuditEvent


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def scanned_asset(client):
    response = client.post("/scans", json={"target": "seed_corpus"})
    assert response.status_code == 202
    scan_id = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan_id, source_type="path", target="seed_corpus")
    items = client.get("/assets", params={"scanId": scan_id}).json()["items"]
    assert items
    return items[0]


@pytest.fixture(scope="module")
def scan_id(client):
    response = client.post("/scans", json={"target": "seed_corpus"})
    assert response.status_code == 202
    scan = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan, source_type="path", target="seed_corpus")
    return scan


def test_health_reports_version(client):
    payload = client.get("/health").json()
    assert payload["status"] == "healthy"
    assert payload["version"]
    assert payload["requestId"]


def test_readiness_reports_dependencies(client):
    response = client.get("/health/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["checks"]["database"] == "ok"
    assert payload["checks"]["standardsRegistry"] == "ok"
    assert payload["checks"]["detectionSignals"] == "ok"
    assert payload["standardsRegistry"]["entryCount"] > 0
    assert payload["standardsRegistry"]["version"]
    assert payload["build"]["commit"]


def test_request_id_is_generated_and_echoed(client):
    response = client.get("/health")
    request_id = response.headers.get("X-Request-ID")
    assert request_id
    assert response.json()["requestId"] == request_id


def test_inbound_request_id_is_preserved(client):
    response = client.get("/health", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers.get("X-Request-ID") == "trace-abc-123"


def test_security_headers_are_applied(client):
    headers = client.get("/health").headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert headers.get("Cache-Control") == "no-store"


def test_errors_carry_request_id(client):
    response = client.get("/assets/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body["detail"]
    assert body["statusCode"] == 404
    assert body["requestId"] == response.headers.get("X-Request-ID")


def test_validation_errors_are_structured(client):
    response = client.get("/assets", params={"pageSize": 5000})
    assert response.status_code == 422
    body = response.json()
    assert body["statusCode"] == 422
    assert body["requestId"]
    assert any(error["field"].endswith("pageSize") for error in body["errors"])


def test_context_override_is_recorded_in_the_audit_trail(client, scanned_asset):
    patched = client.patch(
        f"/assets/{scanned_asset['bom-ref']}/context",
        json={"usageContext": "password-storage", "operator": "security-reviewer"},
    )
    assert patched.status_code == 200

    with SessionLocal() as db:
        events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).all()
    assert events, "operator override must leave an audit record"
    event = events[0]
    assert event.action == "asset-context-override"
    assert event.actor == "security-reviewer"
    assert event.asset_ref == scanned_asset["bom-ref"]
    assert json.loads(event.after_json)["usageContext"] == "password-storage"


def test_audit_trail_records_the_request_id(client, scanned_asset):
    client.patch(
        f"/assets/{scanned_asset['bom-ref']}/context",
        json={"usageContext": "password-storage"},
        headers={"X-Request-ID": "audit-trace-1"},
    )
    with SessionLocal() as db:
        event = db.query(AuditEvent).filter(AuditEvent.request_id == "audit-trace-1").first()
    assert event is not None
    assert event.action == "asset-context-override"


def test_sqlite_pragmas_are_applied():
    with engine.connect() as connection:
        journal = connection.exec_driver_sql("PRAGMA journal_mode").scalar()
        foreign_keys = connection.exec_driver_sql("PRAGMA foreign_keys").scalar()
    if engine.url.get_backend_name() == "sqlite":
        assert str(journal).lower() == "wal"
        assert foreign_keys == 1


def test_operational_indexes_exist():
    if engine.url.get_backend_name() != "sqlite":
        pytest.skip("index assertions target the SQLite backend")
    with engine.connect() as connection:
        rows = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    names = {row[0] for row in rows}
    assert "idx_asset_scan_name" in names
    assert "idx_recommendation_asset" in names


def test_asset_listing_paginates_in_the_database(client, scan_id):
    full = client.get("/assets", params={"scanId": scan_id, "pageSize": 200}).json()
    assert full["total"] > 5
    assert len(full["items"]) == full["total"]

    first = client.get("/assets", params={"scanId": scan_id, "pageSize": 5, "page": 1}).json()
    second = client.get("/assets", params={"scanId": scan_id, "pageSize": 5, "page": 2}).json()
    assert first["total"] == full["total"]
    assert len(first["items"]) == 5
    assert len(second["items"]) == 5
    assert first["pages"] == math.ceil(full["total"] / 5)
    first_refs = {item["bom-ref"] for item in first["items"]}
    second_refs = {item["bom-ref"] for item in second["items"]}
    assert not (first_refs & second_refs)


def test_asset_listing_applies_filters_and_slider(client, scan_id):
    filtered = client.get("/assets", params={"scanId": scan_id, "artifactType": "algorithm"}).json()
    assert filtered["total"] >= 0
    for item in filtered["items"]:
        assert item["ecdatEnrichment"]["artifactType"] == "algorithm"

    slider = client.get("/assets", params={"scanId": scan_id, "z": 3}).json()
    assert slider["items"]
    assert slider["zUsed"] == 3
    for item in slider["items"]:
        assert item["ecdatEnrichment"]["moscaZ"] == 3


def test_unhandled_errors_return_a_generic_envelope():
    import asyncio

    from starlette.requests import Request

    from backend.main import unhandled_exception_handler

    scope = {"type": "http", "method": "GET", "path": "/boom", "headers": []}
    request = Request(scope)
    response = asyncio.run(unhandled_exception_handler(request, RuntimeError("secret detail")))
    body = json.loads(response.body)
    assert response.status_code == 500
    assert body["detail"] == "Internal server error."
    assert "secret detail" not in response.body.decode()
    assert body["requestId"]


def test_health_probes_stay_reachable_when_a_token_is_configured(monkeypatch):
    monkeypatch.setenv("ECDAT_API_TOKEN", "s3cret-token")
    # No context manager: the module fixture already owns the scan-worker lock.
    test_client = TestClient(app)
    assert test_client.get("/health").status_code == 200
    assert test_client.get("/health/ready").status_code == 200
    assert test_client.get("/assets").status_code == 401
    authorised = test_client.get("/assets", headers={"Authorization": "Bearer s3cret-token"})
    assert authorised.status_code == 200
