"""Operational excellence: metrics, rate limiting, lifecycle audit, retention."""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.database import SessionLocal, init_db
from backend.engine.orchestrator import run_scan_pipeline_sync
from backend.main import app
from backend.metrics import record_request, record_scan_outcome, render_metrics
from backend.models.db_models import AuditEvent, Scan
from backend.ratelimit import RateLimitMiddleware, _positive_env
from backend.retention import get_retention_days, prune_expired_scans
from backend.version import VERSION


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture(scope="module")
def client():
    # No lifespan: this module must not contend for the worker lock with
    # other modules' clients.
    return TestClient(app)


def _sample(metric_name: str, text: str) -> list[str]:
    pattern = re.compile(rf"^{re.escape(metric_name)}(?:\{{[^}}]*\}})?\s+([0-9.eE+-]+)$", re.MULTILINE)
    return pattern.findall(text)


def test_metrics_endpoint_exposes_core_series(client):
    client.get("/health")
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "# TYPE ecdat_requests_total counter" in body
    assert "# TYPE ecdat_build_info gauge" in body
    build = [line for line in body.splitlines() if line.startswith("ecdat_build_info{")]
    assert build and f'version="{VERSION}"' in build[0]
    uptime = _sample("ecdat_process_uptime_seconds", body)
    assert uptime and float(uptime[0]) >= 0


def test_metrics_counts_requests_by_route_and_status(client):
    before = len(_sample("ecdat_requests_total", client.get("/metrics").text))
    client.get("/health")
    body = client.get("/metrics").text
    health_rows = [line for line in body.splitlines() if 'ecdat_requests_total{method="GET",route="/health"' in line]
    assert health_rows
    # Each recorded series carries a matching duration series.
    assert '# TYPE ecdat_request_duration_seconds_sum counter' in body


def test_metrics_records_scan_outcomes(client):
    record_scan_outcome("completed")
    body = render_metrics(version="1.3.0")
    assert _sample("ecdat_scan_outcomes_total", body)
    assert 'ecdat_scan_outcomes_total{outcome="completed"}' in body


def test_metrics_db_gauges_reflect_store(client):
    response = client.post("/scans", json={"target": "demo/workspace"})
    assert response.status_code == 202
    scan_id = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan_id, source_type="path", target="demo/workspace")

    body = client.get("/metrics").text
    completed = _sample('ecdat_scans_total{status="completed"}', body)
    assets = _sample("ecdat_assets_total", body)
    assert completed and int(float(completed[0])) >= 1
    assert assets and int(float(assets[0])) >= 1


def test_scan_completion_is_audited(client):
    response = client.post("/scans", json={"target": "demo/workspace"})
    scan_id = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan_id, source_type="path", target="demo/workspace")
    with SessionLocal() as db:
        events = (
            db.query(AuditEvent)
            .filter(AuditEvent.scan_id == scan_id, AuditEvent.action == "scan-completed")
            .all()
        )
        assert len(events) == 1
        detail = json.loads(events[0].after_json)
        assert detail["assetCount"] >= 1
        assert events[0].actor == "system"


def test_scan_deletion_is_audited_with_actor(client):
    response = client.post("/scans", json={"target": "demo/workspace"})
    scan_id = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan_id, source_type="path", target="demo/workspace")

    deleted = client.delete(f"/scans/{scan_id}", headers={"X-Operator": "alice@example.com"})
    assert deleted.status_code == 200
    with SessionLocal() as db:
        event = (
            db.query(AuditEvent)
            .filter(AuditEvent.scan_id == scan_id, AuditEvent.action == "scan-deleted")
            .one()
        )
        assert event.actor == "alice@example.com"
        before = json.loads(event.before_json)
        assert before["target"].replace("\\", "/").endswith("demo/workspace")


def test_limited_app_returns_429_with_retry_after(monkeypatch):
    monkeypatch.setenv("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", "2")
    monkeypatch.delenv("ECDAT_RATE_LIMIT_BURST", raising=False)
    limited_app = FastAPI()
    limited_app.add_middleware(RateLimitMiddleware)

    @limited_app.get("/ping")
    def ping():
        return {"ok": True}

    statuses = []
    for _ in range(3):
        with TestClient(limited_app) as probe:
            statuses.append(probe.get("/ping").status_code)
    assert statuses == [200, 200, 429]


def test_limited_app_exempts_health_probes(monkeypatch):
    monkeypatch.setenv("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", "1")
    limited_app = FastAPI()
    limited_app.add_middleware(RateLimitMiddleware)

    @limited_app.get("/health")
    def health():
        return {"status": "healthy"}

    with TestClient(limited_app) as probe:
        statuses = [probe.get("/health").status_code for _ in range(5)]
    assert statuses == [200] * 5


def test_limited_app_disabled_by_default():
    limited_app = FastAPI()
    limited_app.add_middleware(RateLimitMiddleware)

    @limited_app.get("/ping")
    def ping():
        return {"ok": True}

    with TestClient(limited_app) as probe:
        statuses = [probe.get("/ping").status_code for _ in range(10)]
    assert statuses == [200] * 10


def test_rate_limit_env_rejects_non_integers(monkeypatch):
    for bad in ("-1", "abc", "1.5"):
        monkeypatch.setenv("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", bad)
        with pytest.raises(ValueError):
            _positive_env("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", 0)
    monkeypatch.setenv("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", "120")
    assert _positive_env("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", 0) == 120


def test_retention_disabled_by_default():
    assert get_retention_days() == 0


def test_retention_prunes_only_old_completed_scans(monkeypatch):
    monkeypatch.setenv("ECDAT_SCAN_RETENTION_DAYS", "7")
    assert get_retention_days() == 7

    old = Scan(
        id="retention-old",
        source_type="path",
        target="old-target",
        status="completed",
        completed_at=datetime.utcnow() - timedelta(days=10),
        asset_count=3,
    )
    fresh = Scan(
        id="retention-fresh",
        source_type="path",
        target="fresh-target",
        status="completed",
        completed_at=datetime.utcnow() - timedelta(days=1),
    )
    failed = Scan(id="retention-failed", source_type="path", target="failed-target", status="failed")
    with SessionLocal() as db:
        for scan in (old, fresh, failed):
            db.merge(scan)
        db.commit()

        pruned = prune_expired_scans(db)
        assert pruned == 1

        remaining = {scan.id for scan in db.query(Scan).filter(Scan.id.like("retention-%"))}
        assert remaining == {"retention-fresh", "retention-failed"}

        event = (
            db.query(AuditEvent)
            .filter(AuditEvent.scan_id == "retention-old", AuditEvent.action == "scan-retention-deleted")
            .one()
        )
        assert json.loads(event.before_json)["retentionDays"] == 7


def test_retention_rejects_invalid_env(monkeypatch):
    for bad in ("-1", "abc", "2.5"):
        monkeypatch.setenv("ECDAT_SCAN_RETENTION_DAYS", bad)
        with pytest.raises(ValueError):
            get_retention_days()


def _write_database(path: Path) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.executescript(
            "CREATE TABLE scans (id TEXT PRIMARY KEY, status TEXT);"
            "INSERT INTO scans VALUES ('s1', 'completed');"
            "INSERT INTO scans VALUES ('s2', 'completed');"
        )
    finally:
        connection.close()


def test_db_admin_backup_and_stats(tmp_path):
    from scripts.db_admin import cmd_backup, cmd_stats, sqlite_path

    source = tmp_path / "source.db"
    _write_database(source)

    backup = tmp_path / "backups" / "copy.db"
    assert cmd_backup(source, backup) == 0
    assert backup.is_file()

    check = sqlite3.connect(str(backup))
    try:
        rows = check.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        check.close()
    assert rows == 2

    assert cmd_stats(source) == 0
    assert sqlite_path(f"sqlite:///{source}") == source


def test_db_admin_rejects_non_sqlite_url():
    from scripts.db_admin import sqlite_path

    with pytest.raises(SystemExit):
        sqlite_path("postgresql://user:pass@localhost/ecdat")


def test_committed_openapi_contract_matches_application():
    contract_path = Path(__file__).resolve().parents[2] / "openapi.json"
    committed = json.loads(contract_path.read_text(encoding="utf-8"))
    assert app.openapi() == committed, (
        "openapi.json is stale; regenerate it with: "
        "python -c \"import json; from backend.main import app; "
        "json.dump(app.openapi(), open('openapi.json','w'), indent=2)\""
    )
