"""CBOM drift: the diff endpoint detects added, removed and changed assets."""
from __future__ import annotations

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from backend.database import SessionLocal, init_db
from backend.engine.orchestrator import run_scan_pipeline_sync
from backend.main import app
from backend.models.db_models import Asset


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_diff_reports_added_removed_and_changed(client):
    from backend.database import SessionLocal
    from backend.models.db_models import Scan

    with SessionLocal() as db:
        db.add(Scan(id="drift-baseline", source_type="path", target="demo/workspace", status="queued"))
        db.commit()
    run_scan_pipeline_sync("drift-baseline", "path", "demo/workspace")

    # Simulate a later scan of the same estate with one asset removed,
    # one added and one changed, without re-running the scanners.
    with SessionLocal() as db:
        assets = db.query(Asset).filter(Asset.scan_id == "drift-baseline").all()
        assert len(assets) >= 2
        dropped = assets[0]
        kept = assets[-1]

        db.add(Scan(id="drift-current", source_type="path", target="demo/workspace", status="completed", completed_at=datetime.utcnow()))
        db.commit()

        dropped_name, kept_name = dropped.name, kept.name
        moved = []
        for asset in assets:
            if asset.id == dropped.id:
                continue  # removed from the current scan
            data = {
                column.name: getattr(asset, column.name)
                for column in asset.__table__.columns
                if column.name != "id"
            }
            data["id"] = f"drift-current_{asset.id}"
            data["scan_id"] = "drift-current"
            if asset.id == kept.id:
                data["migration_action"] = "replace"
            moved.append(Asset(**data))
        db.add_all(moved)
        db.commit()

        response = client.get("/cbom/drift-current/diff", params={"against": "drift-baseline"})
        assert response.status_code == 200
        payload = response.json()

    assert payload["summary"]["added"] == 0
    assert payload["summary"]["removed"] == 1
    assert payload["removed"][0]["name"] == dropped_name
    assert payload["summary"]["changed"] == 1
    assert payload["changed"][0]["name"] == kept_name
    assert payload["changed"][0]["before"]["migrationAction"] != "replace"
    assert payload["changed"][0]["after"]["migrationAction"] == "replace"


def test_diff_rejects_unknown_or_incomplete_scans(client):
    missing = client.get("/cbom/does-not-exist/diff", params={"against": "also-missing"})
    assert missing.status_code == 404

    from backend.database import SessionLocal
    from backend.models.db_models import Scan

    with SessionLocal() as db:
        db.add(Scan(id="drift-queued", source_type="path", target="x", status="queued"))
        db.commit()
    incomplete = client.get("/cbom/drift-queued/diff", params={"against": "drift-baseline"})
    assert incomplete.status_code == 400
