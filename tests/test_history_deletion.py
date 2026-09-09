"""History deletion removes saved results atomically without touching inputs."""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db, SessionLocal
from backend.models.db_models import Scan, ScanJob, Asset, Recommendation
from backend.engine.orchestrator import run_scan_pipeline_sync


@pytest.fixture
def client():
    init_db()
    with SessionLocal() as db:
        db.query(ScanJob).delete()
        for scan in db.query(Scan).all():
            db.delete(scan)
        db.commit()
    # Keep the worker stopped so queued-job deletion checks are deterministic.
    return TestClient(app)


def completed_scan(client, tmp_path):
    source = tmp_path / "example.py"
    source.write_text('import hashlib\nhashlib.md5(b"demo")\n')
    response = client.post('/scans', json={'target': str(source)})
    assert response.status_code == 202
    scan_id = response.json()['scanId']
    run_scan_pipeline_sync(scan_id, 'path', str(source))
    assert client.get(f'/scans/{scan_id}').json()['assetCount'] > 0
    return scan_id, source


def test_delete_selected_removes_results_but_preserves_source(client, tmp_path):
    scan_id, source = completed_scan(client, tmp_path)
    response = client.delete(f'/scans/{scan_id}')
    assert response.status_code == 200
    assert response.json()['deletedCount'] == 1
    assert client.get(f'/scans/{scan_id}').status_code == 404
    assert client.get(f'/reports/{scan_id}').status_code == 404
    with SessionLocal() as db:
        assert db.get(ScanJob, scan_id) is None
        assert db.query(Asset).count() == 0
        assert db.query(Recommendation).count() == 0
    assert source.exists()


def test_delete_all_clears_history_and_is_repeatable(client, tmp_path):
    completed_scan(client, tmp_path)
    completed_scan(client, tmp_path)
    assert client.delete('/scans').json()['deletedCount'] == 2
    assert client.get('/scans').json() == []
    assert client.delete('/scans').json()['deletedCount'] == 0


@pytest.mark.parametrize('status', ['queued', 'running'])
def test_active_scans_block_selected_and_all_deletion(client, tmp_path, status):
    completed_scan(client, tmp_path)
    with SessionLocal() as db:
        db.add(Scan(id='active-history-job', source_type='path', target=str(tmp_path), status=status))
        db.commit()
    assert client.delete('/scans/active-history-job').status_code == 409
    assert client.delete('/scans').status_code == 409
    assert len(client.get('/scans').json()) == 2


def test_missing_scan_and_protected_deletion(client, monkeypatch):
    assert client.delete('/scans/missing').status_code == 404
    monkeypatch.setenv('ECDAT_API_TOKEN', 'history-test-token')
    assert client.delete('/scans').status_code == 401
    assert client.delete('/scans/missing').status_code == 401
    assert client.delete('/scans', headers={'Authorization': 'Bearer history-test-token'}).status_code == 200
