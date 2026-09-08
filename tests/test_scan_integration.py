"""Regressions for real scanner ingestion and honest empty/error results."""
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.scanners.runner import run_scanners

@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


def test_empty_directory_stays_empty(client, tmp_path):
    response = client.post('/scans', json={'target': str(tmp_path)})
    assert response.status_code == 202
    scan_id = response.json()['scanId']
    from tests.test_ingestion_jobs import wait_scan
    result = wait_scan(client, scan_id)
    assert result['status'] == 'completed'
    assert result['assetCount'] == 0
    assert client.get('/assets', params={'scanId': scan_id}).json()['items'] == []
    assert client.get(f'/cbom/{scan_id}').json()['components'] == []


def test_invalid_target_rejected_without_creating_job(client, tmp_path):
    before = client.get('/scans').json()
    response = client.post('/scans', json={'target': str(tmp_path / 'missing')})
    assert response.status_code == 422
    assert client.get('/scans').json() == before


@pytest.mark.parametrize('source', ['git', 'image', 'upload'])
def test_unsupported_sources_are_explicit(client, source):
    response = client.post('/scans', json={'sourceType': source, 'target': 'example'})
    assert response.status_code == 422
    assert response.json()['detail']


def test_real_modules_all_reach_pipeline():
    findings = run_scanners('path', 'seed_corpus', 'integration')
    assert {f.sourceModule for f in findings} == {
        'M1_source_scanner', 'M2_dep_binary_scanner', 'M3_container_config_scanner'}
    assert any(f.detectionTier == 'ast' for f in findings)
    assert all(f.scanTargetId == 'integration' for f in findings)
    assert all(not Path(f.filePath).is_absolute() for f in findings)


def test_single_file_scans_actual_content(tmp_path):
    source = tmp_path / 'example.py'
    source.write_text('import hashlib\nhashlib.md5(b"test").hexdigest()\n')
    findings = run_scanners('path', str(source), 'one-file')
    assert any(f.detectedPrimitive == 'MD5' and f.filePath == 'example.py' for f in findings)


@pytest.mark.parametrize('z', [0, -1, 51])
def test_invalid_timeline_rejected(client, z):
    assert client.post('/scans', json={'target': 'seed_corpus', 'threatTimelineOverride': z}).status_code == 422
