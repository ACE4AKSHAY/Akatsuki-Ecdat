import io
import json
import time
import zipfile
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal
from backend.models.db_models import Scan, ScanJob
from backend.engine.jobs import recover_interrupted, process_next
from backend.ingestion import extract_zip, validate_git_url, prepared_target
from backend.scanners.infra.container import scan_container_image
from backend.engine.recommend import generate_recommendation


def wait_scan(client, scan_id):
    for _ in range(100):
        item = client.get(f'/scans/{scan_id}').json()
        if item['status'] in ('completed', 'failed'):
            return item
        time.sleep(.05)
    pytest.fail('Scan did not finish')


def test_zip_upload_runs_real_scan(tmp_path, monkeypatch):
    monkeypatch.setenv('ECDAT_STATE_DIR', str(tmp_path))
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('app.py', 'import hashlib\nhashlib.md5(b"fixture")\n')
    with TestClient(app) as client:
        response = client.post('/scans/upload', files={'file': ('demo.zip', data.getvalue(), 'application/zip')})
        assert response.status_code == 202
        result = wait_scan(client, response.json()['scanId'])
        assert result['status'] == 'completed', result
        assert result['assetCount'] >= 1


def test_image_sbom_upload(tmp_path, monkeypatch):
    monkeypatch.setenv('ECDAT_STATE_DIR', str(tmp_path))
    data = {'bomFormat':'CycloneDX', 'components':[{'name':'openssl','version':'1.0.2'}]}
    with TestClient(app) as client:
        response = client.post('/scans/upload', data={'sourceType':'image'}, files={'file':('image.json',json.dumps(data),'application/json')})
        result = wait_scan(client, response.json()['scanId'])
        assert result['status'] == 'completed', result
        assert result['assetCount'] == 1


def test_auth_protects_api_and_exports(monkeypatch):
    monkeypatch.setenv('ECDAT_API_TOKEN', 'test-only-workspace-token')
    with TestClient(app) as client:
        assert client.get('/health').status_code == 200
        assert client.get('/scans').status_code == 401
        assert client.get('/reports/missing').status_code == 401
        assert client.get('/scans', headers={'Authorization':'Bearer test-only-workspace-token'}).status_code == 200


def test_queue_recovery_retains_options(tmp_path, monkeypatch):
    from backend.database import init_db
    init_db()
    with SessionLocal() as db:
        scan = Scan(id='recovery-test', source_type='path', target=str(tmp_path), status='running')
        db.merge(scan)
        db.merge(ScanJob(scan_id=scan.id, options_json=json.dumps({'compliance_target':'CNSA2.0','threat_timeline_override':12})))
        db.commit()
    recover_interrupted()
    with SessionLocal() as db:
        assert db.get(Scan, 'recovery-test').status == 'queued'
        assert json.loads(db.get(ScanJob, 'recovery-test').options_json)['threat_timeline_override'] == 12
    while process_next():
        pass
    with SessionLocal() as db:
        assert db.get(Scan, 'recovery-test').status == 'completed'


def test_zip_regular_files_only(tmp_path):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w') as z:
        info=zipfile.ZipInfo('linked-file'); info.external_attr=0o120777 << 16
        z.writestr(info,'somewhere')
    data.seek(0)
    with pytest.raises(ValueError, match='ordinary'):
        extract_zip(data,tmp_path)


def test_snapshot_excludes_dependencies_and_links(tmp_path, monkeypatch):
    root=tmp_path/'source';root.mkdir()
    (root/'app.py').write_text('import hashlib')
    (root/'node_modules').mkdir();(root/'node_modules'/'dependency.js').write_text('fixture')
    (root/'linked.py').symlink_to(root/'app.py')
    monkeypatch.setenv('ECDAT_STATE_DIR',str(tmp_path/'state'))
    with prepared_target('path',str(root)) as snapshot:
        assert sorted(p.name for p in snapshot.iterdir()) == ['app.py']


def test_public_git_validation():
    assert validate_git_url('https://github.com/ACE4AKSHAY/Akatsuki-Ecdat')
    with pytest.raises(ValueError): validate_git_url('file:///local/repo')


def test_image_inventory_and_actionable_recommendation(tmp_path):
    path=tmp_path/'image.json';path.write_text(json.dumps({'Results':[{'Target':'image','Packages':[{'Name':'openssl','Version':'1.0.2'}]}]}))
    assert len(scan_container_image(str(path),'image-test')) == 1
    assert generate_recommendation('OpenSSL','key-management')['recommendedReplacement'] == 'Review required'
    assert generate_recommendation('AES-256','symmetric')['recommendedReplacement'] == 'No change needed'


def test_custom_timelines_reach_normalizer():
    from backend.engine.normalizer import normalize_findings
    from backend.scanners.runner import get_contract_seed_findings
    result=normalize_findings(get_contract_seed_findings('settings'), shelf_life_defaults={'Authentication-Token':9}, migration_effort_defaults={'hash':2})
    asset=next(a for a in result if a.name == 'SHA-1')
    assert asset.ecdatEnrichment.moscaX == 9
    assert asset.ecdatEnrichment.moscaY == 2


def test_worker_refuses_duplicate_owner(tmp_path, monkeypatch):
    from backend.engine.jobs import JobWorker
    monkeypatch.setenv('ECDAT_STATE_DIR',str(tmp_path))
    first=JobWorker(); first.start()
    try:
        with pytest.raises(RuntimeError,match='Another ECDAT worker'):
            JobWorker().start()
    finally:
        first.stop()
