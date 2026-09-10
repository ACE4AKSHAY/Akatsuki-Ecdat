"""Capacity checks use generated benign input and the isolated test database."""
import io
import json
import subprocess
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ingestion import prepared_target, extract_zip
from backend.scanners.infra.container import scan_container_image

MIB = 1024 * 1024


def finished_scan(client, response):
    assert response.status_code == 202, response.text
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = client.get('/scans/' + response.json()['scanId']).json()
        if result['status'] in ('completed', 'failed'):
            assert result['status'] == 'completed', result
            assert result['assetCount'] >= 1
            return
        time.sleep(.1)
    pytest.fail('Large fixture did not finish within 90 seconds')


def test_repository_over_old_size_and_count_limits(tmp_path):
    source = tmp_path / 'large repository'
    source.mkdir()
    (source / 'app.py').write_text('import hashlib\nhashlib.md5(b"capacity fixture")\n')
    with (source / 'padding.dat').open('wb') as padding:
        padding.truncate(101 * MIB)
    for index in range(10000):
        (source / f'fixture-{index}.dat').touch()
    with TestClient(app) as client:
        finished_scan(client, client.post('/scans', json={'sourceType': 'path', 'target': str(source)}))


def test_upload_and_expansion_over_old_limits(tmp_path):
    archive = tmp_path / 'large upload.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr('app.py', 'import hashlib\nhashlib.sha1(b"capacity fixture")\n')
        with bundle.open('padding.dat', 'w') as padding:
            for _ in range(101):
                padding.write(b' ' * MIB)
    with TestClient(app) as client, archive.open('rb') as data:
        finished_scan(client, client.post('/scans/upload', files={'file': ('large.zip', data, 'application/zip')}))


def test_image_inventory_over_old_20_mib_limit(tmp_path):
    inventory = tmp_path / 'inventory.json'
    inventory.write_text(json.dumps({'bomFormat': 'CycloneDX', 'components': [{'name': 'openssl', 'version': '1.0.2'}]}) + ' ' * (21 * MIB))
    assert len(scan_container_image(str(inventory))) == 1


@pytest.mark.parametrize('source_type', ['upload', 'image'])
def test_configured_upload_limit_reports_size_and_cleans_up(tmp_path, monkeypatch, source_type):
    monkeypatch.setenv('ECDAT_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('ECDAT_MAX_UPLOAD_MIB' if source_type == 'upload' else 'ECDAT_MAX_INVENTORY_MIB', '1')
    with TestClient(app) as client:
        response = client.post('/scans/upload', data={'sourceType': source_type}, files={'file': ('padding.json', b' ' * (MIB + 1))})
        assert response.status_code == 413
        assert '1 MiB' in response.json()['detail']
    assert list((tmp_path / 'state' / 'uploads').iterdir()) == []


@pytest.mark.parametrize('source_type', ['directory', 'zip', 'file'])
def test_configured_workspace_size_limit(tmp_path, monkeypatch, source_type):
    monkeypatch.setenv('ECDAT_MAX_WORKSPACE_MIB', '1')
    source = tmp_path / 'source'
    source.mkdir()
    padding = source / 'padding.dat'
    padding.write_bytes(b' ' * (MIB + 1))
    with pytest.raises(ValueError, match='1 MiB'):
        if source_type == 'zip':
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as bundle:
                bundle.write(padding, 'padding.dat')
            data.seek(0)
            extract_zip(data, tmp_path / 'expanded')
        else:
            with prepared_target('path', str(source if source_type == 'directory' else padding)):
                pass


@pytest.mark.parametrize('source_type', ['directory', 'zip'])
def test_configured_file_count_limit(tmp_path, monkeypatch, source_type):
    monkeypatch.setenv('ECDAT_MAX_FILES', '2')
    source = tmp_path / 'source'
    source.mkdir()
    for name in ('a.txt', 'b.txt', 'c.txt'):
        (source / name).write_text('fixture')
    with pytest.raises(ValueError, match='2 (files|entries)'):
        if source_type == 'zip':
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as bundle:
                for path in source.iterdir():
                    bundle.write(path, path.name)
            data.seek(0)
            extract_zip(data, tmp_path / 'expanded')
        else:
            with prepared_target('path', str(source)):
                pass


def test_inventory_has_separate_configured_limit(tmp_path, monkeypatch):
    monkeypatch.setenv('ECDAT_MAX_INVENTORY_MIB', '1')
    inventory = tmp_path / 'inventory.json'
    inventory.write_bytes(b' ' * (MIB + 1))
    with pytest.raises(ValueError, match='1 MiB'):
        scan_container_image(str(inventory))


@pytest.mark.parametrize('value', ['0', '-1', '1.5', 'unlimited'])
def test_invalid_limits_fail_at_startup(monkeypatch, value):
    monkeypatch.setenv('ECDAT_MAX_FILES', value)
    with pytest.raises(ValueError, match='ECDAT_MAX_FILES must be a positive integer'):
        with TestClient(app):
            pass


def test_git_uses_configured_clone_deadline(monkeypatch):
    monkeypatch.setenv('ECDAT_GIT_TIMEOUT_SECONDS', '900')

    def expired(command, **kwargs):
        assert kwargs['timeout'] == 900
        raise subprocess.TimeoutExpired(command, kwargs['timeout'])

    monkeypatch.setattr(subprocess, 'run', expired)
    with pytest.raises(ValueError, match='900 second limit'):
        with prepared_target('git', 'https://github.com/example/capacity-fixture'):
            pass


def test_image_uses_configured_inventory_deadline(monkeypatch):
    monkeypatch.setenv('ECDAT_IMAGE_TIMEOUT_SECONDS', '900')
    monkeypatch.setattr('shutil.which', lambda name: 'trivy')

    def expired(command, **kwargs):
        assert command[command.index('--timeout') + 1] == '900s'
        assert kwargs['timeout'] == 910
        raise subprocess.TimeoutExpired(command, kwargs['timeout'])

    monkeypatch.setattr(subprocess, 'run', expired)
    with pytest.raises(ValueError, match='900 second timeout'):
        scan_container_image('example/capacity-fixture:latest')
