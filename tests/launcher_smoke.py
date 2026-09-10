"""Real process smoke check, run explicitly after setup (including in Windows CI)."""
from pathlib import Path
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
import httpx
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.launcher import local_ipv4_addresses, stop_process

# Ignore corporate HTTP proxies for requests to this machine's LAN interface.
http = build_opener(ProxyHandler({}))

def free_port():
    with socket.socket() as sock:
        sock.bind(('0.0.0.0', 0))
        return sock.getsockname()[1]


def request(url, token=None, payload=None, method=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    data = None if payload is None else json.dumps(payload).encode()
    if data is not None:
        headers['Content-Type'] = 'application/json'
    with http.open(Request(url, data=data, headers=headers, method=method), timeout=5) as response:
        return response.status, response.read()


def wait_ready(url, process):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f'Launcher exited early: {process.returncode}')
        try:
            if request(url)[0] == 200:
                return
        except (URLError, OSError):
            time.sleep(.25)
    raise AssertionError(f'Not ready: {url}')


def main():
    api_port, ui_port = free_port(), free_port()
    while ui_port == api_port:
        ui_port = free_port()
    with tempfile.TemporaryDirectory(prefix='ecdat smoke with spaces ') as storage:
        root = Path(storage)
        # A non-secret fixture token; never connect this test to a shared database.
        token = 'launcher-smoke-fixture-token'
        env = dict(os.environ, DATABASE_URL=f'sqlite:///{(root / "test.db").as_posix()}',
                   ECDAT_STATE_DIR=str(root / 'state'), ECDAT_API_TOKEN=token, PYTHONUTF8='1')
        log_path = ROOT / 'work' / 'launcher-smoke.log'
        log_path.parent.mkdir(exist_ok=True)
        with log_path.open('w', encoding='utf-8') as log:
            args = [sys.executable, '-u', str(ROOT / 'scripts/launcher.py'), 'lan',
                    '--api-port', str(api_port), '--ui-port', str(ui_port), '--no-browser']
            kwargs = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
            process = subprocess.Popen(args, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, **kwargs)
            try:
                base = f'http://127.0.0.1:{ui_port}'
                wait_ready(base + '/api/health', process)
                assert b'<div id="root">' in request(base + '/')[1]
                try:
                    request(base + '/api/scans')
                    raise AssertionError('LAN data was exposed without a token')
                except HTTPError as error:
                    assert error.code == 401
                addresses = local_ipv4_addresses()
                assert addresses, 'Runner has no LAN IPv4 interface to verify'
                lan = f'http://{addresses[0]}:{ui_port}'
                assert request(lan + '/')[0] == 200
                assert request(lan + '/api/health')[0] == 200
                assert json.loads(request(lan + '/api/scans', token)[1]) == []
                # The browser's /api route must create and read real scan results.
                _, body = request(lan + '/api/scans', token, {'sourceType':'path', 'target':str(ROOT / 'demo/workspace')})
                scan_id = json.loads(body)['scanId']
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    scan = json.loads(request(lan + '/api/scans/' + scan_id, token)[1])
                    if scan['status'] in ('completed', 'failed'):
                        break
                    time.sleep(.25)
                assert scan['status'] == 'completed', scan
                assert scan['assetCount'] == 10, scan
                for fmt in ('pdf', 'csv', 'xlsx', 'json'):
                    status, body = request(lan + f'/api/reports/{scan_id}?format={fmt}', token)
                    assert status == 200 and len(body) > 50
                assert json.loads(request(lan + '/api/scans/' + scan_id, token, method='DELETE')[1])['deletedCount'] == 1
                assert json.loads(request(lan + '/api/scans', token)[1]) == []
                print('PASS: LAN page, API proxy, token enforcement, 10-asset scan, four reports and deletion')
                archive = root / 'large-upload.zip'
                with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as bundle:
                    bundle.writestr('app.py', 'import hashlib\nhashlib.md5(b"LAN capacity fixture")\n')
                    with bundle.open('padding.dat', 'w') as padding:
                        for _ in range(21):
                            padding.write(b' ' * (1024 * 1024))
                with httpx.Client(trust_env=False, timeout=60) as client, archive.open('rb') as data:
                    response = client.post(lan + '/api/scans/upload',
                        headers={'Authorization': f'Bearer {token}'}, files={'file': ('large-upload.zip', data, 'application/zip')})
                assert response.status_code == 202, response.text
                upload_id = response.json()['scanId']
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    scan = json.loads(request(lan + '/api/scans/' + upload_id, token)[1])
                    if scan['status'] in ('completed', 'failed'):
                        break
                    time.sleep(.25)
                assert scan['status'] == 'completed' and scan['assetCount'] >= 1, scan
                assert json.loads(request(lan + '/api/scans/' + upload_id, token, method='DELETE')[1])['deletedCount'] == 1
                print('PASS: 21 MiB ZIP upload through LAN proxy completed with real findings')
            finally:
                if process.poll() is None:
                    process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGINT)
                    try:
                        process.wait(timeout=35)
                    except subprocess.TimeoutExpired:
                        stop_process(process)
                        raise AssertionError('Launcher did not stop after interrupt')
                for port in (api_port, ui_port):
                    with socket.socket() as sock:
                        assert sock.connect_ex(('127.0.0.1', port)) != 0, f'Owned service still running on {port}'
                assert process.returncode == 0, f'Launcher exit: {process.returncode}; see {log_path}'
                print('PASS: interrupt released both owned service ports')


if __name__ == '__main__':
    main()
