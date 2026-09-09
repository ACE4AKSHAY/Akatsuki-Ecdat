"""LAN mode must publish a reachable UI while keeping its data API protected."""
import subprocess
import sys
from pathlib import Path


def test_lan_mode_reaches_port_validation():
    script = Path(__file__).resolve().parents[1] / 'scripts' / 'launcher.py'
    result = subprocess.run([sys.executable, str(script), 'lan', '--api-port', '8123', '--ui-port', '8123'], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'different ports' in result.stderr


def test_lan_environment_protects_api_without_changing_parent(monkeypatch):
    from scripts import launcher
    monkeypatch.delenv('ECDAT_API_TOKEN', raising=False)
    first = launcher.service_environment('lan', 8123)
    second = launcher.service_environment('lan', 8123)
    assert len(first['ECDAT_API_TOKEN']) >= 24
    assert first['ECDAT_API_TOKEN'] != second['ECDAT_API_TOKEN']
    assert 'ECDAT_API_TOKEN' not in launcher.os.environ
    assert first['API_PROXY_TARGET'] == 'http://127.0.0.1:8123'


def test_lan_environment_preserves_configured_token(monkeypatch):
    from scripts import launcher
    monkeypatch.setenv('ECDAT_API_TOKEN', 'test-fixture-token')
    assert launcher.service_environment('lan', 8123)['ECDAT_API_TOKEN'] == 'test-fixture-token'


def test_local_mode_does_not_enable_token_implicitly(monkeypatch):
    from scripts import launcher
    monkeypatch.delenv('ECDAT_API_TOKEN', raising=False)
    assert 'ECDAT_API_TOKEN' not in launcher.service_environment('dev', 8123)
