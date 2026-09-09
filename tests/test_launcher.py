"""Version and port checks must fail early rather than launch broken services."""
import socket
import subprocess
import sys
from pathlib import Path
import pytest
from scripts.launcher import LauncherError, version_tuple, require_free_port


@pytest.mark.parametrize(('text','expected'), [('v22.12.0',(22,12,0)),('git version 2.46.2.windows.1',(2,46,2)),('Python 3.12.8',(3,12,8))])
def test_tool_versions(text, expected):
    assert version_tuple(text) == expected


def test_unknown_version_is_reported():
    with pytest.raises(LauncherError,match='Cannot read a version'):
        version_tuple('not installed')


def test_busy_port_is_reported_without_stopping_owner():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        listener.listen()
        port=listener.getsockname()[1]
        with pytest.raises(LauncherError,match='unavailable'):
            require_free_port(port)
        with socket.create_connection(('127.0.0.1',port),timeout=1):
            pass


def test_launcher_runs_outside_repository_directory(tmp_path):
    script=Path(__file__).resolve().parents[1]/'scripts'/'launcher.py'
    result=subprocess.run([sys.executable,str(script),'commands','--api-port','8123','--ui-port','3123'],cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode == 0
    assert '--port 8123' in result.stdout and 'http://127.0.0.1:3123/' in result.stdout


def test_invalid_port_is_rejected_before_startup():
    script=Path(__file__).resolve().parents[1]/'scripts'/'launcher.py'
    result=subprocess.run([sys.executable,str(script),'dev','--api-port','80'],capture_output=True,text=True)
    assert result.returncode != 0
    assert 'between 1024 and 65535' in result.stderr
