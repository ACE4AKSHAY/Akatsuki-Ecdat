"""The application must import on platforms without the Unix fcntl module."""
import subprocess
import sys


def test_backend_import_without_unix_fcntl():
    result = subprocess.run([sys.executable, '-c',
        'import subprocess, sys; sys.modules["fcntl"] = None; import backend.main'],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
