"""Headless CI scan: artifacts, isolation from operator history, exit codes."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "scan_cli.py"), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=300,
    )


def test_cli_scan_produces_cbom_and_sarif(tmp_path):
    output = tmp_path / "results"
    result = _run("--target", "demo/workspace", "--output", str(output))
    assert result.returncode == 0, result.stderr

    cbom = json.loads((output / "cbom.json").read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 9

    sarif = json.loads((output / "results.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 9
    assert "assets: 9" in result.stdout
    assert "Critical" in result.stdout


def test_cli_fail_on_critical_exit_code(tmp_path):
    output = tmp_path / "results"
    result = _run("--target", "demo/workspace", "--output", str(output), "--fail-on-critical")
    assert result.returncode == 1
    assert "fail-on-critical" in result.stderr
    # Artifacts are still produced; the exit code is the CI gate, not the report.
    assert (output / "cbom.json").is_file()


def test_cli_rejects_missing_target(tmp_path):
    result = _run("--target", "does/not/exist", "--output", str(tmp_path / "results"))
    assert result.returncode == 1
    assert "does not exist" in result.stderr
