"""M3 container sub-scanner.

`scan_dockerfile(path)` — extract `FROM`, `RUN apt-get install ...`,
`RUN pip install ...`, `RUN npm install ...` lines; cross-reference installed
packages against the M2 crypto library registry; emit RawFindings with
`detectionTier="dockerfile"`, `confidence=0.85`.

`scan_container_image(ref)` reads an offline package inventory or uses the optional Trivy executable for a live image reference.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.registry import lookup
from backend.scanners.binary_deps.manifests import _strip_expected_header

FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE)
RUN_APT_RE = re.compile(r"^\s*RUN\s+.*?apt-get\s+install[^\n]*", re.IGNORECASE)
RUN_PIP_RE = re.compile(r"^\s*RUN\s+.*?pip(?:3)?\s+install[^\n]*", re.IGNORECASE)
RUN_NPM_RE = re.compile(r"^\s*RUN\s+.*?npm\s+install[^\n]*", re.IGNORECASE)
PKG_TOKEN_RE = re.compile(r"([\w\-\.]+)\s*([=<>~!]=)?\s*([\w\-\.\+]+)?")


def _emit_installs(packages: Iterable[str], *, scan_target_id: str, file_path: str,
                   line_no: int) -> list[RawFinding]:
    out: list[RawFinding] = []
    for pkg in packages:
        name = pkg.strip().strip("\"'")
        if not name or name in {"install", "&&", "\\", "-y", "--no-install-recommends"}:
            continue
        for entry in lookup(name) or []:
            pass
        entry = lookup(name)
        if entry is None or not entry.get("algorithms"):
            continue
        out.append(RawFinding(
            sourceModule="M3_container_config_scanner",
            scanTargetId=scan_target_id,
            filePath=file_path,
            lineNumber=line_no,
            language="manifest",
            library=entry["library"],
            rawSignal=f"install {name}",
            detectedPrimitive=entry["library"],
            primitiveCategory="key-management",
            keySizeBits=None,
            mode=None,
            confidence=0.85,
            detectionTier="dockerfile",
        ))
    return out


def scan_dockerfile(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    p = Path(path)
    if p.is_dir():
        return [finding for candidate in p.rglob("*") if candidate.is_file() and (candidate.name.lower().startswith("dockerfile") or candidate.suffix.lower() == ".dockerfile") for finding in scan_dockerfile(candidate, scan_target_id)]
    if not p.is_file():
        return []
    out: list[RawFinding] = []
    text = _strip_expected_header(p.read_text(encoding="utf-8", errors="replace"))
    for line_no, line in enumerate(text.splitlines(), 1):
        m = FROM_RE.match(line)
        if m:
            base = m.group(1)
            out.append(RawFinding(
                sourceModule="M3_container_config_scanner",
                scanTargetId=scan_target_id,
                filePath=str(p),
                lineNumber=line_no,
                language="manifest",
                library=None,
                rawSignal=f"FROM {base}",
                detectedPrimitive="base-image",
                primitiveCategory="key-management",
                keySizeBits=None,
                mode=None,
                confidence=0.7,
                detectionTier="dockerfile",
            ))
            continue
        for rx in (RUN_APT_RE, RUN_PIP_RE, RUN_NPM_RE):
            if rx.match(line):
                # Pull every token that *looks like* a package name (letters,
                # digits, -, ., _, starting with letter, not a flag).
                pkgs = re.findall(r"\b([A-Za-z][\w\-\.]*[A-Za-z0-9])\b", line)
                out.extend(_emit_installs(pkgs, scan_target_id=scan_target_id,
                                          file_path=str(p), line_no=line_no))
                break
    return out


def validate_image_input(target: str) -> str:
    import shutil
    root = Path(target).expanduser()
    if root.is_file():
        if root.suffix.lower() != '.json' or root.stat().st_size > 20 * 1024 * 1024:
            raise ValueError('Offline image input must be a CycloneDX or Trivy JSON inventory under 20 MB.')
        return str(root.resolve())
    if not re.fullmatch(r'[a-z0-9][a-z0-9._/:@-]{0,250}', target):
        raise ValueError('Enter a container image reference or a local image inventory JSON file.')
    if not shutil.which('trivy'):
        raise ValueError('Live image inventory requires Trivy on PATH. Alternatively upload a CycloneDX or Trivy JSON inventory.')
    return target


def findings_from_image_inventory(data: dict, scan_target_id: str) -> list[RawFinding]:
    """Map actual package inventory to the project crypto-library registry."""
    packages = []
    if data.get('bomFormat') == 'CycloneDX' and isinstance(data.get('components'), list):
        for component in data['components']:
            packages.append((component.get('name', ''), component.get('version', ''), component.get('purl', 'image-packages')))
    elif isinstance(data.get('Results'), list):
        for result in data['Results']:
            for package in result.get('Packages', []):
                packages.append((package.get('Name', ''), package.get('Version', ''), result.get('Target', 'image-packages')))
    else:
        raise ValueError('Expected a CycloneDX components array or Trivy Results package inventory.')
    findings = []
    seen = set()
    for name, version, location in packages:
        entry = lookup(name, version=version)
        if not entry or not entry.get("algorithms") or (name, version, location) in seen:
            continue
        seen.add((name, version, location))
        findings.append(RawFinding(sourceModule='M3_container_config_scanner', scanTargetId=scan_target_id,
            filePath=str(location), lineNumber=1, language='manifest', library=entry['library'],
            rawSignal=f'{name}@{version}', detectedPrimitive=entry['library'], primitiveCategory='key-management',
            confidence=0.9, detectionTier='manifest'))
    return findings


def scan_container_image(image_ref: str, scan_target_id: str = 'image') -> list[RawFinding]:
    """Read an offline SBOM or ask Trivy for package-only CycloneDX inventory."""
    import json
    import subprocess
    import tempfile
    target = validate_image_input(image_ref)
    if Path(target).is_file():
        return findings_from_image_inventory(json.loads(Path(target).read_text()), scan_target_id)
    with tempfile.TemporaryDirectory(prefix='ecdat-image-') as tmp:
        output = Path(tmp) / 'inventory.json'
        try:
            result = subprocess.run(['trivy', 'image', '--format', 'cyclonedx', '--output', str(output),
                '--timeout', '3m', '--', target], capture_output=True, timeout=190)
        except subprocess.TimeoutExpired as exc:
            raise ValueError('Image inventory exceeded the 190 second limit.') from exc
        if result.returncode:
            raise ValueError('Trivy could not inventory the image. Check image availability, registry access and Trivy setup.')
        if output.stat().st_size > 20 * 1024 * 1024:
            raise ValueError('Image inventory exceeds the 20 MB limit.')
        return findings_from_image_inventory(json.loads(output.read_text()), scan_target_id)
