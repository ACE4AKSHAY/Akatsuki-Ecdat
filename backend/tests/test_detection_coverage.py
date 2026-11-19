"""Coverage guarantees for the v1.1 detection surface.

Each primitive family added to `signals.yaml` must be:
  1. detected by M1 at AST tier on the matching seed fixture,
  2. silent on the FP-trap fixture that only mentions the API in a string,
  3. canonicalised to the right family by the normalizer,
  4. classified by the standards registry with a sensible action.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.engine.context import infer_usage_context
from backend.engine.normalizer import canonicalize_primitive
from backend.engine.standards import candidate_view, classify
from backend.scanners.source.scanner import scan_repository

SEED = ROOT / "seed_corpus"

# primitive -> (fixture relative path, expected line)
EXPECTED_DETECTIONS = [
    ("bcrypt", "python/real_findings.py", 12),
    ("PBKDF2", "python/real_findings.py", 13),
    ("TLSv1.2", "python/real_findings.py", 14),
    ("bcrypt", "java/RealFindings.java", 8),
    ("HMAC-SHA256", "java/RealFindings.java", 9),
    ("HMAC-SHA256", "javascript/real_findings.js", 6),
    ("TLSv1.2", "javascript/real_findings.js", 8),
    ("TLSv1.2", "go/real_findings.go", 14),
]


@pytest.mark.parametrize(
    "primitive,rel,line",
    EXPECTED_DETECTIONS,
    ids=[f"{p}-{rel.split('/')[-1]}" for p, rel, _ in EXPECTED_DETECTIONS],
)
def test_primitive_detected_at_ast_tier(primitive, rel, line):
    findings = scan_repository(SEED / rel, "test_run")
    match = [
        f for f in findings
        if f.detectedPrimitive == primitive and f.lineNumber == line
    ]
    assert match, (
        f"{primitive} not detected at line {line} in {rel}; "
        f"got {[(f.detectedPrimitive, f.lineNumber) for f in findings]}"
    )
    assert match[0].detectionTier == "ast"
    assert match[0].confidence >= 0.85


@pytest.mark.parametrize(
    "rel",
    ["python/fp_trap.py", "java/FPTrap.java", "javascript/fp_trap.js", "go/fp_trap.go"],
)
def test_fp_trap_files_stay_empty(rel):
    findings = scan_repository(SEED / rel, "test_run")
    assert findings == [], (
        f"{rel} produced false positives: "
        f"{[(f.detectedPrimitive, f.lineNumber, f.rawSignal) for f in findings]}"
    )


@pytest.mark.parametrize(
    "primitive,expected_family",
    [
        ("bcrypt", "kdf"),
        ("PBKDF2", "kdf"),
        ("ARGON2ID", "kdf"),
        ("SCRYPT", "kdf"),
        ("HMAC-SHA256", "mac"),
        ("ChaCha20-Poly1305", "symmetric"),
        ("TLSv1.2", "protocol"),
    ],
)
def test_new_primitives_canonicalize(primitive, expected_family):
    _, _, family, _, _, _ = canonicalize_primitive(primitive)
    assert family == expected_family


@pytest.mark.parametrize(
    "primitive,category,expected_action",
    [
        ("PBKDF2", "kdf", "replace"),
        ("bcrypt", "kdf", "replace"),
        ("HMAC-SHA256", "mac", "retain"),
        ("ChaCha20-Poly1305", "symmetric-cipher", "retain"),
    ],
)
def test_registry_classifies_new_primitives(primitive, category, expected_action):
    result = classify(primitive, category)
    assert result["defaultAction"] == expected_action
    assert result["entryId"] != None  # noqa: E711 — must resolve to a registry entry


def test_kdf_findings_map_to_password_storage_role():
    context, confidence = infer_usage_context("app/auth.py", "bcrypt.hashpw(pw, salt)", "kdf")
    assert context == "password-storage"
    assert confidence >= 0.7


def test_candidate_view_uses_registry_action_not_family_default():
    # ChaCha20-Poly1305 is a healthy symmetric AEAD; the registry says retain,
    # even though the symmetric family default would be "replace".
    view = candidate_view("chacha20-poly1305")
    assert view is not None
    assert view["action"] == "retain"


def test_base_and_key_size_variant_collapse_to_one_finding():
    """`generate_private_key(key_size=2048)` matches both RSA and RSA-2048."""
    findings = scan_repository(SEED / "python" / "real_findings.py", "test_run")
    rsa_hits = [f for f in findings if f.detectedPrimitive.startswith("RSA")]
    assert len(rsa_hits) == 1
    assert rsa_hits[0].keySizeBits == 2048


def test_normalizer_merges_variants_into_one_canonical_asset():
    from backend.engine.normalizer import normalize_findings

    findings = scan_repository(SEED / "python" / "real_findings.py", "test_run")
    assets = {a.name for a in normalize_findings(findings)}
    assert "RSA-2048" in assets
    assert "RSA" not in assets
    assert "AES-128" in assets


def test_cipher_mode_is_captured_for_ecb_usage():
    findings = scan_repository(SEED / "python" / "real_findings.py", "test_run")
    aes = [f for f in findings if f.detectedPrimitive == "AES"]
    assert len(aes) == 1
    assert aes[0].mode == "ECB"
    assert aes[0].keySizeBits == 128
