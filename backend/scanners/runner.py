"""
Scanner runner for M1 (Source), M2 (Deps/Binary), and M3 (Infra/Cert).
Emits RawFinding objects strictly adhering to CONTRACT.md Section 1.
"""
import os
import re
from typing import List
from backend.models.schemas import RawFinding

REGEX_CRYPTO_PATTERNS = [
    (r"(?i)hashes\.sha1\(\)|sha-?1", "SHA1", "hash", "pyca/cryptography", "python"),
    (r"(?i)hashlib\.md5\(\)|md5", "MD5", "hash", "hashlib", "python"),
    (r"(?i)rsa\.generate_private_key|rsa-?2048", "RSA-2048", "asymmetric_kem", "cryptography.hazmat", "python"),
    (r"(?i)ec\.generate_private_key.*secp256r1|ecdsa", "ECDSA-P256", "asymmetric_sig", "cryptography.hazmat", "python"),
    (r"(?i)ciphers\.algorithms\.aes\(.*128\)|aes-?128", "AES-128", "symmetric", "cryptography.hazmat", "python"),
    (r"(?i)ciphers\.algorithms\.aes\(.*256\)|aes-?256", "AES-256", "symmetric", "cryptography.hazmat", "python"),
    (r"(?i)des\.new\(\)|des3|triple-?des", "DES", "symmetric", "pycryptodome", "python"),
]


def get_contract_seed_findings(scan_id: str) -> List[RawFinding]:
    """
    Returns the exact sample findings from CONTRACT.md and Section 9.4 worked examples.
    """
    return [
        # Finding 1: Directly from CONTRACT.md Section 1
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId=scan_id,
            filePath="src/auth/token_signer.py",
            lineNumber=42,
            language="python",
            library="pyca/cryptography",
            rawSignal="hashes.SHA1()",
            detectedPrimitive="SHA1",
            primitiveCategory="hash",
            keySizeBits=None,
            mode=None,
            confidence=0.95,
            detectionTier="ast",
        ),
        # Finding 2: Customer PII field encryption (Section 9.4: RSA-2048 key exchange, X=15, Y=1.5, Z=8 -> Critical)
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId=scan_id,
            filePath="src/customer/pii_vault.py",
            lineNumber=118,
            language="python",
            library="pyca/cryptography",
            rawSignal="rsa.generate_private_key(public_exponent=65537, key_size=2048)",
            detectedPrimitive="RSA-2048",
            primitiveCategory="asymmetric_kem",
            keySizeBits=2048,
            mode=None,
            confidence=0.98,
            detectionTier="ast",
        ),
        # Finding 3: Internal microservice mTLS (Section 9.4: ECDSA-P256 cert, X=3, Y=0.5, Z=8 -> Low)
        RawFinding(
            sourceModule="M3_container_config_scanner",
            scanTargetId=scan_id,
            filePath="infra/tls/internal_service.crt",
            lineNumber=1,
            language="yaml",
            library="x509",
            rawSignal="Subject: CN=internal.rpc, Public Key: ECDSA-P256",
            detectedPrimitive="ECDSA-P256",
            primitiveCategory="asymmetric_sig",
            keySizeBits=256,
            mode=None,
            confidence=1.0,
            detectionTier="cert-parse",
        ),
        # Finding 4: Firmware signing (Section 9.4: RSA-2048 signature, X=10, Y=2, Z=8 -> Critical)
        RawFinding(
            sourceModule="M1_source_scanner",
            scanTargetId=scan_id,
            filePath="firmware/boot_signer.c",
            lineNumber=88,
            language="c",
            library="openssl",
            rawSignal="RSA_sign(NID_sha256, m, m_len, sigret, &siglen, rsa)",
            detectedPrimitive="RSA-2048",
            primitiveCategory="asymmetric_sig",
            keySizeBits=2048,
            mode=None,
            confidence=0.92,
            detectionTier="ast",
        ),
        # Finding 5: Grover weakened AES-128 in internal API
        RawFinding(
            sourceModule="M2_dep_binary_scanner",
            scanTargetId=scan_id,
            filePath="requirements.txt",
            lineNumber=12,
            language="python",
            library="pycryptodome",
            rawSignal="AES.new(key, AES.MODE_CBC)",
            detectedPrimitive="AES-128",
            primitiveCategory="symmetric",
            keySizeBits=128,
            mode="CBC",
            confidence=0.88,
            detectionTier="manifest",
        ),
    ]


def validate_target(source_type: str, target: str):
    from backend.ingestion import validate_input
    return __import__("pathlib").Path(validate_input(source_type, target))


def run_scanners(source_type: str, target: str, scan_id: str) -> List[RawFinding]:
    """Run the actual M1/M2/M3 modules; an empty scan stays empty."""
    from backend.scanners.source.scanner import scan_repository
    from backend.scanners.source.tier1 import scan_file
    from backend.scanners.source.tier2 import confirm
    from backend.scanners.binary_deps.scanner import scan_path as scan_dependencies
    from backend.scanners.infra.scanner import scan_path as scan_infrastructure

    from backend.ingestion import prepared_target, validate_input
    validate_input(source_type, target)
    if source_type == "image":
        from backend.scanners.infra.container import scan_container_image
        return [RawFinding.model_validate(f.model_dump()) for f in scan_container_image(target, scan_id)]
    with prepared_target(source_type, target) as root:
        return _scan_local(root, scan_id)


def _scan_local(root, scan_id):
    from backend.scanners.source.scanner import scan_repository
    from backend.scanners.source.tier1 import scan_file
    from backend.scanners.source.tier2 import confirm
    from backend.scanners.binary_deps.scanner import scan_path as scan_dependencies
    from backend.scanners.infra.scanner import scan_path as scan_infrastructure
    source = scan_repository(root, scan_id) if root.is_dir() else confirm(scan_file(root, scan_target_id=scan_id))
    raw = [*source, *scan_dependencies(root, scan_id), *scan_infrastructure(root, scan_id)]
    categories = {"symmetric-cipher": "symmetric", "asymmetric-cipher": "asymmetric_kem",
                  "signature": "asymmetric_sig", "certificate": "cert"}
    findings = []
    for item in raw:
        data = item.model_dump()
        data["primitiveCategory"] = categories.get(data["primitiveCategory"], data["primitiveCategory"])
        path = __import__("pathlib").Path(data["filePath"])
        if path.is_absolute():
            data["filePath"] = str(path.relative_to(root if root.is_dir() else root.parent))
        findings.append(RawFinding.model_validate(data))
    return findings
