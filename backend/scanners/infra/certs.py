"""M3 certs sub-scanner — X.509 certificate parsing.

For each `.pem` / `.crt` / `.cer` file, emit a RawFinding per rule that
fires (all `detectionTier="cert-parse"`, `confidence=0.95`):
  - RSA key < 2048 bits  -> `detectedPrimitive="RSA-<bits>"`; reason
                             encoded in `library` field (CONTRACT.md
                             has no `flagReason` field — gap flagged to
                             Person B; do not edit CONTRACT.md).
  - Signature alg is SHA-1 or MD5 -> `detectedPrimitive="<hash>-RSA-SIG"`.
  - Self-signed (issuer == subject) -> `detectedPrimitive="self-signed-cert"`.
  - Validity > 2 years -> `detectedPrimitive="long-validity-cert"`,
                           `library="<N> years"`.
"""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from backend.scanners._finding import RawFinding
from backend.scanners.binary_deps.manifests import _strip_expected_header

CERT_EXTS = (".pem", ".crt", ".cer")

# Well-known signature-algorithm OIDs.
_OID_SHA1_RSA = "1.2.840.113549.1.1.5"
_OID_SHA256_RSA = "1.2.840.113549.1.1.11"
_OID_SHA384_RSA = "1.2.840.113549.1.1.12"
_OID_SHA512_RSA = "1.2.840.113549.1.1.13"
_OID_MD5_RSA = "1.2.840.113549.1.1.4"

_WEAK_SIG_HASH = {_OID_SHA1_RSA: "SHA1", _OID_MD5_RSA: "MD5"}

_SIG_NAMES = {
    _OID_SHA1_RSA: "sha1WithRSAEncryption",
    _OID_SHA256_RSA: "sha256WithRSAEncryption",
    _OID_SHA384_RSA: "sha384WithRSAEncryption",
    _OID_SHA512_RSA: "sha512WithRSAEncryption",
    _OID_MD5_RSA: "md5WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


def _key_algorithm(pub) -> str:
    name = type(pub).__name__
    if "RSA" in name:
        return "RSA"
    if "EllipticCurve" in name or name.startswith("EC"):
        return "EC"
    return name.replace("PublicKey", "") or "UNKNOWN"


def _is_cert_file(p: Path) -> bool:
    return p.suffix.lower() in CERT_EXTS


def _iter_certs(root: Path) -> Iterable[Path]:
    if root.is_file():
        if _is_cert_file(root):
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and _is_cert_file(p):
            yield p


def _load_cert(p: Path) -> x509.Certificate | None:
    raw = p.read_bytes()
    raw = _strip_expected_header(raw.decode("utf-8", errors="replace")).encode("utf-8")
    try:
        return x509.load_pem_x509_certificate(raw, default_backend())
    except Exception:
        pass
    try:
        return x509.load_der_x509_certificate(raw, default_backend())
    except Exception:
        return None


def _utc(cert: x509.Certificate) -> tuple[datetime.datetime, datetime.datetime]:
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_before, cert.not_valid_after


def cert_facts(cert: x509.Certificate) -> dict:
    """Structured X.509 facts for enrichment (v1.1 evidence, not a finding)."""
    nb, na = _utc(cert)
    now = datetime.datetime.now(datetime.timezone.utc)
    pub = cert.public_key()
    sig_oid = cert.signature_algorithm_oid.dotted_string
    facts = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "notBefore": nb.isoformat(),
        "notAfter": na.isoformat(),
        "daysToExpiry": (na - now).days,
        "keyAlgorithm": _key_algorithm(pub),
        "keySizeBits": getattr(pub, "key_size", None),
        "signatureAlgorithm": _SIG_NAMES.get(sig_oid, sig_oid),
        "selfSigned": cert.issuer == cert.subject,
        "sanCount": 0,
    }
    try:
        facts["signatureHash"] = cert.signature_hash_algorithm.name.upper()
    except Exception:
        facts["signatureHash"] = None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        facts["sanCount"] = len(san.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    return facts


def _cert_to_findings(cert: x509.Certificate, *, scan_target_id: str,
                      file_path: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    sig_oid = cert.signature_algorithm_oid.dotted_string
    facts = cert_facts(cert)
    evidence = {"certificateFacts": facts, "artifactType": "certificate"}

    # 1) Key size for RSA.
    pub = cert.public_key()
    try:
        key_size = pub.key_size  # RSAPublicKey has this; EC does not
        if key_size < 2048 and sig_oid in (_OID_SHA1_RSA, _OID_SHA256_RSA, _OID_SHA384_RSA, _OID_SHA512_RSA):
            out.append(RawFinding(
                sourceModule="M3_container_config_scanner",
                scanTargetId=scan_target_id,
                filePath=file_path,
                lineNumber=1,
                language=None,
                library=f"flag:small-rsa-key-{key_size}-bits",
                rawSignal=f"RSA public key {key_size} bits",
                detectedPrimitive=f"RSA-{key_size}",
                primitiveCategory="certificate",
                keySizeBits=key_size,
                mode="weak",
                confidence=0.95,
                detectionTier="cert-parse",
                **evidence,
            ))
    except AttributeError:
        pass  # EC key — no key_size attr

    # 2) Signature hash (SHA-1 / MD5).
    if sig_oid in _WEAK_SIG_HASH:
        hash_name = _WEAK_SIG_HASH[sig_oid]
        out.append(RawFinding(
            sourceModule="M3_container_config_scanner",
            scanTargetId=scan_target_id,
            filePath=file_path,
            lineNumber=1,
            language=None,
            library=f"flag:weak-sig-hash-{hash_name}",
            rawSignal=f"{hash_name}-with-RSA signature",
            detectedPrimitive=f"{hash_name}-RSA-SIG",
            primitiveCategory="certificate",
            keySizeBits=None,
            mode="weak",
            confidence=0.95,
            detectionTier="cert-parse",
            **evidence,
        ))

    # 3) Self-signed.
    try:
        if cert.issuer == cert.subject:
            out.append(RawFinding(
                sourceModule="M3_container_config_scanner",
                scanTargetId=scan_target_id,
                filePath=file_path,
                lineNumber=1,
                language=None,
                library="flag:self-signed",
                rawSignal="issuer == subject",
                detectedPrimitive="self-signed-cert",
                primitiveCategory="certificate",
                keySizeBits=None,
                mode="self-signed",
                confidence=0.95,
                detectionTier="cert-parse",
                **evidence,
            ))
    except Exception:
        pass

    # 4) Long validity (>2 years).
    nb, na = _utc(cert)
    if isinstance(nb, datetime.datetime) and isinstance(na, datetime.datetime):
        years = (na - nb).days / 365.25
        if years > 2.0:
            out.append(RawFinding(
                sourceModule="M3_container_config_scanner",
                scanTargetId=scan_target_id,
                filePath=file_path,
                lineNumber=1,
                language=None,
                library=f"flag:long-validity-{years:.1f}-years",
                rawSignal=f"validity {years:.1f} years",
                detectedPrimitive="long-validity-cert",
                primitiveCategory="certificate",
                keySizeBits=None,
                mode=f"{years:.1f}-years",
                confidence=0.95,
                detectionTier="cert-parse",
                **evidence,
            ))
    return out


def scan_certificates(path: str | Path, scan_target_id: str) -> list[RawFinding]:
    root = Path(path)
    if not root.exists():
        return []
    out: list[RawFinding] = []
    for f in _iter_certs(root):
        cert = _load_cert(f)
        if cert is None:
            continue
        out.extend(_cert_to_findings(cert, scan_target_id=scan_target_id,
                                     file_path=str(f)))
    return out
