"""Usage-context inference for cryptographic findings (M1/M4 support).

The same algorithm needs different migration advice depending on its role.
These heuristics only classify context when the evidence supports it and
otherwise return ``unknown`` so the UI can ask for human review.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

ARTIFACT_TYPES = {
    "certificate": "certificate",
    "cert": "certificate",
    "protocol": "protocol",
    "key-management": "key-reference",
    "library": "library",
    "hardware": "hardware-module",
    "cloud-service": "cloud-service",
}

_PASSWORD_HINTS = ("password", "passwd", "credential", "login", "passphrase")
_PASSWORD_SIGNAL_HINTS = ("bcrypt", "argon2", "scrypt", "pbkdf2", "hash_password", "check_password")
_TOKEN_HINTS = ("jwt", "token", "session")
_SIGN_HINTS = ("sign", "signature", "verify", "signer")
_FIRMWARE_HINTS = ("firmware", "boot", "rom", "u-boot", "secureboot")
_KMS_HINTS = ("kms", "keyvault", "key_vault", "vault", "hsm", "pkcs11", "secretsmanager", "secret_manager")
_CERT_HINTS = (".pem", ".crt", ".cer", ".p12", ".pfx", ".jks", "truststore", "keystore")
_TRANSPORT_HINTS = ("tls", "ssl", "https", "handshake", "nginx", "httpd", "haproxy", "envoy")


def _contains(text: str, hints: Tuple[str, ...]) -> bool:
    return any(hint in text for hint in hints)


def infer_usage_context(
    file_path: str,
    raw_signal: str,
    primitive_category: Optional[str],
    detected_primitive: str = "",
    mode: Optional[str] = None,
) -> Tuple[str, float]:
    """Return ``(usage_context, confidence)`` for a finding."""
    path = (file_path or "").lower()
    signal = (raw_signal or "").lower()
    primitive = (detected_primitive or "").lower()
    category = (primitive_category or "").lower()

    if category in {"certificate", "cert"} or _contains(path, _CERT_HINTS):
        if _contains(path, _FIRMWARE_HINTS):
            return "firmware-signing", 0.8
        return "certificate", 0.9

    if category == "protocol" or _contains(path, _TRANSPORT_HINTS):
        return "transport", 0.85

    if category == "kdf" and _contains(path + signal, _PASSWORD_HINTS):
        return "password-storage", 0.9

    if _contains(path, _PASSWORD_HINTS) or _contains(signal, _PASSWORD_SIGNAL_HINTS):
        return "password-storage", 0.9

    if _contains(path, _FIRMWARE_HINTS) and (category in {"signature", "asymmetric_sig"} or "sign" in signal or "rsa" in primitive):
        return "firmware-signing", 0.8

    if _contains(path, _KMS_HINTS):
        return "key-establishment", 0.5

    if _contains(path, _TOKEN_HINTS) and (category in {"signature", "asymmetric_sig", "hash"} or "sign" in signal):
        return "token-signing", 0.75

    if category in {"asymmetric_kem", "asymmetric-cipher"}:
        return "key-establishment", 0.8

    if category in {"asymmetric_sig", "signature"}:
        return "signing", 0.8

    if category in {"symmetric", "symmetric-cipher", "cipher"}:
        return "encryption", 0.8

    if category in {"hash", "mac"}:
        if _contains(path, _SIGN_HINTS) or "sign" in signal:
            return "signing", 0.6
        return "hashing", 0.75

    if _contains(signal, _SIGN_HINTS):
        return "signing", 0.6

    return "unknown", 0.0


def infer_artifact_type(primitive_category: Optional[str], usage_context: str) -> str:
    """Classify the artefact independently from the algorithm family."""
    category = (primitive_category or "").lower()
    if category in ARTIFACT_TYPES:
        return ARTIFACT_TYPES[category]
    if usage_context == "certificate":
        return "certificate"
    if usage_context == "transport":
        return "protocol"
    if usage_context in {"password-storage", "hashing"}:
        return "algorithm"
    return "algorithm"


def confidentiality_relevant(usage_context: str) -> bool:
    return usage_context in {"encryption", "key-establishment", "transport", "key-management", "data-protection"}


def signature_relevant(usage_context: str) -> bool:
    return usage_context in {"signing", "token-signing", "firmware-signing", "certificate"}


def build_context(
    file_path: str,
    raw_signal: str,
    primitive_category: Optional[str],
    detected_primitive: str,
    mode: Optional[str] = None,
) -> Dict[str, object]:
    usage, confidence = infer_usage_context(
        file_path, raw_signal, primitive_category, detected_primitive, mode
    )
    return {
        "usageContext": usage,
        "contextConfidence": confidence,
        "artifactType": infer_artifact_type(primitive_category, usage),
        "confidentialityRelevant": confidentiality_relevant(usage),
        "signatureRelevant": signature_relevant(usage),
    }
