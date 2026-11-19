"""Migration strategy engine (M6).

Converts an assessed finding into a ranked set of candidates, one chosen
action, explicit blockers and a phased playbook.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.engine.playbook import build_playbook
from backend.engine.standards import candidates_for_path, get_entry, resolve_entry

_VALID_ACTIONS = {
    "retain",
    "monitor",
    "deprecate",
    "replace",
    "hybridize",
    "rotate",
    "reissue-certificate",
    "upgrade-library",
    "reconfigure",
    "manual-review",
}

_BROKEN_SYMMETRIC = {"des", "3des", "rc4", "blowfish"}
_BROKEN_HASH = {"md5", "sha-1"}


def _pick(candidates: List[Dict[str, Any]], compliance_target: str) -> Optional[Dict[str, Any]]:
    if not candidates:
        return None
    order = ["preferred", "transition", "acceptable-alternative", "alternative", "tracked-future"]
    if compliance_target == "CNSA2.0":
        order = ["preferred", "transition", "acceptable-alternative", "alternative", "tracked-future"]
    for fit in order:
        for candidate in candidates:
            if candidate["fit"] == fit:
                return candidate
    return candidates[0]


def _template_for(
    artifact_type: str,
    usage_context: str,
    classical_status: str,
    quantum_status: str,
    entry_id: Optional[str],
    action: str,
) -> str:
    if action == "retain":
        return "retain"
    if action == "manual-review":
        return "review"
    if artifact_type == "certificate":
        return "certificate"
    if artifact_type == "protocol" or usage_context == "transport":
        return "protocol"
    if usage_context == "password-storage":
        return "password-storage"
    if usage_context == "firmware-signing":
        return "firmware-signature"
    if usage_context in {"signing", "token-signing"}:
        return "signature"
    if usage_context == "key-establishment":
        return "key-establishment"
    if entry_id in _BROKEN_HASH:
        return "legacy-hash"
    if entry_id in _BROKEN_SYMMETRIC:
        return "legacy-symmetric"
    if usage_context == "encryption":
        return "legacy-symmetric"
    if usage_context in {"hashing", "integrity"} and classical_status in {"broken", "deprecated"}:
        return "legacy-hash"
    return "review"


def build_migration_strategy(
    *,
    name: str,
    primitive_category: str,
    usage_context: str,
    artifact_type: str,
    classical_status: str,
    quantum_status: str,
    compliance_target: str = "NIST-general",
    latency_sensitive: bool = False,
    is_firmware: bool = False,
    mode: Optional[str] = None,
    certificate_facts: Optional[Dict[str, Any]] = None,
    blockers: Optional[List[str]] = None,
    mosca_tier: str = "Low",
) -> Dict[str, Any]:
    """Return ranked candidates, the selected action, and a phased playbook."""
    entry = resolve_entry(name, primitive_category)
    entry_id = entry["id"] if entry else None
    assumptions: List[str] = []
    candidates: List[Dict[str, Any]] = []
    action = "manual-review"
    phase = "monitor"
    template_id = "review"
    target_label = "Review required"
    target_maturity = "not-applicable"
    rationale = "Static evidence is insufficient to prescribe a migration path."

    # 1. Certificates are lifecycle assets first and algorithm assets second.
    if artifact_type == "certificate":
        candidates = candidates_for_path("certificate", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "reissue-certificate"
        template_id = "certificate"
        target_label = selected["label"] if selected else "Renewal with reviewed algorithm"
        target_maturity = selected["maturity"] if selected else "not-applicable"
        phase = "transition" if mosca_tier in {"Critical", "High"} else "monitor"
        facts = certificate_facts or {}
        days = facts.get("daysToExpiry")
        if days is not None and isinstance(days, (int, float)) and days < 90:
            phase = "immediate"
        rationale = (
            "Certificates must change at a renewal boundary with CA and client compatibility confirmed."
        )
        assumptions.append("Certificate role and trust path were inferred from the file location.")

    # 2. Password storage must not be redirected to a general-purpose digest.
    elif usage_context == "password-storage":
        candidates = candidates_for_path("password-storage", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "replace"
        phase = "immediate" if classical_status in {"broken", "deprecated"} else "transition"
        template_id = "password-storage"
        target_label = selected["label"] if selected else "Argon2id"
        target_maturity = selected["maturity"] if selected else "final"
        rationale = "Legacy password digests are unsafe; use a memory-hard password KDF and rehash on login."

    # 3. Protocol and configuration findings.
    elif artifact_type == "protocol" or usage_context == "transport":
        candidates = candidates_for_path("protocol", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "reconfigure"
        template_id = "protocol"
        phase = "immediate" if classical_status == "broken" else "transition"
        target_label = "TLS 1.3 with a modern cipher policy"
        target_maturity = "final"
        rationale = "The negotiated protocol or cipher policy must be fixed before key-exchange migration."
        if entry_id == "tls-1.3":
            action = "hybridize"
            hybrid = next((c for c in candidates if c["id"] == "x25519mlkem768"), None)
            if hybrid:
                target_label = hybrid["label"]
                target_maturity = hybrid["maturity"]

    # 4. Classically broken or deprecated primitives take precedence.
    elif classical_status == "broken" and entry_id in _BROKEN_SYMMETRIC:
        candidates = candidates_for_path("legacy-symmetric", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "replace"
        phase = "immediate"
        template_id = "legacy-symmetric"
        target_label = selected["label"] if selected else "AES-256-GCM"
        target_maturity = selected["maturity"] if selected else "final"
        rationale = "The cipher is broken today; replace it with an AEAD construction before considering quantum migration."

    elif classical_status == "deprecated" and entry_id in _BROKEN_SYMMETRIC:
        candidates = candidates_for_path("legacy-symmetric", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "deprecate"
        phase = "immediate"
        template_id = "legacy-symmetric"
        target_label = selected["label"] if selected else "AES-256-GCM"
        target_maturity = selected["maturity"] if selected else "final"
        rationale = "The cipher is deprecated; replace it with an AEAD construction at the next change window."

    elif entry_id in _BROKEN_HASH or classical_status == "broken":
        candidates = candidates_for_path("hash-integrity", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "deprecate"
        phase = "immediate"
        template_id = "legacy-hash"
        target_label = selected["label"] if selected else "SHA-384"
        target_maturity = selected["maturity"] if selected else "final"
        rationale = "Collision resistance is broken; replace the digest in every collision-sensitive use."

    # 5. Quantum-vulnerable key establishment.
    elif usage_context == "key-establishment" and quantum_status == "vulnerable":
        candidates = candidates_for_path("key-establishment", compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "replace" if compliance_target == "CNSA2.0" else "hybridize"
        phase = "transition"
        template_id = "key-establishment"
        target_label = selected["label"] if selected else "ML-KEM-768"
        target_maturity = selected["maturity"] if selected else "final"
        rationale = (
            "Key establishment is quantum-vulnerable and exposed to harvest-now-decrypt-later risk; "
            "a PQ/T hybrid preserves classical compatibility during the transition."
        )
        if latency_sensitive:
            assumptions.append("Latency sensitivity favours the smaller parameter set where security policy allows.")

    # 6. Quantum-vulnerable signatures.
    elif usage_context in {"signing", "token-signing", "firmware-signing"} and quantum_status == "vulnerable":
        path_id = "firmware-signature" if (is_firmware or usage_context == "firmware-signing") else "signature"
        candidates = candidates_for_path(path_id, compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "replace"
        phase = "transition"
        template_id = path_id
        target_label = selected["label"] if selected else "ML-DSA-65"
        target_maturity = selected["maturity"] if selected else "final"
        rationale = "Digital signatures are quantum-vulnerable and must migrate before the signing trust anchor is renewed."
        if selected and selected["id"] == "lms-xmss":
            assumptions.append("LMS/XMSS are stateful; the signing service must guarantee one-time key state.")

    # 7. AES-128 or other weakened symmetric primitives.
    elif quantum_status == "weakened" and entry_id in {"aes-128", "sha-256", "sha3-256"}:
        path_id = "symmetric-strength" if entry_id == "aes-128" else "hash-integrity"
        candidates = candidates_for_path(path_id, compliance_target)
        selected = _pick(candidates, compliance_target)
        action = "replace" if entry_id == "aes-128" else "monitor"
        phase = "transition" if entry_id == "aes-128" else "monitor"
        template_id = "legacy-symmetric" if entry_id == "aes-128" else "retain"
        target_label = selected["label"] if selected else ("AES-256-GCM" if entry_id == "aes-128" else "Retain with review")
        target_maturity = selected["maturity"] if selected else "final"
        rationale = (
            "Grover reduces the effective symmetric margin; plan a larger key for long-lived sensitive data."
            if entry_id == "aes-128"
            else "The digest is acceptable for its role; monitor the configuration and data lifetime."
        )

    # 8. Strong assets are retained.
    elif classical_status in {"strong", "acceptable"} and quantum_status in {"resistant", "weakened"}:
        action = "retain" if quantum_status == "resistant" else "monitor"
        template_id = "retain"
        phase = "monitor"
        target_label = "No algorithm change required"
        target_maturity = "final"
        rationale = "No cryptographic replacement is identified; validate usage and configuration."

    # 9. Unknown or ambiguous evidence.
    else:
        action = "manual-review"
        template_id = "review"
        phase = "monitor"
        rationale = "The observed evidence is insufficient to determine a safe replacement."

    if action not in _VALID_ACTIONS:
        action = "manual-review"

    if usage_context == "unknown":
        assumptions.append("Cryptographic usage context could not be inferred; a reviewer must confirm the role.")
    assumptions.append("Readiness and risk are estimates from static evidence, not runtime proof.")

    playbook = build_playbook(template_id, target_label, blockers, certificate_facts)

    return {
        "action": action,
        "phase": phase,
        "templateId": template_id,
        "selectedCandidate": target_label,
        "target": target_label,
        "maturity": target_maturity,
        "candidates": candidates,
        "blockers": list(blockers or []),
        "assumptions": assumptions,
        "playbook": playbook,
        "rationale": rationale,
    }


def legacy_recommendation_name(strategy: Dict[str, Any], fallback: str) -> str:
    """Map a strategy result onto the legacy single-string recommendation field."""
    action = strategy["action"]
    if action in {"retain", "monitor"}:
        return "No change needed"
    if action == "manual-review":
        return "Review required"
    return strategy["selectedCandidate"] or fallback


def entry_status(entry_id: str) -> str:
    entry = get_entry(entry_id)
    return entry["status"] if entry else "not-applicable"
