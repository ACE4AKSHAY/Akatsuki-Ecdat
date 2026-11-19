"""Migration-readiness assessment.

Readiness answers a different question from risk: how feasible is the
migration with the evidence that was actually discovered. Each component is
scored 0-2 and every blocker is reported in plain language.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

COMPONENT_MAX = 2
COMPONENTS = (
    "algorithm_abstraction",
    "library_support",
    "protocol_support",
    "pki_or_key_support",
    "test_evidence",
    "dependency_visibility",
)

COMPONENT_LABELS = {
    "algorithm_abstraction": "Algorithm abstraction",
    "library_support": "Library or provider support",
    "protocol_support": "Protocol support",
    "pki_or_key_support": "PKI or key support",
    "test_evidence": "Compatibility test evidence",
    "dependency_visibility": "Dependency visibility",
}


def _protocol_score(usage_context: str, protocol: Optional[str]) -> int:
    if usage_context != "transport" and not protocol:
        return 1
    protocol_upper = (protocol or "").upper()
    if "1.3" in protocol_upper:
        return 2
    if "1.2" in protocol_upper:
        return 1
    return 0


def _pki_score(artifact_type: str, certificate_facts: Optional[Dict[str, Any]]) -> int:
    if artifact_type != "certificate":
        return 1
    if not certificate_facts:
        return 0
    if certificate_facts.get("selfSigned"):
        return 1
    if certificate_facts.get("issuer") or certificate_facts.get("notAfter"):
        return 2
    return 1


def assess_readiness(
    *,
    artifact_type: str,
    usage_context: str,
    library: Optional[str],
    provider_facts: Optional[Dict[str, Any]] = None,
    certificate_facts: Optional[Dict[str, Any]] = None,
    protocol: Optional[str] = None,
    has_config_abstraction: bool = False,
    dependency_visible: bool = True,
    test_evidence: bool = False,
) -> Dict[str, Any]:
    provider_facts = provider_facts or {}

    if has_config_abstraction:
        abstraction = 2
    elif library:
        abstraction = 1
    else:
        abstraction = 0

    pqc_support = provider_facts.get("pqcSupport")
    if pqc_support is True:
        library_support = 2
    elif library:
        library_support = 1
    else:
        library_support = 0

    protocol_support = _protocol_score(usage_context, protocol or provider_facts.get("protocol"))
    pki_support = _pki_score(artifact_type, certificate_facts)
    tests = 2 if test_evidence else 0
    dependencies = 2 if dependency_visible and library else (1 if dependency_visible else 0)

    scores = {
        "algorithm_abstraction": abstraction,
        "library_support": library_support,
        "protocol_support": protocol_support,
        "pki_or_key_support": pki_support,
        "test_evidence": tests,
        "dependency_visibility": dependencies,
    }

    total = sum(scores.values())
    maximum = len(COMPONENTS) * COMPONENT_MAX
    score = round(total / maximum * 100)

    blockers: List[str] = []
    if not library:
        blockers.append("Cryptographic provider is unknown; confirm library and version before planning.")
    elif pqc_support is not True:
        blockers.append("Library version and PQC support must be verified.")
    if usage_context == "transport" and protocol_support < 2:
        blockers.append("Protocol upgrade to TLS 1.3 or a supported PQ/T hybrid group is required.")
    if artifact_type == "certificate":
        blockers.append("Certificate authority and client compatibility must be confirmed before reissue.")
    if not test_evidence:
        blockers.append("No staging or integration evidence of a compatible target was found.")
    if not dependency_visible:
        blockers.append("Dependency graph is incomplete; direct and transitive providers may be missing.")

    evidence_insufficient = (not library) and (not certificate_facts) and not protocol
    if evidence_insufficient:
        tier = "Unknown"
    elif usage_context == "transport" and protocol_support == 0:
        tier = "Blocked"
    elif score >= 75:
        tier = "Ready"
    else:
        tier = "Partial"

    return {
        "score": score,
        "tier": tier,
        "maximum": maximum,
        "components": {
            key: {
                "label": COMPONENT_LABELS[key],
                "score": value,
                "maximum": COMPONENT_MAX,
            }
            for key, value in scores.items()
        },
        "blockers": blockers,
    }
