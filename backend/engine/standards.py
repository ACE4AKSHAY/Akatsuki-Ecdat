"""Versioned standards and policy registry access (M5/M6 support).

Policy data lives in ``backend/knowledge/standards_registry.json`` so
recommendations can be reviewed and updated without editing engine logic.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "standards_registry.json"

_UNKNOWN = {
    "entryId": None,
    "displayName": "Unknown",
    "classicalStatus": "unknown",
    "quantumStatus": "unknown",
    "standardsMaturity": "not-applicable",
    "defaultAction": "manual-review",
    "standard": "Not determined",
    "family": "unknown",
    "useCases": [],
    "notes": "Static evidence is insufficient to classify this artefact.",
}

_CATEGORY_TO_USE_CASE = {
    "asymmetric_kem": "key-establishment",
    "asymmetric-cipher": "key-establishment",
    "asymmetric_sig": "signatures",
    "signature": "signatures",
    "cert": "certificates",
    "certificate": "certificates",
    "protocol": "transport",
    "cipher": "encryption",
    "symmetric-cipher": "encryption",
}

_ACTION_BY_FAMILY = {
    "kem": "hybridize",
    "signature": "replace",
    "symmetric": "replace",
    "kdf": "replace",
    "protocol": "reconfigure",
    "certificate": "reissue-certificate",
}


@lru_cache(maxsize=1)
def get_registry() -> Dict[str, Any]:
    with REGISTRY_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _by_id() -> Dict[str, Dict[str, Any]]:
    return {entry["id"]: entry for entry in get_registry()["entries"]}


@lru_cache(maxsize=1)
def _alias_index() -> List[tuple[str, Dict[str, Any]]]:
    pairs: List[tuple[str, Dict[str, Any]]] = []
    for entry in get_registry()["entries"]:
        for alias in entry.get("aliases", []):
            pairs.append((alias.upper(), entry))
        pairs.append((entry["id"].upper(), entry))
    # Longest alias first so "SHA-256" wins over "SHA".
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    return pairs


def get_entry(entry_id: str) -> Optional[Dict[str, Any]]:
    return _by_id().get(entry_id)


def _category_use_case(category: Optional[str]) -> Optional[str]:
    if not category:
        return None
    return _CATEGORY_TO_USE_CASE.get(category.lower())


def _matches_category(entry: Dict[str, Any], category: Optional[str]) -> bool:
    use_case = _category_use_case(category)
    return use_case is None or use_case in entry.get("useCases", [])


def resolve_entry(name: str, category: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Resolve an algorithm or artefact name to a registry entry.

    Tries an exact alias first, then a longest-substring match, while
    preferring entries compatible with the reported primitive category.
    """
    clean = name.upper().replace("_", "-").strip()
    if not clean:
        return None

    exact = [entry for alias, entry in _alias_index() if alias == clean]
    for entry in exact:
        if _matches_category(entry, category):
            return entry
    if exact:
        return exact[0]

    for alias, entry in _alias_index():
        if alias in clean and _matches_category(entry, category):
            return entry
    return None


def classify(
    name: str,
    category: Optional[str] = None,
    key_size: Optional[int] = None,
    mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Classify a detected artefact on the four independent policy axes."""
    entry = resolve_entry(name, category)

    # Key size can change the entry for a family with parameter-dependent status.
    if entry and entry["family"] == "symmetric" and "AES" in name.upper() and key_size:
        if key_size >= 256:
            entry = get_entry("aes-256") or entry
        elif key_size <= 128:
            entry = get_entry("aes-128") or entry

    if not entry:
        result = dict(_UNKNOWN)
        result["displayName"] = name
        return result

    result = {
        "entryId": entry["id"],
        "displayName": entry["displayName"],
        "classicalStatus": entry["classicalStatus"],
        "quantumStatus": entry["quantumStatus"],
        "standardsMaturity": entry["status"],
        "defaultAction": entry["defaultAction"],
        "standard": entry["standard"],
        "family": entry["family"],
        "useCases": list(entry.get("useCases", [])),
        "notes": entry.get("notes", ""),
    }

    # ECB is never an acceptable mode for new work, even with a strong cipher.
    if mode and mode.upper() == "ECB" and result["classicalStatus"] in {"strong", "acceptable"}:
        result["classicalStatus"] = "deprecated"
        result["defaultAction"] = "reconfigure"
        result["notes"] = "ECB mode leaks plaintext structure; migrate to an AEAD mode."

    return result


def candidate_view(entry_id: str, fit: str = "preferred", compliance_target: str = "NIST-general") -> Optional[Dict[str, Any]]:
    """Render a registry entry as a UI/report-friendly candidate."""
    entry = get_entry(entry_id)
    if not entry:
        return None

    action = _ACTION_BY_FAMILY.get(entry["family"], "manual-review")
    if entry["family"] == "kem":
        action = "hybridize"
    if entry["id"] in {"hqc", "fn-dsa"}:
        action = "monitor"

    resolved_fit = fit
    if compliance_target == "CNSA2.0":
        if entry["id"] in {"ml-kem-1024", "ml-dsa-87"} and fit == "cnsa-preferred":
            resolved_fit = "preferred"
        elif fit == "preferred":
            resolved_fit = "transition"
        elif fit == "cnsa-preferred":
            resolved_fit = "alternative"
    elif fit == "cnsa-preferred":
        resolved_fit = "alternative"

    return {
        "id": entry["id"],
        "label": entry["displayName"],
        "action": action,
        "role": ", ".join(entry.get("useCases", [])),
        "standard": entry["standard"],
        "maturity": entry["status"],
        "fit": resolved_fit,
        "latencyImpact": entry.get("latencyImpact", "unknown"),
        "costImpact": entry.get("costImpact", "unknown"),
        "constraints": list(entry.get("constraints", [])),
        "rationale": entry.get("notes", ""),
        "references": list(entry.get("references", [])),
    }


_FIT_ORDER = {
    "preferred": 0,
    "transition": 1,
    "acceptable-alternative": 2,
    "alternative": 3,
    "tracked-future": 4,
}


def candidates_for_path(path_id: str, compliance_target: str = "NIST-general") -> List[Dict[str, Any]]:
    for path in get_registry().get("migrationPaths", []):
        if path["id"] == path_id:
            views = [
                candidate_view(item["entryId"], item.get("fit", "preferred"), compliance_target)
                for item in path.get("candidates", [])
            ]
            ranked = [view for view in views if view]
            ranked.sort(key=lambda view: _FIT_ORDER.get(view["fit"], 99))
            return ranked
    return []


def path_id_for_role(role: str) -> Optional[str]:
    for path in get_registry().get("migrationPaths", []):
        if role in path.get("roles", []):
            return path["id"]
    return None


def registry_summary() -> Dict[str, Any]:
    registry = get_registry()
    return {
        "registryVersion": registry["registryVersion"],
        "reviewedOn": registry["reviewedOn"],
        "entryCount": len(registry["entries"]),
        "entries": [
            {
                "id": entry["id"],
                "displayName": entry["displayName"],
                "family": entry["family"],
                "standard": entry["standard"],
                "status": entry["status"],
                "classicalStatus": entry["classicalStatus"],
                "quantumStatus": entry["quantumStatus"],
                "references": entry.get("references", []),
            }
            for entry in registry["entries"]
        ],
    }


def iter_entries() -> Iterable[Dict[str, Any]]:
    return iter(get_registry()["entries"])
