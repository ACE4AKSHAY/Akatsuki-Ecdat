"""SARIF 2.1.0 export so ECDAT results surface in code-scanning consumers.

Each assessed asset becomes one SARIF result, with the risk tier mapped to a
SARIF level and the migration plan carried in the message and properties.
Tools such as GitHub code scanning ingest SARIF directly, which is the
interoperability lane cbomkit-action and cryptobom-forge occupy.
"""
from __future__ import annotations

from typing import Any, Dict, List

_TOOL_NAME = "ECDAT"
_TOOL_URI = "https://github.com/ACE4AKSHAY/Akatsuki-Ecdat"

_RULE_TITLES = {
    "replace": "Replace the cryptographic primitive",
    "hybridize": "Bridge with a hybrid construction",
    "reconfigure": "Reconfigure mode or protocol",
    "reissue-certificate": "Re-issue the certificate",
    "deprecate": "Deprecate the primitive",
    "rotate": "Rotate the key material",
    "retain": "Retain at target state",
    "monitor": "Monitor and review",
    "manual-review": "Manual review required",
}

_TIER_TO_LEVEL = {
    "Critical": "error",
    "High": "warning",
    "Medium": "note",
    "Low": "none",
}


def _rule_id(action: str) -> str:
    return f"ECDAT/{action or 'manual-review'}"


def _uri(path: str) -> str:
    return (path or "unknown").replace("\\", "/")


def _message(asset: Dict[str, Any]) -> str:
    target = asset.get("recommended_replacement") or "review required"
    context = asset.get("usage_context") or "unknown"
    classical = asset.get("classical_status") or "unknown"
    quantum = asset.get("quantum_status") or "unknown"
    return (
        f"{asset.get('name', 'unknown asset')} used for {context}: classical {classical}, "
        f"quantum {quantum}. Plan: {asset.get('migration_action') or 'manual-review'} "
        f"in phase {asset.get('migration_phase') or 'monitor'} — target {target}."
    )


def build_sarif(scan_id: str, version: str, assets_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for asset in assets_data:
        action = asset.get("migration_action") or "manual-review"
        rule_id = _rule_id(action)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": _RULE_TITLES.get(action, "Manual review required").replace(" ", ""),
                "shortDescription": {
                    "text": _RULE_TITLES.get(action, "Manual review required")
                },
                "fullDescription": {
                    "text": (
                        f"ECDAT assessed this cryptographic asset and recommends "
                        f"'{action}' as the migration action."
                    )
                },
                "helpUri": _TOOL_URI,
                "properties": {"action": action},
            }

        tier = asset.get("risk_tier") or "Low"
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _TIER_TO_LEVEL.get(tier, "note"),
            "message": {"text": _message(asset)},
            "properties": {
                "assetId": asset.get("id"),
                "bomRef": asset.get("bom_ref"),
                "riskTier": tier,
                "riskScore": asset.get("risk_score"),
                "moscaRatio": asset.get("urgency_ratio_r"),
                "usageContext": asset.get("usage_context"),
                "artifactType": asset.get("artifact_type"),
                "classicalStatus": asset.get("classical_status"),
                "quantumStatus": asset.get("quantum_status"),
                "standardsMaturity": asset.get("standards_maturity"),
                "readinessTier": asset.get("readiness_tier"),
                "hndlTier": asset.get("hndl_tier"),
                "recommendedReplacement": asset.get("recommended_replacement"),
                "migrationPhase": asset.get("migration_phase"),
            },
        }
        file_path = asset.get("file_path")
        if file_path:
            region: Dict[str, Any] = {}
            if asset.get("line_number"):
                region["startLine"] = int(asset["line_number"])
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(file_path)},
                    **({"region": region} if region else {}),
                }
            }]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "version": version,
                    "informationUri": _TOOL_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def export_sarif(scan_id: str, version: str, assets_data: List[Dict[str, Any]]) -> tuple[bytes, str, str]:
    import json

    document = build_sarif(scan_id=scan_id, version=version, assets_data=assets_data)
    content = json.dumps(document, indent=2)
    return (
        content.encode("utf-8"),
        "application/sarif+json",
        f"ecdat-sarif-{scan_id}.sarif",
    )
