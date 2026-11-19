"""Aggregated migration roadmap for a completed scan."""
import json
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.db_models import Asset, Scan

router = APIRouter(prefix="/roadmap", tags=["Roadmap"])

PHASES = [
    ("immediate", "Act now", "Broken or expiring today; schedule this first."),
    ("transition", "Plan and stage", "Quantum-vulnerable or deprecated; begin the transition."),
    ("target", "Reach target state", "Complete the committed migration."),
    ("monitor", "Monitor and review", "Retain with periodic review or resolve unknowns."),
]

_TIER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, None: 4}


@router.get("/{scan_id}")
def get_roadmap(scan_id: str, db: Session = Depends(get_db)):
    """Group a scan's assets into phased, ordered migration work."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    grouped: Dict[str, List[dict]] = {phase_id: [] for phase_id, _, _ in PHASES}

    for asset in assets:
        phase = asset.migration_phase if asset.migration_phase in grouped else "monitor"
        grouped[phase].append({
            "id": asset.id,
            "bomRef": asset.bom_ref,
            "name": asset.name,
            "artifactType": asset.artifact_type,
            "usageContext": asset.usage_context,
            "action": asset.migration_action,
            "readinessTier": asset.readiness_tier,
            "hndlTier": asset.hndl_tier,
            "riskTier": asset.risk_tier,
            "target": _target(asset) or None,
        })

    phases = []
    for phase_id, label, description in PHASES:
        items = sorted(grouped[phase_id], key=lambda item: _TIER_ORDER.get(item["riskTier"], 4))
        phases.append({
            "id": phase_id,
            "label": label,
            "description": description,
            "count": len(items),
            "items": items,
        })

    return {
        "scanId": scan_id,
        "phases": phases,
        "total": len(assets),
        "summary": {
            "immediate": len(grouped["immediate"]),
            "transition": len(grouped["transition"]),
            "target": len(grouped["target"]),
            "monitor": len(grouped["monitor"]),
        },
    }


def _target(asset: Asset) -> str:
    try:
        enrichment = json.loads(asset.asset_json).get("ecdatEnrichment", {})
        return enrichment.get("recommendedReplacement", "")
    except (TypeError, ValueError):
        return ""
