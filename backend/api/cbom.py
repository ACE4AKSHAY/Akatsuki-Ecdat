"""
CBOM Export API route: GET /cbom/{scanId}
Exports CycloneDX 1.6 Cryptographic Bill of Materials JSON document.
GET /cbom/{scanId}/diff compares two scans' asset populations for drift.
"""
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Asset, Scan

router = APIRouter(prefix="/cbom", tags=["CBOM"])

# Identity of an asset across scans: same canonical algorithm means the same
# asset; these view keys decide whether it drifted.
_CHANGE_KEYS = ("riskTier", "migrationAction", "usageContext", "artifactType")


def _asset_view(asset: Asset) -> Dict[str, Any]:
    return {
        "name": asset.name,
        "bomRef": asset.bom_ref,
        "riskTier": asset.risk_tier,
        "migrationAction": asset.migration_action,
        "usageContext": asset.usage_context,
        "artifactType": asset.artifact_type,
    }


def _fingerprint(view: Dict[str, Any]) -> tuple:
    return tuple(view[key] for key in _CHANGE_KEYS)


def _collect(db: Session, scan_id: str) -> Dict[str, Dict[str, Any]]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan '{scan_id}' is '{scan.status}'. Drift comparison needs a completed scan.",
        )
    rows = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    return {row.name: _asset_view(row) for row in rows}


@router.get("/{scan_id}/diff")
def diff_cbom(
    scan_id: str,
    against: str = Query(..., description="Scan id to compare with (the older scan)"),
    db: Session = Depends(get_db),
):
    """Compare two completed scans of the same estate and report crypto drift."""
    current = _collect(db, scan_id)
    baseline = _collect(db, against)

    added = [view for name, view in current.items() if name not in baseline]
    removed = [view for name, view in baseline.items() if name not in current]
    changed = []
    for name, view in current.items():
        baseline_view = baseline.get(name)
        if baseline_view and _fingerprint(view) != _fingerprint(baseline_view):
            changed.append({
                "name": name,
                "before": {key: baseline_view[key] for key in _CHANGE_KEYS},
                "after": {key: view[key] for key in _CHANGE_KEYS},
            })

    return {
        "scanId": scan_id,
        "against": against,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(set(current) & set(baseline)) - len(changed),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }


@router.get("/{scan_id}")
def download_cbom_json(scan_id: str, db: Session = Depends(get_db)):
    """
    Returns the standardized CycloneDX 1.6 CBOM document for the specified scan ID.
    Delivered with Content-Disposition: attachment.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan '{scan_id}' is currently in state '{scan.status}'. CBOM is only available once completed."
        )

    content = scan.raw_cbom_json or "{}"
    filename = f"cyclonedx-cbom-{scan_id}.json"

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=\"{filename}\"",
            "X-CycloneDX-Spec": "1.6",
        },
    )
