"""
Report Export API route: GET /reports/{scanId}?format=pdf|csv|json
Delegates to the M9 reporting module.
"""
import json
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Scan, Asset, Recommendation
from backend.version import VERSION
from backend.engine.reporting import generate_report

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{scan_id}")
def export_scan_report(
    scan_id: str,
    format: Literal["pdf", "csv", "xlsx", "json", "sarif"] = Query("json", description="Report format: pdf, csv, xlsx, json, or sarif"),
    db: Session = Depends(get_db),
):
    """
    Generates and downloads a report for the specified scan.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan '{scan_id}' is '{scan.status}'. Reports are only available once scan completes."
        )

    # Fetch flat asset records for CSV/PDF generation
    db_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    assets_data = []

    for a in db_assets:
        rec = db.query(Recommendation).filter(Recommendation.asset_id == a.id).first()
        try:
            payload = json.loads(a.asset_json)
        except (TypeError, ValueError):
            payload = {}
        enrichment = payload.get("ecdatEnrichment", {})
        crypto = payload.get("cryptoProperties", {})
        algorithm = crypto.get("algorithmProperties", {})
        assets_data.append({
            "id": a.id,
            "bom_ref": a.bom_ref,
            "type": crypto.get("assetType", ""),
            "name": a.name,
            "primitive_category": a.primitive_category,
            "file_path": a.file_path,
            "line_number": a.line_number,
            "library": a.library,
            "key_size": algorithm.get("classicalSecurityLevel", ""),
            "business_criticality": a.business_criticality,
            "exposure": a.exposure,
            "risk_tier": a.risk_tier,
            "risk_score": a.risk_score,
            "urgency_ratio_r": a.urgency_ratio_r,
            "shelf_life_x": a.shelf_life_x,
            "migration_effort_y": a.migration_effort_y,
            "threat_timeline_z": a.threat_timeline_z,
            "quantum_vulnerable": a.quantum_vulnerable,
            "auto_escalated": enrichment.get("autoEscalated", False),
            "recommended_replacement": rec.recommended_algorithm if rec else "",
            "complexity": (rec.complexity if rec else "") or enrichment.get("migrationComplexity", ""),
            "reference_standard": rec.reference_standard if rec else "",
            "usage_context": a.usage_context or enrichment.get("usageContext", ""),
            "artifact_type": a.artifact_type or enrichment.get("artifactType", ""),
            "classical_status": a.classical_status or enrichment.get("classicalStatus", ""),
            "quantum_status": a.quantum_status or enrichment.get("quantumStatus", ""),
            "standards_maturity": a.standards_maturity or enrichment.get("standardsMaturity", ""),
            "migration_action": a.migration_action or enrichment.get("migrationAction", ""),
            "migration_phase": a.migration_phase or enrichment.get("migrationPhase", ""),
            "readiness_tier": a.readiness_tier or enrichment.get("readinessTier", ""),
            "hndl_tier": a.hndl_tier or enrichment.get("hndlTier", ""),
        })

    content_bytes, media_type, filename = generate_report(
        scan_id=scan_id,
        raw_cbom_json=scan.raw_cbom_json or "{}",
        assets_data=assets_data,
        report_format=format,
        tool_version=VERSION,
    )

    return Response(
        content=content_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""},
    )
