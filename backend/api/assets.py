"""
Asset Inventory & Detail API routes: GET /assets, GET /assets/{id}
Supports filtering and dynamic Z-slider re-scoring for interactive heatmap simulator.
"""
import json
import math
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Asset, AuditEvent, Recommendation
from backend.models.schemas import (
    AssetSummaryResponse,
    AssetDetailResponse,
    AssetContextUpdateRequest,
    CanonicalCBOMAsset,
)
from backend.engine.risk import calculate_mosca_ratio, get_mosca_tier
from backend.engine.context import infer_artifact_type
from backend.engine.readiness import assess_readiness
from backend.engine.strategy import build_migration_strategy

router = APIRouter(prefix="/assets", tags=["Assets"])


def _relationships(db: Session, db_asset: Asset, asset_dict: dict) -> list:
    refs = asset_dict.get("ecdatEnrichment", {}).get("relatedAssetRefs") or []
    if not refs:
        return []
    rows = db.query(Asset).filter(
        Asset.scan_id == db_asset.scan_id, Asset.bom_ref.in_(refs)
    ).all()
    return [
        {
            "bomRef": row.bom_ref,
            "name": row.name,
            "artifactType": row.artifact_type,
            "relation": "referenced-by" if row.bom_ref in refs else "related",
        }
        for row in rows
    ]


def _strategy_from(enrichment) -> dict:
    return {
        "action": enrichment.migrationAction,
        "phase": enrichment.migrationPhase,
        "selectedCandidate": enrichment.recommendedReplacement,
        "candidates": enrichment.candidates,
        "blockers": enrichment.blockers,
        "assumptions": enrichment.assumptions,
        "playbook": enrichment.playbook,
        "rationale": enrichment.strategyRationale,
    }


def _assessment_from(enrichment) -> dict:
    return {
        "classicalStatus": enrichment.classicalStatus,
        "quantumStatus": enrichment.quantumStatus,
        "standardsMaturity": enrichment.standardsMaturity,
        "usageContext": enrichment.usageContext,
        "contextConfidence": enrichment.contextConfidence,
        "artifactType": enrichment.artifactType,
        "complianceTarget": enrichment.complianceTarget,
        "readiness": {
            "score": enrichment.readinessScore,
            "tier": enrichment.readinessTier,
            "components": enrichment.readinessComponents,
        },
        "hndl": {
            "applicable": enrichment.hndlApplicable,
            "tier": enrichment.hndlTier,
            "score": enrichment.hndlScore,
            "explanation": enrichment.hndlExplanation,
        },
        "certificateFacts": enrichment.certificateFacts,
        "evidence": enrichment.evidence,
    }


@router.get("", response_model=AssetSummaryResponse)
def list_assets(
    scanId: Optional[str] = Query(None, description="Filter by scan job ID"),
    riskTier: Optional[str] = Query(None, description="Filter by risk tier (Critical, High, Medium, Low)"),
    exposure: Optional[str] = Query(None, description="Filter by exposure (external-facing, internal-only)"),
    businessCriticality: Optional[str] = Query(None, description="Filter by business criticality"),
    algorithm: Optional[str] = Query(None, description="Filter by algorithm name (e.g. SHA-1, RSA-2048)"),
    usageContext: Optional[str] = Query(None, description="Filter by inferred use (signing, transport, password-storage…)"),
    artifactType: Optional[str] = Query(None, description="Filter by artifact type (algorithm, certificate, protocol…)"),
    migrationAction: Optional[str] = Query(None, description="Filter by selected action (replace, hybridize, retain…)"),
    readinessTier: Optional[str] = Query(None, description="Filter by migration readiness tier"),
    hndlTier: Optional[str] = Query(None, description="Filter by HNDL exposure tier"),
    page: int = Query(1, ge=1, description="Page number"),
    pageSize: int = Query(50, ge=1, le=200, description="Items per page"),
    z: Optional[float] = Query(None, ge=0.5, le=50.0, description="Interactive threat-timeline Z slider override"),
    db: Session = Depends(get_db),
):
    """
    Returns paginated assets matching filter criteria.
    If 'z' query parameter is provided, recomputes Mosca r = (X+Y)/Z and risk tier dynamically!
    """
    query = db.query(Asset)

    if scanId:
        query = query.filter(Asset.scan_id == scanId)
    if exposure:
        query = query.filter(Asset.exposure.ilike(f"%{exposure}%"))
    if businessCriticality:
        query = query.filter(Asset.business_criticality.ilike(f"%{businessCriticality}%"))
    if algorithm:
        query = query.filter(Asset.name.ilike(f"%{algorithm}%"))
    if usageContext:
        query = query.filter(Asset.usage_context == usageContext)
    if artifactType:
        query = query.filter(Asset.artifact_type == artifactType)
    if migrationAction:
        query = query.filter(Asset.migration_action == migrationAction)
    if readinessTier:
        query = query.filter(Asset.readiness_tier == readinessTier)
    if hndlTier:
        query = query.filter(Asset.hndl_tier == hndlTier)

    start_idx = (page - 1) * pageSize

    if z is None:
        # Stored tiers are used as-is, so filtering, counting and paging all
        # happen in the database instead of loading every row into memory.
        tier_counts = {
            tier: count
            for tier, count in query.with_entities(Asset.risk_tier, func.count())
            .group_by(Asset.risk_tier)
            .all()
        }
        crit_count = tier_counts.get("Critical", 0)
        high_count = tier_counts.get("High", 0)
        med_count = tier_counts.get("Medium", 0)
        low_count = tier_counts.get("Low", 0)

        if riskTier:
            query = query.filter(func.lower(Asset.risk_tier) == riskTier.lower())

        total_items = query.count()
        rows = query.offset(start_idx).limit(pageSize).all()
        paged_items = []
        for db_asset in rows:
            try:
                paged_items.append(
                    CanonicalCBOMAsset.model_validate(json.loads(db_asset.asset_json))
                )
            except Exception:
                continue

        z_used = 8.0
        first_row = db.query(Asset).filter(Asset.scan_id == scanId).first() if scanId else None
        if first_row:
            z_used = first_row.threat_timeline_z

        return AssetSummaryResponse(
            items=paged_items,
            total=total_items,
            page=page,
            pageSize=pageSize,
            pages=math.ceil(total_items / pageSize) if total_items > 0 else 1,
            zUsed=z_used,
            criticalCount=crit_count,
            highCount=high_count,
            mediumCount=med_count,
            lowCount=low_count,
        )

    all_matching_db_assets = query.all()

    # Recompute risk tier for the interactive threat-timeline slider.
    parsed_assets = []
    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0

    for db_asset in all_matching_db_assets:
        try:
            asset_dict = json.loads(db_asset.asset_json)
        except Exception:
            continue

        enrichment = asset_dict.get("ecdatEnrichment", {})

        # If dynamic Z is requested
        if z is not None and z > 0:
            x = db_asset.shelf_life_x
            y = db_asset.migration_effort_y
            r_dyn = calculate_mosca_ratio(x, y, z)
            
            # Check auto-escalation
            if enrichment.get("autoEscalated"):
                current_tier = "Critical"
            else:
                current_tier = get_mosca_tier(r_dyn)

            enrichment["moscaZ"] = z
            enrichment["moscaR"] = r_dyn
            enrichment["moscaRiskTier"] = current_tier
            asset_dict["ecdatEnrichment"] = enrichment
        else:
            current_tier = enrichment.get("moscaRiskTier", db_asset.risk_tier)

        # Count distribution
        if current_tier == "Critical":
            crit_count += 1
        elif current_tier == "High":
            high_count += 1
        elif current_tier == "Medium":
            med_count += 1
        elif current_tier == "Low":
            low_count += 1

        # If riskTier filter was passed, apply it here
        if riskTier and current_tier.lower() != riskTier.lower():
            continue

        try:
            parsed_assets.append(CanonicalCBOMAsset.model_validate(asset_dict))
        except Exception:
            continue

    total_items = len(parsed_assets)
    total_pages = math.ceil(total_items / pageSize) if total_items > 0 else 1

    start_idx = (page - 1) * pageSize
    end_idx = start_idx + pageSize
    paged_items = parsed_assets[start_idx:end_idx]

    z_used = z if z is not None else (all_matching_db_assets[0].threat_timeline_z if all_matching_db_assets else 8.0)

    return AssetSummaryResponse(
        items=paged_items,
        total=total_items,
        page=page,
        pageSize=pageSize,
        pages=total_pages,
        zUsed=z_used,
        criticalCount=crit_count,
        highCount=high_count,
        mediumCount=med_count,
        lowCount=low_count,
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset_detail(asset_id: str, db: Session = Depends(get_db)):
    """
    Returns full asset details including exact file/line, complete Mosca breakdown,
    and side-by-side migration recommendation.
    """
    # Look up by ID or by bom_ref
    db_asset = db.query(Asset).filter(
        (Asset.id == asset_id) | (Asset.bom_ref == asset_id)
    ).first()

    if not db_asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    asset_dict = json.loads(db_asset.asset_json)
    canonical_asset = CanonicalCBOMAsset.model_validate(asset_dict)
    enrichment = canonical_asset.ecdatEnrichment

    rec = db.query(Recommendation).filter(Recommendation.asset_id == db_asset.id).first()
    rec_dict = {
        "recommendedReplacement": rec.recommended_algorithm if rec else enrichment.recommendedReplacement,
        "mode": rec.mode if rec else enrichment.recommendationMode,
        "complexity": rec.complexity if rec else enrichment.migrationComplexity,
        "rationale": rec.rationale if rec else enrichment.vulnerabilityReason,
        "referenceStandard": rec.reference_standard if rec else enrichment.referenceStandard,
        "relativeSizeDelta": enrichment.relativeSizeDelta,
        "action": rec.action if rec else enrichment.migrationAction,
        "phase": rec.phase if rec else enrichment.migrationPhase,
    }

    mosca_breakdown = {
        "x": enrichment.moscaX,
        "y": enrichment.moscaY,
        "z": enrichment.moscaZ,
        "r": enrichment.moscaR,
        "riskTier": enrichment.moscaRiskTier,
        "riskScore": enrichment.riskScore,
        "quantumVulnerable": enrichment.quantumVulnerable,
        "autoEscalated": enrichment.autoEscalated,
        "escalationReason": enrichment.escalationReason or enrichment.vulnerabilityReason,
        "businessCriticality": enrichment.businessCriticality,
        "exposure": enrichment.exposure,
        "dataClassification": enrichment.dataClassification,
    }

    return AssetDetailResponse(
        asset=canonical_asset,
        moscaBreakdown=mosca_breakdown,
        recommendation=rec_dict,
        assessment=_assessment_from(enrichment),
        strategy=_strategy_from(enrichment),
        relationships=_relationships(db, db_asset, asset_dict),
    )


@router.patch("/{asset_id}/context", response_model=AssetDetailResponse)
def update_asset_context(
    asset_id: str,
    payload: AssetContextUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Let an operator confirm the use context and re-plan the migration."""
    db_asset = db.query(Asset).filter(
        (Asset.id == asset_id) | (Asset.bom_ref == asset_id)
    ).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")

    asset_dict = json.loads(db_asset.asset_json)
    enrichment = dict(asset_dict.get("ecdatEnrichment", {}))
    primitive_category = db_asset.primitive_category or enrichment.get("artifactType", "algorithm")
    before = {
        "usageContext": enrichment.get("usageContext"),
        "artifactType": enrichment.get("artifactType"),
        "complianceTarget": enrichment.get("complianceTarget"),
        "migrationAction": enrichment.get("migrationAction"),
        "migrationPhase": enrichment.get("migrationPhase"),
    }

    usage_context = payload.usageContext or enrichment.get("usageContext") or "unknown"
    artifact_type = payload.artifactType or enrichment.get("artifactType") or infer_artifact_type(
        primitive_category, usage_context
    )
    compliance_target = payload.complianceTarget or enrichment.get("complianceTarget", "NIST-general")
    evidence = dict(enrichment.get("evidence") or {})
    if payload.protocol:
        evidence["protocol"] = payload.protocol

    readiness = assess_readiness(
        artifact_type=artifact_type,
        usage_context=usage_context,
        library=db_asset.library,
        certificate_facts=enrichment.get("certificateFacts"),
        protocol=evidence.get("protocol"),
    )
    strategy = build_migration_strategy(
        name=db_asset.name,
        primitive_category=primitive_category,
        usage_context=usage_context,
        artifact_type=artifact_type,
        classical_status=enrichment.get("classicalStatus", "unknown"),
        quantum_status=enrichment.get("quantumStatus", "unknown"),
        compliance_target=compliance_target,
        mode=evidence.get("mode"),
        certificate_facts=enrichment.get("certificateFacts"),
        blockers=readiness["blockers"],
        mosca_tier=db_asset.risk_tier,
    )

    enrichment.update({
        "usageContext": usage_context,
        "contextConfidence": 1.0,
        "artifactType": artifact_type,
        "complianceTarget": compliance_target,
        "migrationAction": strategy["action"],
        "migrationPhase": strategy["phase"],
        "readinessScore": readiness["score"],
        "readinessTier": readiness["tier"],
        "readinessComponents": readiness["components"],
        "blockers": strategy["blockers"],
        "assumptions": strategy["assumptions"],
        "candidates": strategy["candidates"],
        "playbook": strategy["playbook"],
        "strategyRationale": strategy["rationale"],
        "evidence": evidence,
    })
    asset_dict["ecdatEnrichment"] = enrichment
    db_asset.asset_json = json.dumps(asset_dict)
    db_asset.usage_context = usage_context
    db_asset.artifact_type = artifact_type
    db_asset.migration_action = strategy["action"]
    db_asset.migration_phase = strategy["phase"]
    db_asset.readiness_score = readiness["score"]
    db_asset.readiness_tier = readiness["tier"]

    rec = db.query(Recommendation).filter(Recommendation.asset_id == db_asset.id).first()
    if rec:
        rec.action = strategy["action"]
        rec.phase = strategy["phase"]
        rec.candidates_json = json.dumps(strategy["candidates"])
        rec.playbook_json = json.dumps(strategy["playbook"])
        rec.blockers_json = json.dumps(strategy["blockers"])
        rec.assumptions_json = json.dumps(strategy["assumptions"])

    after = {
        "usageContext": usage_context,
        "artifactType": artifact_type,
        "complianceTarget": compliance_target,
        "migrationAction": strategy["action"],
        "migrationPhase": strategy["phase"],
    }
    db.add(AuditEvent(
        id=uuid.uuid4().hex,
        scan_id=db_asset.scan_id,
        asset_id=db_asset.id,
        asset_ref=db_asset.bom_ref,
        actor=payload.operator or request.headers.get("X-Operator"),
        action="asset-context-override",
        request_id=getattr(request.state, "request_id", None),
        before_json=json.dumps(before),
        after_json=json.dumps(after),
    ))
    db.commit()

    return get_asset_detail(asset_id, db)
