"""
Scan lifecycle API routes: POST /scans, GET /scans/{id}, GET /scans
"""
import uuid
from backend.ingestion import validate_input, state_dir
from backend.input_limits import MIB, get_input_limits
from pathlib import Path
import json
import shutil
from fastapi import UploadFile, File, Form, Query
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.db_models import Scan, ScanJob
from backend.models.schemas import ScanCreate, ScanResponse

router = APIRouter(prefix="/scans", tags=["Scans"])


def remove_history(scans: list[Scan], db: Session):
    if any(scan.status in ('queued', 'running') for scan in scans):
        raise HTTPException(409, 'Wait for queued or running scans to finish before deleting their history.')
    for scan in scans:
        db.query(ScanJob).filter(ScanJob.scan_id == scan.id).delete(synchronize_session=False)
        # ORM cascades remove the assets and their recommendations together.
        db.delete(scan)
    db.commit()
    return {'deletedCount': len(scans)}


@router.delete('')
def delete_all_scans(db: Session = Depends(get_db)):
    """Remove all saved history; reject the whole action while any scan is active."""
    return remove_history(db.query(Scan).all(), db)


@router.delete('/{scan_id}')
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Remove a finished scan and its saved results. Input files are retained."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return remove_history([scan], db)


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(
    request: ScanCreate,
    db: Session = Depends(get_db),
):
    """
    Kicks off an asynchronous cryptographic discovery scan.
    Returns immediately with a scanId and 'queued' status.
    """
    try:
        resolved_target = validate_input(request.sourceType, request.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}"

    new_scan = Scan(
        id=scan_id,
        source_type=request.sourceType,
        target=str(resolved_target),
        status="queued",
        progress=0.0,
        asset_count=0,
        created_at=datetime.utcnow(),
    )
    db.add(new_scan)
    db.flush()

    db.add(ScanJob(scan_id=scan_id, options_json=json.dumps({
        "compliance_target": request.complianceTarget or "NIST-general",
        "threat_timeline_override": request.threatTimelineOverride,
    })))
    db.commit()

    return ScanResponse(
        scanId=new_scan.id,
        sourceType=new_scan.source_type,
        target=new_scan.target,
        status=new_scan.status,
        progress=new_scan.progress,
        assetCount=new_scan.asset_count,
        createdAt=new_scan.created_at.isoformat(),
        completedAt=new_scan.completed_at.isoformat() if new_scan.completed_at else None,
        error=new_scan.error,
    )


@router.post("/upload", response_model=ScanResponse, status_code=202)
async def upload_scan(file: UploadFile = File(...), sourceType: str = Form("upload"), db: Session = Depends(get_db)):
    """Persist a single source file, ZIP workspace, or image SBOM before queueing."""
    if sourceType not in ("upload", "image"):
        raise HTTPException(422, "Upload source must be upload or image.")
    limits = get_input_limits()
    upload_mib = min(limits.upload_mib, limits.inventory_mib) if sourceType == 'image' else limits.upload_mib
    name = Path(file.filename or "upload.txt").name
    folder = state_dir() / "uploads" / uuid.uuid4().hex
    folder.mkdir(parents=True)
    destination = folder / name
    size = 0
    try:
        with destination.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > upload_mib * MIB:
                    setting = 'ECDAT_MAX_UPLOAD_MIB / ECDAT_MAX_INVENTORY_MIB' if sourceType == 'image' else 'ECDAT_MAX_UPLOAD_MIB'
                    raise HTTPException(413, f'Upload exceeds the {upload_mib:,} MiB limit. Adjust {setting} on the server if needed.')
                out.write(chunk)
        if size == 0:
            raise HTTPException(422, "Upload is empty.")
        return create_scan(ScanCreate(target=str(destination), sourceType=sourceType), db)
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    finally:
        await file.close()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Polls the status of an ongoing or completed scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    return ScanResponse(
        scanId=scan.id,
        sourceType=scan.source_type,
        target=scan.target,
        status=scan.status,
        progress=scan.progress,
        assetCount=scan.asset_count,
        createdAt=scan.created_at.isoformat(),
        completedAt=scan.completed_at.isoformat() if scan.completed_at else None,
        error=scan.error,
    )


@router.get("", response_model=List[ScanResponse])
def list_scans(limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    """Lists recent scans."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    return [
        ScanResponse(
            scanId=s.id,
            sourceType=s.source_type,
            target=s.target,
            status=s.status,
            progress=s.progress,
            assetCount=s.asset_count,
            createdAt=s.created_at.isoformat(),
            completedAt=s.completed_at.isoformat() if s.completed_at else None,
            error=s.error,
        )
        for s in scans
    ]
