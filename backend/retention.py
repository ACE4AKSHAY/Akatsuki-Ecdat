"""Opt-in retention for old scan history.

Disabled by default. Setting `ECDAT_SCAN_RETENTION_DAYS` to a positive number
deletes *completed* scans older than that many days, one audit event each, so
a long-running deployment does not accumulate history forever. Queued,
running and failed scans are never touched.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from backend.models.db_models import AuditEvent, Scan, ScanJob

log = logging.getLogger(__name__)

RETENTION_SWEEP_SECONDS = 3600


def get_retention_days() -> int:
    raw = os.getenv("ECDAT_SCAN_RETENTION_DAYS", "0").strip()
    if not raw.isascii() or not raw.isdecimal() or int(raw) < 0:
        raise ValueError(
            f"ECDAT_SCAN_RETENTION_DAYS must be a non-negative integer; received {raw!r}."
        )
    return int(raw)


def prune_expired_scans(db: Session, now: datetime | None = None) -> int:
    """Delete completed scans past the retention window. Returns the count."""
    days = get_retention_days()
    if days <= 0:
        return 0
    cutoff = (now or datetime.utcnow()) - timedelta(days=days)
    expired = (
        db.query(Scan)
        .filter(Scan.status == "completed", Scan.completed_at.isnot(None), Scan.completed_at < cutoff)
        .all()
    )
    for scan in expired:
        db.query(ScanJob).filter(ScanJob.scan_id == scan.id).delete(synchronize_session=False)
        db.add(AuditEvent(
            id=uuid.uuid4().hex,
            scan_id=scan.id,
            actor="system",
            action="scan-retention-deleted",
            before_json=json.dumps({
                "target": scan.target,
                "assetCount": scan.asset_count,
                "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
                "retentionDays": days,
            }),
        ))
        db.delete(scan)
    db.commit()
    if expired:
        log.info("retention pruned %d scan(s) older than %d day(s)", len(expired), days)
    return len(expired)
