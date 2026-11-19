"""Process-local metrics registry rendered in Prometheus text format.

Counters live in memory and gauges are computed at scrape time. Metrics are
process-local, which matches the single-worker deployment model; a
multi-worker deployment would need a shared store.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Dict, Tuple

_STARTED_AT = time.time()
_lock = threading.Lock()
_request_counts: Dict[Tuple[str, str, str], int] = {}
_request_duration_sum: Dict[Tuple[str, str, str], float] = {}
_scan_outcomes: Dict[str, int] = {}


def record_request(route: str, method: str, status: int, duration_seconds: float) -> None:
    key = (method, route, str(status))
    with _lock:
        _request_counts[key] = _request_counts.get(key, 0) + 1
        _request_duration_sum[key] = _request_duration_sum.get(key, 0.0) + duration_seconds


def record_scan_outcome(outcome: str) -> None:
    with _lock:
        _scan_outcomes[outcome] = _scan_outcomes.get(outcome, 0) + 1


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labelled(name: str, labels: Dict[str, str]) -> str:
    rendered = ",".join(f'{key}="{_escape_label(value)}"' for key, value in labels.items())
    return f"{name}{{{rendered}}}" if rendered else name


def _scan_gauges() -> Dict[str, str]:
    """Scans-by-status and total asset count from the database."""
    from sqlalchemy import func

    from backend.database import SessionLocal
    from backend.models.db_models import Asset, Scan

    with SessionLocal() as db:
        status_counts = dict(
            db.query(Scan.status, func.count()).group_by(Scan.status).all()
        )
        asset_total = db.query(func.count(Asset.id)).scalar() or 0

    gauges: Dict[str, str] = {}
    for status, count in status_counts.items():
        gauges[_labelled("ecdat_scans_total", {"status": status or "unknown"})] = str(count)
    gauges["ecdat_assets_total"] = str(asset_total)
    return gauges


def render_metrics(version: str | None = None) -> str:
    with _lock:
        request_counts = dict(_request_counts)
        duration_sums = dict(_request_duration_sum)
        outcomes = dict(_scan_outcomes)

    out: list[str] = []

    out.append("# HELP ecdat_requests_total Total HTTP requests processed.")
    out.append("# TYPE ecdat_requests_total counter")
    for (method, route, status), count in sorted(request_counts.items()):
        out.append(
            f'{_labelled("ecdat_requests_total", {"method": method, "route": route, "status": status})} {count}'
        )

    out.append("# HELP ecdat_request_duration_seconds_sum Cumulative request duration by route.")
    out.append("# TYPE ecdat_request_duration_seconds_sum counter")
    for (method, route, status), total in sorted(duration_sums.items()):
        out.append(
            f'{_labelled("ecdat_request_duration_seconds_sum", {"method": method, "route": route, "status": status})} {total:.6f}'
        )

    out.append("# HELP ecdat_scan_outcomes_total Scan pipeline outcomes recorded since start.")
    out.append("# TYPE ecdat_scan_outcomes_total counter")
    for outcome, count in sorted(outcomes.items()):
        out.append(f'{_labelled("ecdat_scan_outcomes_total", {"outcome": outcome})} {count}')

    out.append("# HELP ecdat_scans_total Scans currently stored by status.")
    out.append("# TYPE ecdat_scans_total gauge")
    out.append("# HELP ecdat_assets_total Assets currently stored.")
    out.append("# TYPE ecdat_assets_total gauge")
    try:
        out.extend(f"{key} {value}" for key, value in _scan_gauges().items())
    except Exception:
        # A database hiccup must not fail the scrape; the gauges are absent.
        pass

    out.append("# HELP ecdat_process_uptime_seconds Seconds since the metrics registry started.")
    out.append("# TYPE ecdat_process_uptime_seconds gauge")
    out.append(f"ecdat_process_uptime_seconds {time.time() - _STARTED_AT:.3f}")

    out.append("# HELP ecdat_build_info Build metadata, always 1.")
    out.append("# TYPE ecdat_build_info gauge")
    out.append(
        _labelled(
            "ecdat_build_info",
            {
                "version": version or os.getenv("ECDAT_VERSION", "unknown"),
                "commit": os.getenv("ECDAT_BUILD_COMMIT", "unknown"),
                "builtAt": os.getenv("ECDAT_BUILD_DATE", "unknown"),
            },
        )
        + " 1"
    )

    return "\n".join(out) + "\n"
