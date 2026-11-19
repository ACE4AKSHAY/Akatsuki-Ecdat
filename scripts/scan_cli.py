"""Headless ECDAT scan for CI pipelines.

Runs the full discovery pipeline synchronously against a target and writes
CBOM and SARIF artifacts without touching the operator's scan history: the
run uses a dedicated throwaway database by default.

    python scripts/scan_cli.py --target demo/workspace --output work/ci-results
    python scripts/scan_cli.py --target . --fail-on-critical

Exit codes: 0 = completed, 1 = scan failed or --fail-on-critical tripped.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Local path to scan (relative to the repository root or absolute)")
    parser.add_argument("--output", type=Path, default=Path("work/ecdat-ci-results"), help="Directory for cbom.json and results.sarif")
    parser.add_argument("--source-type", default="path", choices=("path", "git"), help="Target type")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit 1 when the scan finds Critical-tier assets")
    parser.add_argument("--compliance-target", default="NIST-general", choices=("NIST-general", "CNSA2.0"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # The environment must be decided before any backend import reads it.
    workdir = Path(tempfile.mkdtemp(prefix="ecdat-cli-"))
    os.environ.setdefault("ECDAT_STATE_DIR", str(workdir / "state"))
    os.environ["DATABASE_URL"] = f"sqlite:///{(workdir / 'cli.db').as_posix()}"
    os.environ["ECDAT_SCAN_RETENTION_DAYS"] = "0"

    sys.path.insert(0, str(ROOT))

    target = Path(args.target)
    if not target.is_absolute():
        target = ROOT / target
    target = target.resolve()
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 1

    from backend.database import SessionLocal, init_db
    from backend.engine.orchestrator import run_scan_pipeline_sync
    from backend.engine.reporting.sarif_report import build_sarif
    from backend.models.db_models import Asset, Recommendation, Scan
    from backend.version import VERSION

    init_db()
    scan_id = f"cli-{os.urandom(4).hex()}"

    with SessionLocal() as db:
        db.add(Scan(id=scan_id, source_type=args.source_type, target=str(target), status="queued"))
        db.commit()

    run_scan_pipeline_sync(
        scan_id=scan_id,
        source_type=args.source_type,
        target=str(target),
        compliance_target=args.compliance_target,
    )

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "completed":
            error = scan.error if scan else "scan record missing"
            print(f"error: scan did not complete: {error}", file=sys.stderr)
            return 1

        assets = []
        for a in db.query(Asset).filter(Asset.scan_id == scan_id).all():
            rec = db.query(Recommendation).filter(Recommendation.asset_id == a.id).first()
            try:
                payload = json.loads(a.asset_json)
            except (TypeError, ValueError):
                payload = {}
            enrichment = payload.get("ecdatEnrichment", {})
            crypto = payload.get("cryptoProperties", {})
            assets.append({
                "id": a.id,
                "bom_ref": a.bom_ref,
                "name": a.name,
                "file_path": a.file_path,
                "line_number": a.line_number,
                "usage_context": a.usage_context or enrichment.get("usageContext", ""),
                "artifact_type": a.artifact_type or enrichment.get("artifactType", ""),
                "classical_status": a.classical_status or enrichment.get("classicalStatus", ""),
                "quantum_status": a.quantum_status or enrichment.get("quantumStatus", ""),
                "standards_maturity": a.standards_maturity or enrichment.get("standardsMaturity", ""),
                "risk_tier": a.risk_tier,
                "risk_score": a.risk_score,
                "urgency_ratio_r": a.urgency_ratio_r,
                "migration_action": a.migration_action or enrichment.get("migrationAction", ""),
                "migration_phase": a.migration_phase or enrichment.get("migrationPhase", ""),
                "readiness_tier": a.readiness_tier or enrichment.get("readinessTier", ""),
                "hndl_tier": a.hndl_tier or enrichment.get("hndlTier", ""),
                "recommended_replacement": rec.recommended_algorithm if rec else "",
            })

    output: Path = args.output if args.output.is_absolute() else ROOT / args.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "cbom.json").write_text(scan.raw_cbom_json or "{}", encoding="utf-8")
    (output / "results.sarif").write_text(
        json.dumps(build_sarif(scan_id=scan_id, version=VERSION, assets_data=assets), indent=2),
        encoding="utf-8",
    )

    tiers = Counter(a["risk_tier"] for a in assets)
    print(f"ECDAT {VERSION} scan of {target}")
    print(f"assets: {len(assets)}  tiers: {dict(tiers)}")
    print(f"artifacts: {output / 'cbom.json'}, {output / 'results.sarif'}")

    if args.fail_on_critical and tiers.get("Critical", 0) > 0:
        print(f"fail-on-critical: {tiers['Critical']} Critical asset(s) found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
