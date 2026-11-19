"""CBOM interoperability: the emitted document must validate against the
official CycloneDX 1.6 JSON schema, not just our own model."""
from __future__ import annotations

import json

import pytest

from backend.engine.cbom_validator import validate_document
from backend.engine.normalizer import build_cyclonedx_document, normalize_findings
from backend.engine.orchestrator import run_scan_pipeline_sync
from backend.scanners.runner import get_contract_seed_findings


def test_contract_seed_cbom_validates_against_official_schema():
    findings = get_contract_seed_findings("cbom-interop-test")
    assets = normalize_findings(findings, threat_timeline_z=8.0)
    assert assets

    document = build_cyclonedx_document("cbom-interop-test", assets)
    problems = validate_document(document.model_dump(by_alias=True))
    assert problems == []


def test_enrichment_is_carried_in_namespaced_properties():
    findings = get_contract_seed_findings("cbom-interop-test")
    assets = normalize_findings(findings, threat_timeline_z=8.0)
    document = build_cyclonedx_document("cbom-interop-test", assets)

    component = document.components[0]
    names = {prop["name"] for prop in component["properties"]}
    assert "ecdat:occurrence" in names
    for expected in (
        "ecdat:moscaRiskTier",
        "ecdat:moscaX",
        "ecdat:moscaY",
        "ecdat:moscaZ",
        "ecdat:moscaR",
        "ecdat:recommendedReplacement",
        "ecdat:referenceStandard",
    ):
        assert expected in names, f"{expected} missing from properties"


def test_primitives_and_functions_use_official_enums():
    findings = get_contract_seed_findings("cbom-interop-test")
    assets = normalize_findings(findings, threat_timeline_z=8.0)
    document = build_cyclonedx_document("cbom-interop-test", assets)

    valid_primitives = {
        "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
        "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
    }
    valid_functions = {
        "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
        "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
    }
    for component in document.components:
        algorithm = component.get("cryptoProperties", {}).get("algorithmProperties")
        if not algorithm:
            continue
        assert algorithm["primitive"] in valid_primitives
        for function in algorithm.get("cryptoFunctions", []):
            assert function in valid_functions


@pytest.fixture(scope="module")
def pipeline_cbom(tmp_path_factory):
    import os

    state_dir = tmp_path_factory.mktemp("cbom-interop-state")
    os.environ.setdefault("ECDAT_STATE_DIR", str(state_dir))
    from backend.database import SessionLocal, init_db
    from backend.models.db_models import Scan

    init_db()
    scan_id = "cbom-interop-pipeline"
    with SessionLocal() as db:
        db.add(Scan(id=scan_id, source_type="path", target="demo/workspace", status="queued"))
        db.commit()
    run_scan_pipeline_sync(scan_id, "path", "demo/workspace")
    with SessionLocal() as db:
        raw = db.get(Scan, scan_id).raw_cbom_json
    return json.loads(raw)


def test_full_pipeline_cbom_validates_against_official_schema(pipeline_cbom):
    assert pipeline_cbom["components"]
    assert validate_document(pipeline_cbom) == []
