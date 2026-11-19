"""API surface for assessment, context overrides, roadmap and standards."""
import pytest
from fastapi.testclient import TestClient

from backend.database import init_db
from backend.main import app
from backend.engine.orchestrator import run_scan_pipeline_sync


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture(scope="module")
def completed_scan():
    client = TestClient(app)
    response = client.post("/scans", json={"target": "seed_corpus"})
    assert response.status_code == 202
    scan_id = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan_id, source_type="path", target="seed_corpus")
    yield client, scan_id


def test_assets_expose_assessment_and_strategy(completed_scan):
    client, scan_id = completed_scan
    payload = client.get("/assets", params={"scanId": scan_id}).json()
    assert payload["items"]
    enrichment = payload["items"][0]["ecdatEnrichment"]
    assert enrichment["migrationAction"]
    assert enrichment["migrationPhase"] in {"immediate", "transition", "target", "monitor"}
    assert enrichment["playbook"]
    assert "readinessTier" in enrichment


def test_asset_detail_and_context_override(completed_scan):
    client, scan_id = completed_scan
    item = client.get("/assets", params={"scanId": scan_id}).json()["items"][0]

    detail = client.get(f"/assets/{item['bom-ref']}").json()
    assert detail["assessment"]["classicalStatus"]
    assert detail["strategy"]["action"]
    assert isinstance(detail["relationships"], list)

    patched = client.patch(
        f"/assets/{item['bom-ref']}/context",
        json={"usageContext": "password-storage", "artifactType": "algorithm"},
    )
    assert patched.status_code == 200
    body = patched.json()
    assert body["assessment"]["usageContext"] == "password-storage"
    assert body["strategy"]["action"] == "replace"
    assert any(candidate["id"] == "argon2id" for candidate in body["strategy"]["candidates"])


def test_roadmap_groups_every_asset(completed_scan):
    client, scan_id = completed_scan
    roadmap = client.get(f"/roadmap/{scan_id}").json()
    assert [phase["id"] for phase in roadmap["phases"]] == ["immediate", "transition", "target", "monitor"]
    assert sum(phase["count"] for phase in roadmap["phases"]) == roadmap["total"]
    assert roadmap["total"] > 0
    assert client.get("/roadmap/missing-scan").status_code == 404


def test_standards_registry_and_cnsa_filter():
    client = TestClient(app)
    registry = client.get("/standards").json()
    assert registry["registryVersion"]
    assert registry["entries"]
    assert registry["migrationPaths"]

    cnsa = client.get(
        "/standards", params={"path": "key-establishment", "complianceTarget": "CNSA2.0"}
    ).json()
    assert cnsa["candidates"][0]["id"] == "ml-kem-1024"

    entry = client.get("/standards/ml-kem-768").json()
    assert entry["standard"] == "FIPS 203"
    assert client.get("/standards/not-real").status_code == 404


def test_asset_filters_use_migration_fields(completed_scan):
    client, scan_id = completed_scan
    filtered = client.get(
        "/assets", params={"scanId": scan_id, "migrationAction": "deprecate"}
    ).json()
    assert filtered["items"]
    assert all(item["ecdatEnrichment"]["migrationAction"] == "deprecate" for item in filtered["items"])


def test_certificate_assets_expose_parsed_facts(completed_scan):
    client, scan_id = completed_scan
    items = client.get(
        "/assets", params={"scanId": scan_id, "artifactType": "certificate"}
    ).json()["items"]
    assert items
    detail = client.get(f"/assets/{items[0]['bom-ref']}").json()
    facts = detail["asset"]["ecdatEnrichment"]["certificateFacts"]
    assert facts["issuer"]
    assert facts["notAfter"]
    assert facts["keyAlgorithm"]

