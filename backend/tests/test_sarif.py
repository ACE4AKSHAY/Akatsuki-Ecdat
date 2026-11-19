"""SARIF export: results, levels, rules and code-scanning compatibility shape."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.database import SessionLocal, init_db
from backend.engine.orchestrator import run_scan_pipeline_sync
from backend.engine.reporting.sarif_report import build_sarif
from backend.main import app
from backend.version import VERSION


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def completed_scan(client):
    response = client.post("/scans", json={"target": "demo/workspace"})
    assert response.status_code == 202
    scan_id = response.json()["scanId"]
    run_scan_pipeline_sync(scan_id=scan_id, source_type="path", target="demo/workspace")
    return scan_id


def test_sarif_endpoint_returns_valid_document(client, completed_scan):
    response = client.get(f"/reports/{completed_scan}", params={"format": "sarif"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/sarif+json")

    document = json.loads(response.content)
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "ECDAT"
    assert run["tool"]["driver"]["version"] == VERSION
    assert run["tool"]["driver"]["rules"]

    assets = client.get("/assets", params={"scanId": completed_scan}).json()["items"]
    assert len(run["results"]) == len(assets)


def test_sarif_levels_follow_risk_tiers(client, completed_scan):
    document = json.loads(client.get(f"/reports/{completed_scan}", params={"format": "sarif"}).content)
    results = document["runs"][0]["results"]

    levels = {result["level"] for result in results}
    assert levels <= {"error", "warning", "note", "none"}
    critical = [result for result in results if result["properties"]["riskTier"] == "Critical"]
    assert critical, "demo fixture must contain critical assets"
    assert all(result["level"] == "error" for result in critical)


def test_sarif_results_carry_locations_and_plan(client, completed_scan):
    document = json.loads(client.get(f"/reports/{completed_scan}", params={"format": "sarif"}).content)
    located = [result for result in document["runs"][0]["results"] if "locations" in result]
    assert located
    first = located[0]
    assert first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    message = first["message"]["text"]
    assert "Plan:" in message


def test_sarif_rules_are_declared_and_deduplicated(client, completed_scan):
    document = json.loads(client.get(f"/reports/{completed_scan}", params={"format": "sarif"}).content)
    driver = document["runs"][0]["tool"]["driver"]
    rule_ids = [rule["id"] for rule in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    used_rule_ids = {result["ruleId"] for result in document["runs"][0]["results"]}
    assert used_rule_ids <= set(rule_ids)


def test_build_sarif_handles_empty_inventory():
    document = build_sarif(scan_id="empty", version=VERSION, assets_data=[])
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []
