"""M5/M6 migration assessment engines — registry, context, HNDL, readiness, strategy."""
from backend.engine import standards
from backend.engine.context import build_context, infer_usage_context
from backend.engine.hndl import assess_hndl
from backend.engine.normalizer import normalize_findings
from backend.engine.playbook import build_playbook
from backend.engine.readiness import assess_readiness
from backend.engine.strategy import build_migration_strategy
from backend.scanners.infra.certs import scan_certificates
from backend.scanners.infra.configs import scan_configs
from backend.scanners.runner import get_contract_seed_findings

ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]


def test_registry_classifies_primitive_axes():
    sha1 = standards.classify("SHA1", "hash")
    assert sha1["classicalStatus"] == "broken"
    assert sha1["quantumStatus"] == "weakened"

    aes = standards.classify("AES-256", "symmetric", key_size=256)
    assert aes["classicalStatus"] == "strong"
    assert aes["quantumStatus"] == "resistant"

    aes128 = standards.classify("AES-128", "symmetric", key_size=128)
    assert aes128["quantumStatus"] == "weakened"

    ecb = standards.classify("AES", "symmetric", key_size=256, mode="ECB")
    assert ecb["classicalStatus"] == "deprecated"
    assert ecb["defaultAction"] == "reconfigure"

    unknown = standards.classify("MysteryCipher", "algorithm")
    assert unknown["classicalStatus"] == "unknown"
    assert unknown["defaultAction"] == "manual-review"


def test_cnsa_ranking_prefers_final_maximum_parameter_sets():
    candidates = standards.candidates_for_path("key-establishment", "CNSA2.0")
    preferred = [candidate["id"] for candidate in candidates if candidate["fit"] == "preferred"]
    assert preferred == ["ml-kem-1024"]


def test_context_distinguishes_password_and_transport():
    assert infer_usage_context("app/auth/passwords.py", "bcrypt.hashpw", "hash", "bcrypt")[0] == "password-storage"
    assert infer_usage_context("infra/nginx.conf", "ssl_protocols", "protocol", "TLS 1.2")[0] == "transport"
    context = build_context("src/signing/cert.pem", "BEGIN CERTIFICATE", "cert", "RSA-2048")
    assert context["artifactType"] == "certificate"
    assert context["signatureRelevant"] is True


def test_hndl_is_confidentiality_only_and_tiered():
    signature = assess_hndl(
        quantum_status="vulnerable", usage_context="signing", exposure="external-facing",
        shelf_life_years=10, z_years=8,
    )
    assert signature["applicable"] is False
    assert signature["tier"] == "NotApplicable"

    exposed = assess_hndl(
        quantum_status="vulnerable", usage_context="encryption", exposure="external-facing",
        shelf_life_years=15, z_years=8,
    )
    assert exposed["tier"] == "Critical"

    unknown = assess_hndl(
        quantum_status="vulnerable", usage_context="encryption", exposure="internal-only",
        shelf_life_years=None, z_years=8,
    )
    assert unknown["tier"] == "Unknown"


def test_readiness_reports_blockers_and_tier():
    result = assess_readiness(
        artifact_type="algorithm", usage_context="transport", library=None, protocol="TLS 1.0"
    )
    assert result["tier"] == "Blocked"
    assert any("Protocol upgrade" in blocker for blocker in result["blockers"])
    assert result["components"]["protocol_support"]["score"] == 0

    ready = assess_readiness(
        artifact_type="algorithm", usage_context="encryption", library="cryptography",
        provider_facts={"pqcSupport": True}, test_evidence=True,
    )
    assert ready["tier"] == "Ready"


def test_playbook_steps_have_owner_evidence_and_rollback():
    steps = build_playbook("key-establishment", "X25519MLKEM768", ["Library support unverified"])
    assert len(steps) >= 4
    assert all(step["ownerRole"] and step["evidence"] and step["rollback"] for step in steps)
    assert steps[0]["blockers"] == ["Library support unverified"]
    assert any(step["phase"] == "transition" for step in steps)


def test_strategy_password_storage_uses_kdf_not_digest():
    strategy = build_migration_strategy(
        name="MD5", primitive_category="hash", usage_context="password-storage",
        artifact_type="algorithm", classical_status="broken", quantum_status="vulnerable",
    )
    assert strategy["action"] == "replace"
    assert strategy["phase"] == "immediate"
    assert strategy["templateId"] == "password-storage"
    assert strategy["playbook"][0]["action"].startswith("Inventory every place")


def test_strategy_hybridizes_key_exchange_and_reissues_certificates():
    kem = build_migration_strategy(
        name="RSA-2048", primitive_category="asymmetric_kem", usage_context="key-establishment",
        artifact_type="algorithm", classical_status="acceptable", quantum_status="vulnerable",
    )
    assert kem["action"] == "hybridize"
    assert kem["selectedCandidate"] == "X25519MLKEM768"

    cert = build_migration_strategy(
        name="RSA-2048", primitive_category="cert", usage_context="certificate",
        artifact_type="certificate", classical_status="acceptable", quantum_status="vulnerable",
        certificate_facts={"notAfter": "2026-12-20", "daysToExpiry": 30},
    )
    assert cert["action"] == "reissue-certificate"
    assert cert["phase"] == "immediate"
    assert any("renewal window ending 2026-12-20" in step["action"] for step in cert["playbook"])


def test_normalizer_populates_assessment_and_strategy():
    assets = normalize_findings(get_contract_seed_findings("assessment"), threat_timeline_z=8.0)
    sha1 = next(asset for asset in assets if asset.name == "SHA-1")
    enrichment = sha1.ecdatEnrichment
    assert enrichment.classicalStatus == "broken"
    assert enrichment.migrationAction == "deprecate"
    assert enrichment.migrationPhase == "immediate"
    assert enrichment.playbook
    assert enrichment.evidence["detectionTier"]

    rsa = next(asset for asset in assets if asset.name.startswith("RSA"))
    assert rsa.ecdatEnrichment.candidates
    assert rsa.ecdatEnrichment.readinessTier in {"Ready", "Partial", "Blocked", "Unknown"}


def test_ecb_usage_is_reconfigured_to_an_aead():
    """ECB is a mode fault: the cipher stays, the construction changes."""
    from backend.engine.recommend import generate_recommendation
    from backend.engine.strategy import build_migration_strategy

    strategy = build_migration_strategy(
        name="AES-128",
        primitive_category="symmetric-cipher",
        usage_context="encryption",
        artifact_type="algorithm",
        classical_status="deprecated",
        quantum_status="weakened",
        mode="ECB",
    )
    assert strategy["action"] == "reconfigure"
    assert strategy["phase"] == "immediate"
    assert strategy["selectedCandidate"] == "AES-256-GCM"
    assert strategy["playbook"]

    headline = generate_recommendation("AES-128", "symmetric", mode="ECB")
    assert headline["recommendedReplacement"] == "AES-256-GCM or ChaCha20-Poly1305"
    assert headline["mode"] == "AEAD reconfiguration"


def test_certificate_findings_carry_x509_facts():
    findings = scan_certificates(ROOT / "seed_corpus" / "certs", "evidence")
    assert findings
    for finding in findings:
        facts = finding.certificateFacts
        assert facts and facts["notAfter"] and facts["issuer"]
        assert isinstance(facts["daysToExpiry"], int)


def test_config_certificate_directive_links_assets(tmp_path):
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "ssl_protocols TLSv1 TLSv1.2;\nssl_certificate certs/small_rsa1024.pem;\n",
        encoding="utf-8",
    )
    config_findings = scan_configs(conf, "evidence")
    protocol = next(f for f in config_findings if f.detectedPrimitive == "TLSv1")
    assert protocol.protocol == "TLSv1"
    assert protocol.referencedPaths == ["certs/small_rsa1024.pem"]

    assets = normalize_findings(
        [*scan_certificates(ROOT / "seed_corpus" / "certs", "evidence"), *config_findings]
    )
    config_asset = next(a for a in assets if a.name == "TLSv1")
    linked = [
        a for a in assets
        if a.bom_ref in config_asset.ecdatEnrichment.relatedAssetRefs
    ]
    assert linked and any(
        a.occurrences[0].location.replace("\\", "/").endswith("small_rsa1024.pem")
        for a in linked
    )
    cert_asset = linked[0]
    assert config_asset.bom_ref in cert_asset.ecdatEnrichment.relatedAssetRefs
    assert cert_asset.ecdatEnrichment.certificateFacts["notAfter"]

