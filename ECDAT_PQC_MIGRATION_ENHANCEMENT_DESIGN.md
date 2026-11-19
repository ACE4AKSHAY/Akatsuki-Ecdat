# ECDAT PQC Migration and Crypto Agility Enhancement

## Design and Technical Implementation Document

**Project:** Enterprise Cryptographic Discovery and Analysis Tool (ECDAT)  
**SIH problem statement:** SIH26164  
**Document status:** Implementation design for the existing working codebase  
**Target team:** Three developers, three modules each  
**Baseline:** Existing root `backend/` and `frontend/` implementation

## 1. Executive summary

ECDAT already discovers cryptographic evidence, normalizes it into a CycloneDX-aligned CBOM, scores urgency through Mosca's inequality, recommends replacements, and presents results in a React dashboard. This enhancement turns the current algorithm-centric recommendation into a migration-planning capability.

The intended outcome is not merely:

```text
RSA-2048 -> ML-KEM-768
```

It is:

```text
RSA-2048 in an internet-facing TLS service
  -> classically acceptable but quantum-vulnerable
  -> high Harvest Now Decrypt Later exposure
  -> hybrid TLS migration is recommended
  -> validate library, client, certificate, and gateway compatibility
  -> execute a staged rollout with a rollback path
```

The implementation preserves the current static, local-first, single-worker architecture. It adds a versioned standards registry, richer artefact and certificate evidence, a transparent migration-readiness assessment, a strategy engine, migration playbooks, and user interfaces that make recommendations actionable.

This directly supports the SIH26164 requirement to catalogue algorithms, keys, certificates, protocols, libraries, hardware modules, and cloud services; assess quantum risk; classify by lifetime and business criticality; and recommend PQC or hybrid alternatives using risk, latency, and cost considerations.

## 2. Scope and product decisions

### 2.1 In scope for this enhancement

- Preserve the current M1-M9 pipeline and active `backend/` and `frontend/` trees.
- Extend static discovery for crypto usage context, protocols, certificates, key stores, libraries, and cloud/KMS references where evidence is present in source or configuration files.
- Introduce a data-driven standards and recommendation registry rather than expanding hard-coded `if` statements.
- Classify each finding independently by classical status, quantum status, standard maturity, and recommended migration action.
- Add HNDL and crypto-agility/readiness assessments around the existing Mosca score.
- Produce a phased migration playbook for algorithm, protocol, certificate, key, library, and configuration findings.
- Add a certificate-focused view and a migration roadmap view to the existing dashboard.
- Export all new assessment fields and playbook steps in CSV, XLSX, PDF, and CBOM extension fields.

### 2.2 Explicit non-goals

- No automated production changes, certificate issuance, key rotation, or deployment execution.
- No claim that a static scan proves compliance or finds every cryptographic dependency.
- No live authenticated scans of cloud accounts, HSMs, or production networks in this increment.
- No automatic recommendation of draft or emerging PQC algorithms as a production default.
- No rework of the historical duplicate `ecdat/` package. All development is in the repository-root `backend/` and `frontend/` trees.

### 2.3 Design principles

1. Recommendations must be evidence-based and explainable.
2. An algorithm alone is not enough; its role and environment determine the migration strategy.
3. A missing fact must produce `Review required`, not an invented answer.
4. Standards must carry their maturity and review date.
5. Every generated playbook must include validation and rollback guidance.
6. Existing scans and exports must remain readable after schema changes.

## 3. Baseline implementation to extend

| Existing capability | Active implementation | Enhancement impact |
| --- | --- | --- |
| M1 source scanning | `backend/scanners/source/` | Add contextual detection for usage, protocol, keystore, and crypto-agility signals. |
| M2 manifests and binary evidence | `backend/scanners/binary_deps/` | Add provider capability and PQC-support metadata from a registry. |
| M3 infrastructure and certificates | `backend/scanners/infra/` | Parse richer X.509 facts and protocol/configuration context. |
| M4 normalization | `backend/engine/normalizer.py` | Produce enriched asset records and relationship records. |
| M5 risk | `backend/engine/risk.py` | Retain Mosca; add HNDL and migration-readiness components. |
| M6 recommendations | `backend/engine/recommend.py` | Replace hard-coded mapping with a data-driven strategy and playbook engine. |
| M7 API and persistence | `backend/api/`, `backend/models/`, `backend/engine/orchestrator.py` | Persist new assessment data and expose the new API contract. |
| M8 dashboard | `frontend/src/` | Add migration roadmap, certificate details, filters, and explanation panels. |
| M9 reports | `backend/engine/reporting/` | Add assessment and playbook columns/sections. |

## 4. Target architecture

```text
Input and bounded snapshot
        |
        +-- M1 source context scanner
        +-- M2 dependency and provider capability scanner
        +-- M3 infrastructure, protocol, certificate, and key-material scanner
        |
        v
M4 canonical CBOM plus ECDAT enrichment and relationships
        |
        +-- M5 risk and readiness assessment
        |       Mosca + classical status + quantum status + HNDL + readiness
        |
        +-- M6 migration strategy engine
        |       standards registry + candidates + chosen strategy + playbook
        |
        v
M7 persisted scan, asset, relationship, assessment, and recommendation data
        |
        +-- M8 inventory, certificate view, readiness dashboard, migration roadmap
        +-- M9 CBOM, PDF, CSV, and XLSX exports
```

The existing raw-finding contract remains the scanner boundary. New fields are optional so existing scanners continue to work while each owner incrementally adds richer evidence.

## 5. Cryptographic artefact model

### 5.1 Artefact types

ECDAT must recognize the following as separate asset types even when they are linked to one another.

| Artefact type | Examples | Migration value |
| --- | --- | --- |
| Algorithm | RSA-2048, AES-128, SHA-1, ML-KEM-768 | Identifies strength and replacement candidates. |
| Key and key material | PEM key, SSH key, JWK, PKCS#12, KMS key reference | Identifies rotation and storage implications. |
| Certificate and PKI | X.509 leaf, intermediate CA, trust store, CSR | Identifies expiry windows, chains, issuer, and client impact. |
| Protocol and cipher suite | TLS 1.2, SSH, IPsec, TLS_AES_256_GCM_SHA384 | Identifies where algorithm migration must occur. |
| Library/provider | OpenSSL, JCA/JCE, BoringSSL, PKCS#11 provider | Identifies implementation capability and upgrade blockers. |
| Hardware and service reference | HSM, TPM, AWS KMS, Azure Key Vault, GCP KMS | Identifies ownership and compatibility dependency. |
| Signing system | Firmware, code, package, container, document signing | Identifies integrity and long-lived verification requirements. |
| Data protection use | Database, backup, archive, disk, object storage | Identifies HNDL urgency. |

### 5.2 Required classification axes

Every canonical asset must expose these four independent outcomes:

| Axis | Allowed values | Meaning |
| --- | --- | --- |
| Classical status | `broken`, `deprecated`, `acceptable`, `strong`, `unknown` | Present-day cryptographic posture. |
| Quantum status | `vulnerable`, `weakened`, `resistant`, `not-applicable`, `unknown` | Expected impact of a CRQC. |
| Standards maturity | `final`, `standards-track`, `draft`, `selected`, `experimental`, `not-applicable` | Deployment confidence for a proposed target. |
| Migration action | `retain`, `monitor`, `deprecate`, `replace`, `hybridize`, `rotate`, `reissue-certificate`, `upgrade-library`, `reconfigure`, `manual-review` | What the operator should do next. |

`Review required` is a valid result. It must appear whenever usage semantics, deployment profile, key role, client population, or certificate authority support cannot be inferred safely.

## 6. Standards and policy registry

### 6.1 Registry design

Create `backend/knowledge/standards_registry.json`. This becomes the source of truth for recommendations and avoids placing policy inside application logic.

Each entry requires:

```json
{
  "id": "ml-kem-768",
  "displayName": "ML-KEM-768",
  "family": "kem",
  "standard": "FIPS 203",
  "status": "final",
  "reviewedOn": "2026-09-14",
  "useCases": ["key-establishment", "tls"],
  "securityProfile": "balanced",
  "classicalCompatibility": ["X25519", "P-256"],
  "transitionOptions": ["X25519MLKEM768"],
  "constraints": ["requires-protocol-and-library-support"],
  "notPrimaryFor": ["digital-signature"],
  "references": ["FIPS 203", "RFC 10024"]
}
```

### 6.2 Initial policy entries

| Finding or target | Policy | Default action |
| --- | --- | --- |
| MD5 | Broken. Differentiate password storage from integrity/hash usage. | Password storage: Argon2id, bcrypt, or scrypt. Other uses: a fit-for-purpose modern hash, usually SHA-256 or stronger. |
| SHA-1 | Deprecated/broken for collision-sensitive signatures. | Replace with SHA-256/384 or SHA-3 based on protocol and compatibility. |
| DES, 3DES, RC4 | Deprecated or broken. | Replace with AEAD such as AES-GCM or ChaCha20-Poly1305 where appropriate. |
| AES-128 | Acceptable classically but quantum-weakened. | Retain for short-lived low-risk use only; plan AES-256 for long-lived sensitive data. |
| AES-256, SHA-384, SHA-512, SHA-3 | Strong for their expected role. | Retain and monitor configuration. |
| RSA, DH, ECDH, X25519 for key establishment | Classically acceptable but quantum-vulnerable. | Prefer a hybrid strategy where protocol support exists. |
| RSA, ECDSA, EdDSA for signatures | Classically acceptable but quantum-vulnerable. | Plan ML-DSA or SLH-DSA based on role and operational constraints. |
| ML-KEM, ML-DSA, SLH-DSA | Final NIST standards. | Production-ready candidates when environment support is confirmed. |
| LMS/XMSS/HSS | Final stateful hash-based signature guidance. | Specialized signing option; require state-management capability. |
| HQC and FN-DSA | Not a default production recommendation until final applicable standards are published. | Track as a future/diversity option only. |

### 6.3 Standards labels in the user interface

Every candidate must show a label such as `Final standard`, `Standards track`, `Selected for standardization`, or `Review required`. Never present a draft or selected algorithm as interchangeable with FIPS 203, FIPS 204, or FIPS 205.

## 7. Data contract changes

### 7.1 Backward-compatible raw finding extension

Extend `RawFinding` in `backend/models/schemas.py` with optional fields:

```python
artifactType: Optional[str] = None
usageContext: Optional[str] = None
protocol: Optional[str] = None
cipherSuite: Optional[str] = None
serviceName: Optional[str] = None
environment: Optional[str] = None
relatedAssetHints: List[str] = Field(default_factory=list)
certificateFacts: Optional[Dict[str, Any]] = None
providerFacts: Optional[Dict[str, Any]] = None
```

Existing scanner outputs remain valid because every new field has a default.

### 7.2 ECDAT enrichment extension

Add these fields to `EcdatEnrichment`:

```python
classicalStatus: Literal["broken", "deprecated", "acceptable", "strong", "unknown"]
quantumStatus: Literal["vulnerable", "weakened", "resistant", "not-applicable", "unknown"]
standardsMaturity: Literal["final", "standards-track", "draft", "selected", "experimental", "not-applicable"]
hndlTier: Literal["Critical", "High", "Medium", "Low", "NotApplicable"]
hndlScore: Optional[float]
migrationReadinessScore: Optional[int]
migrationReadinessTier: Optional[Literal["Ready", "Partial", "Blocked", "Unknown"]]
migrationAction: str
migrationPhase: Literal["immediate", "transition", "target", "monitor"]
migrationBlockers: List[str]
migrationPlan: List[Dict[str, Any]]
candidateRecommendations: List[Dict[str, Any]]
relationships: List[Dict[str, Any]]
assumptions: List[str]
```

Use `Field(default_factory=list)` for each list. The normalizer must fill defaults for all existing scan results.

### 7.3 Candidate recommendation shape

```json
{
  "id": "hybrid-x25519-ml-kem-768",
  "label": "X25519MLKEM768",
  "action": "hybridize",
  "role": "TLS key establishment",
  "standard": "FIPS 203 and RFC 10024",
  "maturity": "final",
  "fit": "preferred",
  "latencyImpact": "moderate handshake-size increase",
  "costImpact": "library and compatibility testing required",
  "constraints": ["TLS 1.3", "client support", "library support"],
  "rationale": "Preserves a classical and a post-quantum component during transition."
}
```

### 7.4 Migration playbook step shape

```json
{
  "order": 1,
  "phase": "prepare",
  "action": "Upgrade the TLS library to a version supporting the selected hybrid group.",
  "ownerRole": "Platform engineer",
  "evidence": "Supported group appears in staging handshake test.",
  "rollback": "Keep the existing classical group enabled during the canary rollout.",
  "blocking": true
}
```

## 8. Three developer module allocation

The module division intentionally follows the original M1-M9 model. The teams can work in parallel after the contracts in Sections 6 and 7 are approved.

### Developer A: Discovery and evidence modules

#### M1: Source context and crypto-agility scanner

**Objective:** Extend source scanning from primitive detection to useful migration context.

**Modify:**

- `backend/scanners/source/signals.yaml`
- `backend/scanners/source/tier1.py`
- `backend/scanners/source/tier2.py`
- `backend/scanners/source/scanner.py`
- `backend/tests/test_source_tier1.py`
- `backend/tests/test_source_tier2.py`

**Add:**

- `backend/scanners/source/context.py`
- `backend/knowledge/source_context_rules.yaml`

**Responsibilities:**

1. Detect key-establishment, signing, hashing, encryption, password-storage, token-signing, and certificate-loading usage contexts.
2. Extract algorithm mode where safely visible, such as AES-GCM, AES-CBC, or AES-ECB.
3. Detect crypto-agility signals: algorithm literals spread through code, hard-coded provider selection, factory/configuration usage, wrapper functions, and environment-driven algorithm selection.
4. Detect references to PEM, JKS, PKCS#12, JWK, SSH, and common secret-manager/KMS identifiers without exposing secret values.
5. Emit contextual fields only when confidence is high; use `unknown` otherwise.

**Acceptance tests:**

- A JWT-signing fixture is classified as signature use, not generic RSA use.
- A password hash fixture is classified as password storage, preventing an incorrect SHA-256 migration recommendation.
- AES-GCM and AES-ECB fixtures preserve mode evidence.
- A hard-coded algorithm literal produces a crypto-agility signal.
- No key material value is written to findings, logs, reports, or test snapshots.

#### M2: Dependency provider and capability scanner

**Objective:** Determine whether a detected library/provider is likely to support a required migration path.

**Modify:**

- `backend/scanners/binary_deps/registry.json`
- `backend/scanners/binary_deps/registry.py`
- `backend/scanners/binary_deps/manifests.py`
- `backend/scanners/binary_deps/scanner.py`
- `backend/tests/test_manifests.py`
- `backend/tests/test_binary.py`

**Add:**

- `backend/knowledge/provider_capabilities.json`

**Responsibilities:**

1. Add capability metadata instead of assuming a library can implement PQC.
2. Record detected version, ecosystem, provider, and known algorithm support only where the manifest gives evidence.
3. Produce blockers such as `provider version unknown`, `PQC support unknown`, or `native/HSM provider must be verified`.
4. Identify crypto providers and PKCS#11 references as artefacts, not only as package names.

**Acceptance tests:**

- A manifest with an unsupported/unknown provider leads to `Partial` or `Unknown` readiness, not `Ready`.
- A non-crypto dependency still produces no crypto finding.
- Version parsing remains tolerant of normal Python, Maven, npm, and Go manifest formats.

#### M3: Certificate protocol and infrastructure scanner

**Objective:** Turn certificates and configuration findings into migration-ready PKI and protocol evidence.

**Modify:**

- `backend/scanners/infra/certs.py`
- `backend/scanners/infra/configs.py`
- `backend/scanners/infra/iac.py`
- `backend/scanners/infra/container.py`
- `backend/scanners/infra/scanner.py`
- `backend/tests/test_infra_certs.py`
- `backend/tests/test_infra_configs.py`

**Add:**

- `backend/scanners/infra/protocols.py`

**Certificate facts to capture:**

- Subject, issuer, serial number fingerprint, validity start/end, days to expiry.
- Public-key algorithm and size.
- Certificate signature algorithm.
- Self-signed/CA/leaf indication where available.
- Subject alternative names count only; never expose unnecessary personal data in a default report.
- Estimated renewal window and a relationship hint to configuration files that reference the certificate.

**Protocol and configuration facts to capture:**

- TLS protocol versions, cipher-suite strings, key-exchange groups where present, certificate file paths, trust-store paths, and KMS/HSM references.
- Weak protocol and cipher detection remains intact.

**Acceptance tests:**

- A leaf certificate produces a certificate asset and its algorithm/signature facts, not four unrelated opaque flags.
- A long-validity certificate receives an HNDL-relevant lifetime hint.
- An Nginx TLS configuration links a certificate path and protocol setting when both are visible.

### Developer B: Intelligence and decision modules

#### M4: Canonical artefact graph and normalization

**Objective:** Normalize enriched raw findings into one asset inventory while preserving relationships and evidence.

**Modify:**

- `backend/models/schemas.py`
- `backend/engine/normalizer.py`
- `backend/models/db_models.py`
- `backend/tests/test_contract_compliance.py`
- `tests/test_m4_normalizer.py`

**Add:**

- `backend/engine/relationships.py`
- `backend/knowledge/normalization_aliases.json`

**Responsibilities:**

1. Normalize algorithm aliases (`SHA1`, `SHA-1`, `sha1`) to one canonical identity.
2. Distinguish `algorithm`, `certificate`, `protocol`, `related-crypto-material`, `library`, `key-reference`, `hardware-module`, and `cloud-service` in the ECDAT extension while retaining valid CycloneDX core fields.
3. Merge duplicate evidence without losing occurrences.
4. Build relationships such as `uses`, `implemented-by`, `configured-by`, `protects`, `signed-by`, `issued-by`, and `depends-on` only from direct evidence.
5. Generate a stable `bom-ref` from asset identity, role, and scope.

**Acceptance tests:**

- Certificate plus Nginx config plus RSA/ECDSA evidence can be linked without falsely claiming a live network relationship.
- Existing raw findings still normalize unchanged.
- CycloneDX JSON remains parseable by the current report path.

#### M5: Multi-layer risk and migration-readiness engine

**Objective:** Keep Mosca as the urgency model, then add transparent contextual risk and readiness.

**Modify:**

- `backend/engine/risk.py`
- `backend/config.py`
- `backend/api/config_routes.py`
- `backend/models/schemas.py`
- `tests/test_m5_risk.py`
- `frontend/src/api.ts`

**Add:**

- `backend/engine/readiness.py`
- `backend/engine/hndl.py`
- `backend/knowledge/risk_policy.json`

**Assessment layers:**

1. **Classical status:** broken, deprecated, acceptable, strong, unknown.
2. **Quantum status:** vulnerable, weakened, resistant, not applicable, unknown.
3. **Mosca urgency:** retain the current `r = (X + Y) / Z` calculation and existing escalation for classically broken primitives.
4. **HNDL score:** calculate only for confidentiality-relevant, quantum-vulnerable assets. It is driven by data lifetime, exposure, and quantum status. Do not calculate it for a signature-only finding unless a separate confidentiality role exists.
5. **Migration readiness:** calculate from evidence, not guesswork.

**Readiness component scoring:**

| Component | 0 points | Partial points | Full points |
| --- | --- | --- | --- |
| Algorithm abstraction | Hard-coded algorithm | Wrapper/config evidence | Explicit provider/configuration abstraction |
| Library support | Unknown | Upgrade likely required | Detected capability supports target |
| Protocol support | Legacy/unknown | TLS or protocol upgrade required | Compatible protocol/group evidence |
| PKI or key support | Unknown | Rotation/reissue required | Target-capable path demonstrated |
| Test evidence | None | Unit test only | Integration/staging fixture present |
| Dependency visibility | Unknown | Partial graph | All direct dependencies found |

The UI must show component evidence and blockers. A number without an explanation is not acceptable.

**Acceptance tests:**

- Existing Mosca worked examples continue to pass unchanged.
- An external-facing, long-lived RSA-encrypted data path has a higher HNDL tier than an equivalent short-lived internal one.
- An unknown provider cannot receive a `Ready` readiness tier.
- A classically broken primitive remains Critical even with a low Mosca ratio.

#### M6: Migration strategy and playbook engine

**Objective:** Replace the current one-result `generate_recommendation()` mapping with candidate selection and an executable migration plan.

**Modify:**

- `backend/engine/recommend.py`
- `backend/engine/normalizer.py`
- `backend/models/schemas.py`
- `tests/test_m6_recommend.py`

**Add:**

- `backend/engine/strategy.py`
- `backend/engine/playbook.py`
- `backend/knowledge/standards_registry.json`
- `backend/knowledge/migration_playbooks.json`

**Required entry point:**

```python
def build_migration_strategy(asset, assessment, constraints) -> MigrationStrategy:
    """Return ranked candidates, selected action, blockers, and phased playbook."""
```

**Decision sequence:**

1. Determine artefact type and cryptographic role.
2. Apply the classical status policy first.
3. Apply quantum/HNDL/Mosca urgency.
4. Read deployment constraints: protocol, latency sensitivity, compliance target, provider capability, certificate role, and firmware context.
5. Rank candidates from the standards registry.
6. Select an action: retain, monitor, deprecate, replace, hybridize, rotate, reissue-certificate, upgrade-library, reconfigure, or manual-review.
7. Produce explicit blockers, assumptions, validation requirements, rollback, and playbook steps.

**Required playbook templates:**

- Weak hash in signature/integrity use.
- Legacy password hash.
- Weak symmetric cipher/mode.
- TLS key establishment using RSA, ECDH, or X25519.
- Digital signature or code-signing system.
- Firmware signing system.
- TLS leaf certificate and CA certificate.
- Unsupported provider/library or unknown crypto context.

**Acceptance tests:**

- MD5 password storage does not recommend SHA-384 as the primary fix.
- TLS ECDH/X25519 evidence offers hybrid TLS candidates when supported.
- A certificate finding recommends a renewal/reissue plan rather than only an algorithm name.
- HQC/FN-DSA appear only as tracked or future candidates unless their registry status becomes final.
- Unknown context returns `manual-review` and explains why.

### Developer C: Integration experience and reporting modules

#### M7: Persistence API and migration roadmap service

**Objective:** Persist assessments and expose consistent APIs without breaking current scan history.

**Modify:**

- `backend/models/db_models.py`
- `backend/database.py`
- `backend/engine/orchestrator.py`
- `backend/api/scans.py`
- `backend/api/assets.py`
- `backend/api/config_routes.py`
- `backend/main.py`
- `openapi.json`
- `tests/test_scan_integration.py`
- `tests/test_m7_pipeline.py`

**Add:**

- `backend/api/standards.py`
- `backend/api/roadmap.py`
- `backend/db_migrations/` for application-managed schema upgrades

**Persistence model:**

Add flattened columns to `Asset` only for fields needed for filtering: `artifact_type`, `classical_status`, `quantum_status`, `hndl_tier`, `migration_readiness_score`, `migration_readiness_tier`, and `migration_action`. Store complete details in the canonical `asset_json` to preserve flexibility.

Extend `Recommendation` with `action`, `phase`, `maturity`, `selected_candidate_json`, `candidates_json`, `playbook_json`, `blockers_json`, and `assumptions_json`.

Add `AssetRelationship` for evidence-backed links. Each row stores source asset, target reference, relationship type, confidence, and evidence location.

**Schema upgrade policy:**

- Create a simple versioned application migration mechanism suitable for the current SQLite-first project.
- Migrations must be idempotent and tested against an existing database fixture.
- Never discard old `asset_json`, `raw_cbom_json`, scans, or recommendations.
- Do not introduce PostgreSQL/Celery/Redis as part of this enhancement; those remain deployment roadmap items.

**New endpoints:**

| Endpoint | Purpose |
| --- | --- |
| `GET /standards` | Serve registry entries, maturity, and last review date. |
| `GET /assets?artifactType=&classicalStatus=&quantumStatus=&hndlTier=&readinessTier=&action=` | Filter the enriched inventory. |
| `GET /assets/{id}` | Return asset, relationships, layered assessment, candidates, and playbook. |
| `PATCH /assets/{id}/context` | Store user-supplied business criticality, data lifetime, exposure, and environment. It must preserve an audit trail. |
| `GET /roadmap/{scanId}` | Return grouped migration plans, blockers, and blast-radius summaries. |
| `GET /reports/{scanId}?format=...` | Include enriched fields in all formats. |

**Acceptance tests:**

- Existing scan and asset endpoints remain backward compatible.
- A scan persists a full playbook and returns it after API restart.
- Filters work using flattened fields.
- Context updates re-assess risk/recommendation without re-running M1-M3.

#### M8: Dashboard migration and certificate experience

**Objective:** Make the assessment understandable to a reviewer, operator, and SIH judge.

**Modify:**

- `frontend/src/types.ts`
- `frontend/src/api.ts`
- `frontend/src/App.tsx`
- `frontend/src/pages/OverviewPage.tsx`
- `frontend/src/pages/InventoryPage.tsx`
- `frontend/src/pages/AssetDetailPage.tsx`
- `frontend/src/pages/RecommendationsPage.tsx`
- `frontend/src/pages/HeatmapPage.tsx`
- `frontend/src/heatmap.ts`
- `frontend/src/api.test.ts`
- `frontend/src/heatmap.test.ts`

**Add:**

- `frontend/src/pages/MigrationRoadmapPage.tsx`
- `frontend/src/pages/CertificateDetailPage.tsx`
- `frontend/src/components/AssessmentBadges.tsx`
- `frontend/src/components/MigrationPlan.tsx`
- `frontend/src/components/ReadinessBreakdown.tsx`
- `frontend/src/components/RelationshipList.tsx`

**Required views:**

1. **Overview:** add counts for quantum-vulnerable, classically weak, HNDL-critical, migration-ready, and migration-blocked assets.
2. **Inventory:** filters for artefact type, classical status, quantum status, HNDL tier, readiness, and action.
3. **Asset detail:** show four status badges, Mosca breakdown, HNDL explanation, readiness component score, candidate comparison, assumptions, blockers, and the phased playbook.
4. **Certificate detail:** show certificate role, issuer, validity/renewal window, algorithms, chain/trust hints, dependent configuration evidence, and reissue plan.
5. **Migration roadmap:** group actions by phase and priority. Show the number of assets/services/relationships affected, called the migration blast radius.
6. **Heatmap:** retain the existing Z scenario interaction. Do not imply that changing Z changes persisted assessment unless the user saves a new scenario.

**UX rules:**

- Use clear plain-language labels such as `Classically deprecated`, `Quantum vulnerable`, and `Hybrid transition recommended`.
- Display standards maturity beside every candidate.
- Distinguish detected facts from inferred assumptions and user-entered context.
- Never show secret contents, private key data, or full sensitive certificate subject details by default.

**Acceptance tests:**

- The detail screen renders `manual-review` without a blank or broken state.
- Candidate tables visibly distinguish final and future standards.
- The certificate screen shows a renewal-window action when validity facts exist.
- Existing 24 frontend tests remain green; add tests for mapping and playbook rendering.

#### M9: Migration-focused reporting and demo evidence

**Objective:** Make exports useful for technical teams and readable for decision-makers.

**Modify:**

- `backend/engine/reporting/cbom_report.py`
- `backend/engine/reporting/pdf_report.py`
- `backend/engine/reporting/spreadsheet_report.py`
- `backend/engine/reporting/__init__.py`
- `tests/test_m9_reporting.py`
- `scripts/demo_smoke.py`
- `documentation/TEST_DATA.md`

**Report requirements:**

- **CBOM JSON:** retain CycloneDX core fields and include ECDAT extension fields for assessment, relationships, candidates, and plans.
- **CSV/XLSX:** one row per canonical asset with classical status, quantum status, HNDL tier, Mosca values, readiness, selected action, target, maturity, blockers, and first playbook step.
- **PDF:** executive summary, risk/readiness distribution, priority migration paths, top blockers, certificate renewal opportunities, and a caveat that findings require human review.
- **Demo evidence:** add fixtures that show weak hashes, password storage, TLS hybrid candidate selection, a certificate renewal path, an unknown provider blocker, and a strong algorithm retained.

**Acceptance tests:**

- Existing report formats still generate.
- CBOM JSON remains valid JSON and contains the extension data.
- XLSX column headings and PDF summary contain migration status and standards maturity.
- The demo smoke output contains at least one action from each of `replace`, `hybridize`, `reissue-certificate`, and `manual-review`.

## 9. Risk and readiness methodology

### 9.1 Mosca remains the timing core

The existing calculation remains authoritative:

```text
r = (X + Y) / Z
```

Where `X` is data/security shelf life, `Y` is migration effort, and `Z` is the assumed time to a cryptographically relevant quantum computer. Existing critical/high/medium/low thresholds remain unchanged.

### 9.2 HNDL assessment

HNDL is an additional confidentiality assessment, not a replacement for Mosca. It applies only when all are true:

- the asset protects confidentiality;
- the algorithm is quantum-vulnerable or quantum-weakened; and
- data lifetime is known or conservatively inferred.

Suggested transparent calculation:

```text
HNDL score = quantum factor x exposure factor x min(data lifetime / Z, 2)
```

The display must include the factors and assumptions. If data lifetime is unknown, show `HNDL unknown` rather than making it Critical by default.

### 9.3 Readiness categories

| Tier | Interpretation |
| --- | --- |
| Ready | Evidence supports an available target, protocol/provider compatibility, and a realistic validation path. |
| Partial | A practical target exists but one or more upgrades, certificate changes, or tests are required. |
| Blocked | A material dependency such as an HSM, legacy client, provider, or protocol prevents immediate migration. |
| Unknown | Static evidence is insufficient. Human review is required. |

### 9.4 Prioritization rule

Sort roadmap items using this order:

1. Classically broken assets.
2. HNDL-critical assets.
3. Mosca Critical and High assets.
4. Blocked high-risk assets, because they need early planning.
5. Certificate renewal opportunities that reduce migration disruption.
6. Monitor/retain assets.

## 10. Migration strategy catalogue

| Strategy | When to use | Example output |
| --- | --- | --- |
| Retain | Strong algorithm and acceptable configuration. | AES-256-GCM with known good usage. |
| Monitor | Strong now but implementation/lifecycle needs periodic review. | SHA-256 in a long-lived protocol. |
| Deprecate | Present-day weak algorithm with a known safe use-specific successor. | SHA-1 signature usage. |
| Replace | No safe transition compatibility layer is appropriate. | RC4 to AEAD configuration. |
| Hybridize | Public-key key establishment where both components can operate. | X25519MLKEM768 in TLS 1.3. |
| Rotate | Existing keys require replacement after an algorithm or policy change. | RSA service key rotation. |
| Reissue certificate | Certificate/profile must change at renewal or PKI migration. | ECDSA TLS leaf certificate. |
| Upgrade library | Target support requires a provider/runtime change. | TLS stack cannot negotiate an approved hybrid group. |
| Reconfigure | Current algorithm is acceptable but insecure mode/protocol config is not. | AES-CBC/ECB configuration. |
| Manual review | Evidence is insufficient or the asset is ambiguous. | Generic package dependency without observed crypto usage. |

## 11. Certificate migration design

Certificates are not just algorithms. A certificate assessment must answer:

| Question | Source of evidence |
| --- | --- |
| What is its role? | File location, configuration, and usage context. |
| Which public-key and signature algorithms are in use? | X.509 parsing. |
| When can it be changed with minimal disruption? | Validity and renewal window. |
| Who issues/trusts it? | Issuer, chain, trust-store/configuration evidence. |
| What breaks if it changes? | Referencing services/configuration and discovered relationships. |
| What is the plan? | Reissue, update trust, validate clients, canary, rotate, rollback. |

For a TLS leaf certificate, the default playbook must not claim universal PQ certificate support. It should propose a staged compatibility assessment, classical/hybrid protocol migration where supported, a renewal-window plan, and an explicit CA/client compatibility blocker.

## 12. API and frontend contract

### 12.1 Asset detail response additions

```json
{
  "assessment": {
    "classicalStatus": "acceptable",
    "quantumStatus": "vulnerable",
    "hndlTier": "High",
    "mosca": {"x": 10, "y": 2, "z": 8, "r": 1.5, "tier": "Critical"},
    "readiness": {"score": 48, "tier": "Partial", "blockers": ["Library version must be verified"]}
  },
  "strategy": {
    "action": "hybridize",
    "phase": "transition",
    "selectedCandidate": "X25519MLKEM768",
    "candidates": [],
    "playbook": []
  },
  "relationships": []
}
```

### 12.2 User-entered context

Static scanning cannot know every business fact. The UI must allow an authorized local user to supply:

- business criticality;
- data classification;
- confidentiality lifetime;
- exposure;
- service/application owner;
- deployment environment; and
- known client or hardware constraints.

Each field must record provenance as `detected`, `inferred`, or `user-supplied`. User edits trigger reassessment and retain a timestamped audit record.

## 13. Integration order and branch plan

### 13.1 Day 1 contract freeze

All three developers agree on:

- enums and JSON shapes in Section 7;
- standard registry schema;
- API response examples;
- fixture names and expected outcomes; and
- the rule that only root `backend/` and `frontend/` are active.

### 13.2 Branches

| Developer | Branch | Modules |
| --- | --- | --- |
| A | `feature/discovery-context` | M1, M2, M3 |
| B | `feature/assessment-strategy` | M4, M5, M6 |
| C | `feature/migration-experience` | M7, M8, M9 |

Developer B may begin with fixtures and contract tests before Developer A completes all detectors. Developer C may develop screens against frozen API fixture JSON before the backend merge.

### 13.3 Seven-day implementation plan

| Day | Developer A | Developer B | Developer C |
| --- | --- | --- | --- |
| 1 | Detection/context rule design | Contract, registry, risk policy design | API response mockups, schema migration plan |
| 2 | M1 context fixtures and scanner changes | M4 schema/defaults and M5 assessment skeleton | Database models and API response models |
| 3 | M2 provider capability data | M5 HNDL/readiness tests | Persisted assessment and standards endpoint |
| 4 | M3 certificate/protocol facts | M6 candidate and playbook engine | Asset detail and roadmap UI |
| 5 | Merge discovery work and regression tests | Merge intelligence work and end-to-end tests | Certificate view and reports |
| 6 | Expand fixtures and false-positive review | Scenario tuning and policy review | Demo workflow, PDF/XLSX polish |
| 7 | Full smoke test and bug fixes | Full smoke test and documentation | Full smoke test, presentation rehearsal |

## 14. Test plan

### 14.1 Unit tests

- Normalization aliases, defaults, and relation generation.
- Classical and quantum status classification.
- Mosca tier compatibility with existing tests.
- HNDL applicability and assumptions.
- Readiness evidence scoring and blockers.
- Recommendation candidates and maturity labels.
- Every playbook template.

### 14.2 Integration tests

- Source file to enriched asset to persisted recommendation.
- Certificate and Nginx configuration linked in one scan.
- User context update re-assesses an existing scan without re-running scanners.
- Existing scan history/database data still opens after schema migration.
- CSV/XLSX/PDF/CBOM exports include new values.

### 14.3 Demo fixtures

| Fixture | Expected message |
| --- | --- |
| SHA-1 signature | Replace/deprecate with a use-specific modern digest/signature path. |
| MD5 password storage | Use a password KDF; do not suggest SHA-384. |
| AES-128 long-lived backup | Plan AES-256 because of quantum margin and data lifetime. |
| TLS X25519 configuration | Hybrid candidate and compatibility checks. |
| ECDSA leaf certificate | Renewal/reissue plan with CA/client blocker. |
| Unknown provider manifest | Manual review and readiness unknown. |
| AES-256-GCM | Retain/monitor with configuration confirmation. |

## 15. Security and privacy boundaries

- Never save raw private keys, secrets, plaintext credentials, or upload contents in reports.
- Store fingerprints and paths only where sufficient for asset correlation.
- Sanitize certificate subject fields in overview/report exports.
- Keep the existing bounded snapshot, ZIP validation, Git allowlist, and local worker controls.
- Treat migration plans as guidance requiring review, not a command execution feature.

## 16. Demo script

1. Scan the supplied mixed workspace.
2. Show inventory filters for classically broken, quantum-vulnerable, and certificate assets.
3. Open a high-risk TLS/certificate path and explain Mosca plus HNDL.
4. Compare final-standard ML-KEM candidate with future/tracked alternatives.
5. Show the hybrid transition playbook and its client/library compatibility blockers.
6. Open the certificate renewal plan and show the related configuration evidence.
7. Open the roadmap and show the highest-impact migration paths.
8. Export the CBOM or XLSX and show the migration columns.

## 17. Completion criteria

The enhancement is complete when:

- All original backend and frontend tests remain green.
- A scan produces the four classification axes for every asset, using `unknown` where evidence is absent.
- At least six strategy types are demonstrable from fixtures.
- Certificate findings show a lifecycle-aware migration plan.
- Standards maturity is visible in the UI and reports.
- The roadmap groups findings by priority and exposes blockers/relationships.
- No result exposes secrets or claims that a draft algorithm is a final production standard.

## 18. Standards and research references

- SIH26164 Enterprise Cryptographic Discovery and Analysis Tool: https://sih2026.vuce.in/ps/SIH26164
- NIST PQC standardization status and FIPS 203, 204, 205: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post_Quantum_Cryptography-Standardization
- NIST SP 800-131A, Transitioning the Use of Cryptographic Algorithms and Key Lengths: https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
- NIST SP 800-208, Stateful Hash Based Signature Schemes: https://csrc.nist.gov/pubs/sp/800/208/final
- NIST NCCoE Migration to PQC project: https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc
- NIST SP 1800-38B preliminary discovery guide, including CARAF and risk methodology survey: https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38b-preliminary-draft.pdf
- RFC 10024, PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3: https://www.rfc-editor.org/rfc/rfc10024.html

