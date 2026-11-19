# Changelog

All notable changes to ECDAT are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing pending.

## [1.3.0] - 2026-11-19

The interoperability release, driven by the competitive-landscape research:
ECDAT results now leave the tool in the formats the ecosystem speaks, the
emitted CBOM passes the official CycloneDX schema, and the scanner runs as a
CI step.

### Added

- **SARIF 2.1.0 export** (`GET /reports/{id}?format=sarif`): every assessed
  asset as one SARIF result with tier-to-level mapping, file and line
  locations, declared rules per migration action, and the plan in result
  properties — ready for GitHub code scanning.
- **Headless CI scan** (`scripts/scan_cli.py`): runs the full pipeline against
  a throwaway database and emits `cbom.json` plus `results.sarif`, with an
  optional `--fail-on-critical` gate. The operator's scan history is never
  touched.
- **Composite GitHub Action** ([action.yml](action.yml)): other repositories
  can run ECDAT as a step and receive the CBOM and SARIF artifacts — the
  cbomkit-action pattern, without a SonarQube server.
- **Official-schema CBOM validation** (`backend/engine/cbom_validator.py`,
  `scripts/validate_cbom.py`): the CycloneDX 1.6 JSON schema and its SPDX
  dependency are vendored, and validation runs in tests and CI.
- **CBOM drift endpoint** (`GET /cbom/{id}/diff?against={id}`): added,
  removed and changed assets between two scans with before/after values for
  risk tier, action, usage context and artefact type.
- **OpenAPI contract gate**: the committed `openapi.json` is compared against
  the generated schema in CI.

### Fixed

- The emitted CBOM was **not schema-valid**. The official component schema
  forbids unknown fields and restricts the primitive and crypto-function
  vocabularies, and ECDAT violated all three: `ecdatEnrichment` and
  `occurrences` sat directly on components, primitives such as
  `asymmetric_kem` and `symmetric` were non-standard, functions such as
  `key-exchange` and `transport` were non-standard, and null OIDs were
  emitted. The export now carries occurrences and enrichment in standard
  namespaced `properties` (`ecdat:...`), maps primitives and functions to the
  official enums, and omits null OIDs. `CONTRACT.md` section 2 records the
  amendment; the internal asset model and the `/assets` API are unchanged.

### Changed

- Version source moved to `backend/version.py` (the API reports 1.3.0).
- `jsonschema` added as a runtime dependency for CBOM validation.

## [1.2.0] - 2026-11-19

The operational excellence release. The service can now be scraped by a
monitoring stack, throttled when exposed beyond a single operator, audited
across its whole lifecycle and backed up with one command.

### Added

- **Metrics endpoint** (`GET /metrics`, Prometheus text format): request
  counters and cumulative latency by route template, method and status; scan
  outcome counters; stored scans and assets gauges; process uptime and build
  info. Token-protected like every other data route.
- **Rate limiting** (`backend/ratelimit.py`): a per-client token bucket,
  disabled by default, enabled with `ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE`
  and an optional `ECDAT_RATE_LIMIT_BURST`. Exceeding it returns the standard
  error envelope with `Retry-After`; health probes stay exempt.
- **Scan lifecycle audit trail**: `scan-completed`, `scan-failed`,
  `scan-deleted` (with the `X-Operator` actor) and `scan-retention-deleted`
  join `asset-context-override` in the `audit_events` table.
- **Opt-in retention** (`ECDAT_SCAN_RETENTION_DAYS`): completed scans older
  than the configured window are pruned at start-up and hourly by the worker,
  one audit event each; queued, running and failed scans are never touched.
- **Database administration** (`scripts/db_admin.py`): `stats`, `backup` (via
  the SQLite online-backup API, safe against a running API) and `vacuum`.
- **Committed API contract** ([openapi.json](openapi.json)) with a drift test
  that fails CI when the generated schema no longer matches the committed
  file.
- **Dependabot** (`.github/dependabot.yml`): weekly pip and npm updates,
  monthly GitHub Actions updates.

### Changed

- Service version bumped to 1.2.0 and the committed OpenAPI document
  regenerated at that version (it was still 1.0.0).
- `db_admin stats` skips tables that are absent instead of failing, so it
  works on partial databases.

### Documentation

- Operations guide gains metrics, rate-limiting, retention and audit sections
  and the `db_admin` procedure; README documents the new settings and
  endpoint.

## [1.1.0] - 2026-11-19

The enterprise hardening and post-quantum migration release. Scan results
now carry a versioned policy trail, an explicit migration strategy and an
auditable operator override, and the service exposes production-shaped
operational endpoints.

### Added

- **Standards registry** (`backend/knowledge/standards_registry.json`): a
  versioned, human-reviewed policy file with 41 entries covering symmetric
  ciphers, asymmetric primitives, hashes, KDFs, MACs, protocols and
  certificate artefacts. Each entry declares classical status, quantum
  status, standards maturity, default action and named migration paths with
  ranked candidates.
- **Four-axis assessment engine** (`backend/engine/standards.py`): classical
  status, quantum status, standards maturity and usage context are classified
  independently, so an algorithm can be classically strong and quantum
  vulnerable at the same time.
- **Migration strategy engine** (`backend/engine/strategy.py`): produces an
  action, a phase, ranked candidates, blockers, assumptions and a numbered
  playbook instead of a bare "algorithm to replacement" line.
- **Readiness scoring** (`backend/engine/readiness.py`) and **HNDL exposure
  assessment** (`backend/engine/hndl.py`) per asset, surfaced as tiers.
- **Migration roadmap API** (`GET /roadmap/{scan_id}`) grouping a scan into
  act-now, plan-and-stage, reach-target and monitor phases.
- **Standards API** (`GET /standards`, `GET /standards/{entry_id}`) exposing
  the registry and its migration paths.
- **Operator context override** (`PATCH /assets/{id}/context`): an operator
  can confirm the real use of an artefact and re-plan the migration. Every
  override writes a `before`/`after` audit event with actor and request id.
- **Registry validation** (`validate_registry()`,
  `scripts/validate_registry.py`): structural checks over the policy file run
  in CI and as a local test.
- **Operational endpoints**: `/health` for liveness, `/health/ready` for
  dependency readiness (database, registry, detection signals, scan worker),
  plus build and registry metadata.
- **Structured logging** (`backend/logging_config.py`): JSON or text logs
  carrying a request id on every record.
- **Request context middleware** (`backend/middleware.py`): request id
  generation and echo, security response headers, and access logging.
- **Audit trail** (`audit_events` table) recording operator overrides.
- **Operational indexes** on the asset, recommendation and audit tables for
  the filtered inventory queries.
- **Detection coverage**: ChaCha20-Poly1305, HMAC-SHA256, bcrypt, Argon2id,
  scrypt, PBKDF2 and TLS version usage in code, with tree-sitter AST
  confirmation.
- **CI pipeline** (`.github/workflows/ci.yml`): backend suite on Windows and
  Linux across Python 3.10 and 3.12, frontend unit tests and production
  build, and the registry policy check.
- **Documentation**: architecture reference, migration playbook, operations
  guide and this changelog.

### Changed

- Asset listing now filters, counts and paginates in SQL; only the
  interactive threat-timeline slider path loads rows into memory.
- Detection became data-driven: the cipher mode and key size are read from
  the matched text, so `AES-256-GCM` style identifiers resolve without
  per-language special cases.
- Key-size aware canonicalisation promotes a generic hit to its sized
  variant (`RSA` to `RSA-2048`), so one usage produces one asset.
- Duplicate findings from a single call site are collapsed in the AST
  tier, which removed inflated CBOM counts and false duplicate assets.
- ECB mode is treated as a reconfiguration problem: the recommendation
  targets an AEAD mode before any algorithm change is considered.
- Password storage is routed to KDF-specific candidates rather than a
  generic hash recommendation.
- Recommendations no longer assume NIST-only targets; the compliance
  target can be switched and the candidates are re-ranked for it.

### Security

- Every API error returns a structured envelope with the request id and no
  stack trace or internal detail.
- Validation errors return field-level detail.
- Response headers set `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy` and
  `Cache-Control: no-store`, with HSTS on HTTPS.
- SQLite runs with foreign keys enforced and WAL journalling.
- Health probes stay reachable without the shared bearer token; every other
  endpoint still requires it when `ECDAT_API_TOKEN` is set.

### Fixed

- A symlink-dependent test now skips on hosts without symlink permission
  instead of failing the suite.

## [1.0.0] - 2026-09-10

The first end-to-end release: source, dependency, binary, infrastructure and
certificate discovery feeding a CycloneDX-aligned CBOM, Mosca risk scoring,
recommendations, the React dashboard, PDF/CSV/XLSX/JSON export, the Windows
launcher and the LAN sharing mode.

[Unreleased]: https://github.com/ACE4AKSHAY/Akatsuki-Ecdat/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/ACE4AKSHAY/Akatsuki-Ecdat/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ACE4AKSHAY/Akatsuki-Ecdat/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ACE4AKSHAY/Akatsuki-Ecdat/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ACE4AKSHAY/Akatsuki-Ecdat/releases/tag/v1.0.0