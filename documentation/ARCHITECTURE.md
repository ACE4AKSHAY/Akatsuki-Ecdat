# ECDAT architecture reference

How ECDAT is put together, what each module owns, and where to extend it. For
the original problem framing see `ECDAT_Design_and_Technical_Document.md` at
the repository root; this document describes the system as it is built.

## 1. Shape of the system

ECDAT is a local-first analysis tool. A scan ingests a bounded snapshot of
source, dependency manifests, binaries, infrastructure configuration and
certificates, converts every hit into a canonical cryptographic asset, scores
that asset against a versioned policy registry, and exposes the result through
an HTTP API, a React dashboard and file exports.

```
input (path | zip | upload | git | image inventory)
  │
  ├─ M1 source scanner      tier1 regex  → tier2 tree-sitter AST
  ├─ M2 dependency/binary   manifests + symbols/strings
  └─ M3 infrastructure      configs, IaC, containers, certificates
        │
        ▼
  M4 normalizer            dedupe → canonical CBOM asset + enrichment
        │
        ├─ M5 risk           Mosca r = (X + Y) / Z, tier + composite score
        ├─ M6 recommendation legacy and PQC candidates
        ├─ standards         classical/quantum/maturity/context axes
        ├─ readiness         per-artefact migration readiness tier
        ├─ hndl              harvest-now-decrypt-later exposure tier
        └─ strategy          action, phase, candidates, blockers, playbook
        │
        ▼
  persistence (SQLite)  assets · recommendations · scans · audit events
        │
        ▼
  M7 API → M8 dashboard → M9 reports (PDF / CSV / XLSX / CycloneDX JSON)
```

## 2. Module ownership

### M1 — Source scanner (`backend/scanners/source/`)

Two passes over the same files:

- **Tier 1** (`tier1.py`) matches the regex signals declared in
  `signals.yaml` and emits findings with `detectionTier="regex"` and
  confidence `0.6`. The signal file is the single place where detection
  coverage is defined, so adding a primitive means editing data, not code.
  Mode and key size are recovered from the matched text, which is how
  `AES-256-GCM` identifiers and `modes.ECB()` calls become structured
  evidence.
- **Tier 2** (`tier2.py`) re-parses every file that produced a hit with
  tree-sitter and confirms it against a real crypto API call. Confirmed
  findings carry `detectionTier="ast"` and confidence `0.95`; hits that
  resolve to no crypto call are dropped, which is what keeps the
  false-positive trap corpus empty.

Both passes use the same dedupe key `(filePath, lineNumber, detectedPrimitive)`,
and a base primitive collapses into its key-size variant (`RSA` into
`RSA-2048`) so one call site produces one finding.

Supported languages: Python, Java, JavaScript, TypeScript and Go.

### M2 — Dependency, manifest and binary scanner (`backend/scanners/binary_deps/`)

Reads package manifests (npm, pip, Maven, Gradle, Go) and inspects binaries
through strings and, when present, native symbol tools. Findings are
attributed to the dependency that introduced them, not to a file.

### M3 — Infrastructure scanner (`backend/scanners/infra/`)

Scans configuration and infrastructure-as-code for TLS versions, cipher
suites and key material references, reads X.509 certificates and extracts
their facts (subject, issuer, validity window, signature algorithm, key
size), and parses container package inventories (CycloneDX or Trivy JSON).
Certificate findings record the paths that reference them so a certificate
can be linked back to the configuration that uses it.

### M4 — Normalizer (`backend/engine/normalizer.py`)

Groups raw findings into canonical assets keyed by
`{canonical algorithm}::{file path}`, promotes a generic algorithm to its
key-size variant, merges evidence, and produces the CycloneDX 1.6 aligned
asset with an `ecdatEnrichment` block holding every derived assessment.

### M5 — Risk engine (`backend/engine/risk.py`)

Operationalises Mosca's inequality as `r = (X + Y) / Z`, where `X` is the
estimated shelf life of the data in years, `Y` the migration effort in years
and `Z` the time until a cryptographically relevant quantum computer
exists. The ratio maps to a risk tier, and business criticality, exposure and
key size refine a composite risk score. Known-broken configurations escalate
automatically.

### M6 — Recommendation engine (`backend/engine/recommend.py`)

Turns a canonical algorithm, its mode and its usage context into a
replacement, a reference standard and a complexity note. Mode-aware: ECB
usage is routed to an AEAD reconfiguration rather than an algorithm swap.

### Standards engine (`backend/engine/standards.py`)

Classifies an artefact on four independent axes and serves the policy
registry:

- **classical status** — strong, acceptable, deprecated or broken
- **quantum status** — vulnerable, weakened or resistant
- **standards maturity** — the maturity of the governing standard
- **usage context** — signing, transport, key exchange, password storage and
  so on, inferred from the call site or confirmed by an operator

The registry itself lives in `backend/knowledge/standards_registry.json` and
is versioned (`registryVersion`) and dated (`reviewedOn`). `validate_registry()`
checks its structure so a policy error cannot ship silently.

### Strategy engine (`backend/engine/strategy.py`)

Builds the actionable part of an assessment: the migration **action**
(replace, hybridize, reconfigure, reissue, rotate, retain, monitor, …), the
**phase** (immediate, transition, target, monitor), the ranked **candidates**,
the **blockers** that must be cleared, the **assumptions** the plan rests on
and a numbered **playbook** for the engineer doing the work.

### Readiness and HNDL engines

`readiness.py` scores how ready an artefact is to migrate (evidence quality,
context confidence, protocol and library support) and produces a tier.
`hndl.py` scores harvest-now-decrypt-later exposure, combining quantum
status, usage context, exposure and shelf life against the threat timeline.

### M7 — API (`backend/api/`, `backend/main.py`)

| Endpoint | Purpose |
| --- | --- |
| `POST /scans`, `POST /scans/upload` | Queue a scan from a path, archive or upload |
| `GET /scans`, `GET /scans/{id}` | Scan status, history and results |
| `DELETE /scans/{id}`, `DELETE /scans` | Remove finished scans |
| `GET /assets` | Filtered, paginated inventory with an optional Z slider |
| `GET /assets/{id}` | Full asset detail, Mosca breakdown and strategy |
| `PATCH /assets/{id}/context` | Operator context override (audited) |
| `GET /cbom/{scan_id}` | CycloneDX-aligned document, schema-valid against the official 1.6 JSON schema |
| `GET /cbom/{scan_id}/diff` | Drift between two scans: added, removed and changed assets |
| `GET /roadmap/{scan_id}` | Phased migration work list |
| `GET /standards`, `GET /standards/{id}` | Policy registry and migration paths |
| `GET /config/threat-model`, `PATCH /config/threat-model` | Timeline defaults |
| `GET /reports/{scan_id}` | PDF, CSV, XLSX, JSON and SARIF exports |
| `GET /health`, `GET /health/ready` | Liveness and dependency readiness |

### M8 — Dashboard (`frontend/`)

React with TypeScript and Vite. Pages: overview, inventory, asset detail,
migration roadmap, heatmap and recommendations. The API client centralises the
bearer token and error handling.

### M9 — Reporting (`backend/engine/reporting/`)

Renders the saved assessment to PDF (reportlab), CSV, XLSX (openpyxl) and
CycloneDX-aligned JSON.

## 3. Cross-cutting design decisions

**Data-driven detection.** New primitives are added in `signals.yaml`, not in
Python. The AST tier confirms what the regex tier proposes, so the rules
file stays cheap to audit.

**One asset per usage.** Findings are merged rather than listed, so the CBOM
reflects real cryptographic usage instead of raw hit counts.

**Policy separated from code.** Standards, migration paths and candidate
rankings live in a reviewed JSON file with a version, not in Python
conditionals. Changing policy is a data change with a version trail.

**Actionable output.** An asset always carries a phase, a target and a
playbook, not only a replacement name.

**Local-first, single writer.** SQLite with a single scan worker behind a
cross-platform lock keeps the deployment model simple and the failure modes
predictable.

## 4. Extension points

| Goal | Where to change |
| --- | --- |
| Detect a new algorithm | `backend/scanners/source/signals.yaml`, then a registry entry |
| Change migration policy | `backend/knowledge/standards_registry.json` (bump `registryVersion`) |
| Add a usage context | `backend/engine/context.py` and `backend/engine/standards.py` |
| Add a migration path | `backend/knowledge/standards_registry.json` `migrationPaths` |
| Add a scanner source | `backend/scanners/<new>/`, register it in `backend/scanners/runner.py` |
| Change the risk model | `backend/engine/risk.py` |
| Add an API route | `backend/api/<area>.py`, register the router in `backend/main.py` |
| Add a dashboard view | `frontend/src/` |

## 5. Request lifecycle

1. `RequestContextMiddleware` assigns a request id (honouring an inbound
   `X-Request-ID`), sets it on `request.state` and the logging context, and
   adds the security response headers.
2. `AccessControl` enforces the shared bearer token except on the public
   health paths.
3. The route handler validates input with Pydantic and works through
   `get_db`.
4. The scan queue persists the job and a background worker runs the
   pipeline: ingest → scan → normalize → assess → persist.
5. Errors are converted into a structured envelope
   (`detail`, `statusCode`, `requestId`) by the exception handlers in
   `backend/main.py`; validation errors add field-level `errors`.

## 6. Data model

`scans` → `assets` → `recommendations`, plus `audit_events`.

- **scans**: id, target description, status, options, timestamps.
- **assets**: scan id, bom ref, name, primitive category, usage context,
  artefact type, migration action and phase, readiness tier and score, HNDL
  tier, risk tier, Mosca X/Y/Z, and the full canonical asset JSON.
- **recommendations**: asset id, recommended algorithm, mode, complexity,
  action, phase, rationale, reference standard and the strategy JSON.
- **audit_events**: scan id, asset id and ref, actor, action, request id,
  before and after JSON, timestamp.

## 7. Operational surface

See `documentation/OPERATIONS.md` for configuration, health probes, logging,
the security posture and the registry maintenance procedure, and
`documentation/MIGRATION_PLAYBOOK.md` for how to act on the results.
