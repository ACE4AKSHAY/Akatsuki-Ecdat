# ECDAT operations guide

How to run, observe, secure and maintain an ECDAT deployment. The local
setup procedure lives in `SETUP_AND_RUN.md`; this document covers the
operational surface of the service.

## 1. Deployment model

ECDAT is a local-first, single-node service:

- **API** — FastAPI on loopback by default, Uvicorn, one worker process.
- **Worker** — one background scan worker, guarded by a cross-platform file
  lock so a second instance cannot process the same queue.
- **Database** — SQLite in WAL mode with foreign keys enforced.
- **Dashboard** — a built React bundle served by Vite in dev mode or by any
  static host in production, proxying `/api/*` to the backend.

The single-writer design is deliberate: scan jobs mutate shared state, and
serialising them keeps failures predictable. Horizontal scaling requires a
different job backend and is out of scope for this release.

## 2. Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy connection string | `sqlite:///./ecdat.db` |
| `ECDAT_STATE_DIR` | Uploads, ingestion state and worker lock | `.ecdat` |
| `ECDAT_API_TOKEN` | Shared bearer token for every endpoint except the health probes | unset |
| `ECDAT_CORS_ORIGINS` | Comma-separated allowed browser origins | unset |
| `ECDAT_GIT_HOSTS` | HTTPS Git host allowlist | GitHub, GitLab, Bitbucket |
| `ECDAT_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `ECDAT_LOG_FORMAT` | `json` or `text` | `json` |
| `ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE` | Sustained request rate per client IP; `0` disables limiting | `0` |
| `ECDAT_RATE_LIMIT_BURST` | Bucket depth above the sustained rate | the rate |
| `ECDAT_SCAN_RETENTION_DAYS` | Delete completed scans older than this; `0` keeps everything | `0` |
| `ECDAT_MAX_UPLOAD_MIB` | Upload size limit | `512` |
| `ECDAT_MAX_WORKSPACE_MIB` | Local, Git snapshot or expanded ZIP limit | `2048` |
| `ECDAT_MAX_FILES` | Snapshot file count or ZIP entry count | `100000` |
| `ECDAT_MAX_INVENTORY_MIB` | Container inventory JSON limit | `128` |
| `ECDAT_GIT_TIMEOUT_SECONDS` | Git clone deadline | `600` |
| `ECDAT_IMAGE_TIMEOUT_SECONDS` | Live image inventory deadline | `600` |
| `API_PROXY_TARGET` | Dashboard API proxy target | `http://127.0.0.1:8000` |

All of them are read at start-up. Change a value, then restart the backend.

## 3. Health and readiness

```
GET /health       liveness — the process is up and answering
GET /health/ready readiness — the dependencies are usable
```

`/health` reports the service version and status. `/health/ready` checks each
dependency separately:

| Check | What it verifies |
| --- | --- |
| `database` | The database answers a trivial query |
| `standardsRegistry` | The policy registry loads and passes validation |
| `detectionSignals` | The detection signal file loads and has patterns |
| `scanWorker` | The background scan worker thread is running |

Readiness is decided by the database, registry and signal checks. A stopped
worker is reported but does not by itself make the instance unready, so a
restarting deployment is not taken out of rotation prematurely.

## 3a. Metrics

`GET /metrics` renders the Prometheus text format (media type
`text/plain; version=0.0.4`). Unlike the health probes it exposes no asset
data but is still token-protected, matching every other route.

| Series | Type | Meaning |
| --- | --- | --- |
| `ecdat_requests_total{method,route,status}` | counter | Requests processed, labelled by route template, method and status code |
| `ecdat_request_duration_seconds_sum{method,route,status}` | counter | Cumulative request duration per series |
| `ecdat_scan_outcomes_total{outcome}` | counter | Scan pipeline completions and failures since start |
| `ecdat_scans_total{status}` | gauge | Stored scans grouped by status |
| `ecdat_assets_total` | gauge | Stored cryptographic assets |
| `ecdat_process_uptime_seconds` | gauge | Seconds since process start |
| `ecdat_build_info{version,commit,builtAt}` | gauge | Build metadata, always `1` |

Metrics are process-local, which matches the single-worker model. Scrape
them with any Prometheus-compatible collector, or read them directly during
an incident.

## 3b. Rate limiting

Off by default. Setting `ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE` enables a
per-client token bucket: each client IP may sustain the configured rate with
a burst of `ECDAT_RATE_LIMIT_BURST` (default: the rate itself). Exceeding it
returns `429` with the standard error envelope and a `Retry-After` header.
Health probes are always exempt so monitoring cannot be locked out. The
bucket store is pruned of idle entries, so long-running processes do not grow
unbounded. Enable it when the API is exposed beyond a single operator,
for example in LAN mode on a shared network.

## 3c. Retention

Off by default. `ECDAT_SCAN_RETENTION_DAYS` deletes *completed* scans older
than the configured number of days. The sweep runs once at start-up and then
hourly in the scan worker. Queued, running and failed scans are never
touched, and every pruned scan writes a `scan-retention-deleted` audit event
recording its target, asset count and completion date. Scan reports already
downloaded to disk and uploaded input copies are not affected.

## 3d. Audit trail

The `audit_events` table records every lifecycle decision, not just asset
overrides:

| Action | Written when |
| --- | --- |
| `scan-completed` | The pipeline finishes persisting a scan's assets |
| `scan-failed` | The pipeline aborts, with the truncated error |
| `scan-deleted` | An operator deletes history; the actor comes from `X-Operator` |
| `scan-retention-deleted` | Retention prunes an aged-out scan |
| `asset-context-override` | An operator confirms a usage context and re-plans |

Query it directly for incident reviews:

```sql
SELECT created_at, actor, action, scan_id, asset_ref
FROM audit_events ORDER BY created_at DESC LIMIT 50;
```

Both paths are exempt from the bearer token so an orchestrator can poll them
without a credential. Everything else requires the token when
`ECDAT_API_TOKEN` is set.

`/health/ready` also returns the registry version and review date, the
detection signal count, and the build commit and build time, which is enough
to confirm that the running process is the expected revision.

## 4. Logging

The service emits structured JSON by default. Each record carries the
timestamp, level, logger, message and the request id of the request in
scope. Set `ECDAT_LOG_FORMAT=text` for human-readable output during
development.

Every request is logged once by the request-context middleware with its
method, path, status code and duration. The request id is generated per
request unless the client sends `X-Request-ID`, in which case the inbound
value is reused (truncated to 64 characters). The same id appears in the
response headers and in every error body, so a user-reported failure can be
traced to exact log lines.

The audit trail is separate from the application log: it is stored in the
`audit_events` table and records operator decisions, not request activity.

## 5. Security posture

**Authentication.** A single optional shared bearer token. It is a
single-operator or small-team mechanism, not an identity system.

**Authorisation.** The token grants full access to every route. There are no
roles and no per-tenant isolation. `X-Operator` and the `operator` field in
the context override are recorded for accountability, not enforced.

**Transport.** The default deployment is loopback only. In LAN mode the
dashboard is shared on all IPv4 interfaces while the API stays behind its
loopback proxy. The API is not exposed to the network directly, and any
deployment that puts it beyond loopback must terminate TLS in front of it.

**Response headers.** `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cross-Origin-Opener-Policy: same-origin`, a restrictive `Permissions-Policy`
and `Cache-Control: no-store` on every response. `Strict-Transport-Security`
is added on HTTPS requests.

**Error handling.** Errors return a structured envelope with `detail`,
`statusCode` and `requestId`. Validation errors add field-level `errors`.
Unhandled exceptions return a generic message; stack traces and internal
detail never reach the client.

**Input limits.** Every ingestion path has an explicit size, count and time
limit, and the limits are enforced before work starts. Symbolic links are not
followed.

**Known gaps.** No account lockout, no secret rotation story, no encrypted
storage for scan artefacts, no malware scanning of uploads. The optional
per-IP rate limiter is a congestion control, not an identity boundary.
Treat a shared token as a control for a trusted local network, not as a
substitute for an identity provider.

## 6. Database maintenance

The schema migrates itself on start-up and the migration is additive and
idempotent, so upgrading the code is enough. Operational indexes are created
with `CREATE INDEX IF NOT EXISTS` on every start.

Backups, health checks and compaction are provided by
`scripts/db_admin.py`, which uses the SQLite online-backup API and is safe
against a running API:

```sh
python scripts/db_admin.py stats                    # size, journal mode, row counts, FK check
python scripts/db_admin.py backup --output work/backups/ecdat-weekly.db
python scripts/db_admin.py vacuum                   # checkpoint the WAL and compact
```

The `audit_events` table is the record to preserve longest — include it in
every backup. Restoring is a file copy of a backup over the live database
while the API is stopped. `db_admin` supports SQLite only; `DATABASE_URL`
must be a `sqlite:///` URL.

## 7. Maintaining the standards registry

The registry (`backend/knowledge/standards_registry.json`) is policy data and
is reviewed by humans.

**Changing an entry.** Edit the entry, bump `registryVersion`, update
`reviewedOn`, then validate:

```sh
python scripts/validate_registry.py
```

The validator reports missing required fields, unknown families or actions,
duplicate entry ids, aliases claimed by two entries, migration paths with no
roles, dangling candidate references and unknown candidate fits. The same
check runs in CI and as `backend/tests/test_standards_registry.py`.

**Adding a migration path.** Declare the path id, its `roles` and its
candidates with an explicit `fit` from `preferred`, `transition`,
`acceptable-alternative`, `alternative`, `tracked-future` or
`cnsa-preferred`. Candidates are ranked by fit.

**Adding a detection signal.** Edit
`backend/scanners/source/signals.yaml`, add the algorithm to the registry,
and extend `backend/tests/test_detection_coverage.py` with the positive
fixture and the false-positive trap.

## 8. Running the tests

```sh
python -m pytest -q          # backend
cd frontend && npm test      # frontend unit tests
cd frontend && npm run build # type check and production build
```

The backend suite uses a temporary database and worker state directory.
`ECDAT_TEST_DATABASE_URL`, if set, must point at dedicated test data only.

## 9. Continuous integration

| Workflow | What it does |
| --- | --- |
| `.github/workflows/ci.yml` | Registry policy check, backend suite on Windows and Linux across Python 3.10 and 3.12, frontend unit tests and production build, and a headless scan whose CBOM is validated against the official CycloneDX 1.6 schema |
| `.github/workflows/compatibility.yml` | Windows batch setup, launcher tests, build, LAN smoke check and log capture |

Both run on pushes to `main` and `feature/**` and on pull requests. Other
repositories can run ECDAT as a CI step through the composite action in
[action.yml](../action.yml), which produces `cbom.json` and `results.sarif`
artifacts and can fail the job on Critical findings.
[Dependabot](../../.github/dependabot.yml) opens weekly updates for the pip
and npm ecosystems and monthly updates for the pinned GitHub Actions, so a
dependency fix does not wait for a manual review cycle. A committed
[openapi.json](../openapi.json) is checked against the generated schema by
`test_committed_openapi_contract_matches_application`, so the API contract
cannot drift from the code without a deliberate regeneration.
