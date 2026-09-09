# ECDAT Cryptographic Asset Discovery

ECDAT is a local React dashboard and FastAPI pipeline for discovering cryptographic assets in source code, dependency manifests, binary evidence, infrastructure configuration, certificates and container package inventories. It normalizes findings into a CycloneDX-aligned CBOM model, estimates migration urgency with Mosca's inequality, recommends review actions and exports reports.

## Start on Windows

Use the updated source package or a checkout containing `ecdat.bat`. Install **Python 3.10+ (3.12 recommended)**, **Node.js 22.12+ with npm**, and **Git 2.30+**. Extract the source into a writable folder, then double-click `ecdat.bat`:

1. Choose **2** to set up dependencies and build the frontend.
2. Choose **3** to run both services and open the dashboard.
3. Keep the window open; press Ctrl+C to stop the services.

For Command Prompt, from the repository root:

```bat
ecdat.bat setup
ecdat.bat check
ecdat.bat dev
```

In PowerShell use `.\ecdat.bat` instead. The menu also supports a built frontend preview, individual services, tests and manual command output. **[Full setup and run guide](documentation/SETUP_AND_RUN.md)** covers installation commands, versions, permissions, tokens, alternate ports and troubleshooting. No administrator session or PowerShell execution-policy change is required to run the project.

Default URLs are **http://127.0.0.1:3001/** for the dashboard and **http://127.0.0.1:8000/health** for API health. Vite now uses a fixed port and reports conflicts instead of silently moving to another port.

## Share on the local network

Choose **9** in `ecdat.bat` or run `ecdat.bat lan`. Open the printed `http://HOST_IPV4:3001/` link from another device on the same trusted network. Paste the printed token under **Workspace access token** and click **Connect**. LAN mode generates a token unless `ECDAT_API_TOKEN` is already configured. The API stays on loopback; only the dashboard port needs a Windows Private-profile firewall rule. See the [LAN setup and connection checks](documentation/SETUP_AND_RUN.md#share-with-other-devices-on-the-local-network).

## macOS and Linux

Use a supported Python interpreter; replace `python3.12` if your installed Python 3.10+ command differs:

```sh
python3.12 scripts/launcher.py setup
python3.12 scripts/launcher.py dev
```

Manual startup after setup, in separate terminals from the repository root:

```sh
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

```sh
cd frontend
npm run dev
```

On Windows the backend equivalent is `.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`; use `npm.cmd run dev` for the frontend. Do not copy a virtual environment or `node_modules` between computers.

## Current capability

- Scan a bounded snapshot of a local file/directory or a public HTTPS Git repository.
- Upload one source file or a ZIP workspace up to 20 MB.
- Read a CycloneDX or Trivy JSON package inventory; live image input additionally requires Trivy.
- Run source, dependency/binary, infrastructure and certificate discovery through one pipeline.
- Search and filter inventory, inspect asset evidence and review migration recommendations.
- Explore a temporary quantum threat timeline with years shown to at most two decimals and an explanation of X, Y and Z.
- Review a compact heatmap of counts by business criticality and risk tier; select a cell to inspect every grouped asset.
- Export PDF, CSV, XLSX and CycloneDX-aligned JSON using the saved assessment.
- Reopen history, delete the selected finished scan or delete all history after confirmation.
- Recover queued or interrupted jobs with a persisted single-worker queue and a cross-platform process lock.

Scanned project code is read statically and is not executed. Missing targets produce errors; completed empty scans contain zero assets.

## Demonstration

Choose **Local path** and scan `demo/workspace`. The supplied fixture produces **10 assets and 3 Critical findings** with the default assessment. `demo/image-inventory.json` is an offline container package example with **2 findings**. Relative paths resolve from the backend repository root.

With the API running:

```sh
.venv/bin/python scripts/demo_smoke.py --output work/demo-results
```

On Windows use `.venv\Scripts\python.exe scripts\demo_smoke.py --output work\demo-results`. Add `--git` to also scan this public repository. Git result counts depend on the current repository content.

History deletion removes saved scans, findings, recommendations, queued-job options and stored report data. Source files, uploaded input copies under `.ecdat/uploads` and reports already downloaded to disk are kept. Deletion cannot be undone. Queued/running scans cannot be deleted; deleting all is rejected while any scan is active.

## Configuration

| Setting | Purpose and default |
| --- | --- |
| `DATABASE_URL` | Database connection; defaults to `sqlite:///./ecdat.db` |
| `ECDAT_STATE_DIR` | Uploads, ingestion state and worker lock; defaults to `.ecdat` |
| `ECDAT_API_TOKEN` | Optional shared bearer token on every endpoint except `/health` |
| `ECDAT_CORS_ORIGINS` | Comma-separated allowed browser origins |
| `ECDAT_GIT_HOSTS` | HTTPS Git host allowlist; GitHub, GitLab and Bitbucket by default |
| `API_PROXY_TARGET` | Vite API target; defaults to `http://127.0.0.1:8000` |

The launcher accepts `--api-port` and `--ui-port`, configures the proxy, checks readiness and writes logs to `.ecdat/logs`. Example: `ecdat.bat dev --api-port 8010 --ui-port 3010`. Default modes bind to loopback. `lan` shares the built dashboard on all IPv4 interfaces while the API remains behind its loopback proxy. Local preview is for reviewing a built bundle, not a production hosting system.

API documentation is at http://127.0.0.1:8000/docs. Frontend `/api/*` requests are proxied to FastAPI with the `/api` prefix removed. Production hosting needs equivalent proxy behavior. Token protection also applies to API documentation and deletion endpoints.

## Validation

```bat
ecdat.bat test
```

Or run `.venv/bin/python scripts/launcher.py test` on macOS/Linux. The individual checks are `.venv/bin/pytest -q`, `npm test` and `npm run build` (the npm commands run in `frontend`). Pytest uses a temporary database and worker state directory. An optional `ECDAT_TEST_DATABASE_URL` must point only to dedicated test data.

The update passes **83 backend tests and 23 frontend tests**, plus a production build. Browser validation covers desktop/mobile heatmap behavior, history deletion and core scan/export flows. The launcher was exercised through a fresh local installation in a path containing spaces on macOS; the new [compatibility workflow](.github/workflows/compatibility.yml) checks Windows batch setup, tests, build, LAN proxy and shutdown. Check the Actions result for your revision. A second device on your network must still verify firewall/router reachability.

The [test and sample-data map](documentation/TEST_DATA.md) identifies automated tests, demonstration inputs and all four self-signed certificate fixtures. Certificate fixtures are scanner inputs; do not install them as trusted roots or use them for dashboard HTTPS.

## Documentation

- [Test code and sample inputs](documentation/TEST_DATA.md): test suites, demonstration files and certificate properties.
- [Setup and run guide](documentation/SETUP_AND_RUN.md): Windows commands, launcher menu, requirements, permissions, usage and troubleshooting.
- [Technical reference](documentation/ECDAT_Technical_Reference.docx): objective, architecture, modules, stack, implementation boundaries and future scope.
- [Usage and demo guide](documentation/ECDAT_Usage_and_Demo_Guide.docx): installation, operation, sample data and demonstration steps.

## Boundaries and remaining limitations

Local/Git snapshots are limited to 100 MB and 10,000 files after dependency/output exclusions. Uploads are limited to 20 MB; ZIP expanded content is limited to 100 MB and 10,000 entries. Symbolic links are not followed. HTTPS Git inputs are allowlisted, shallow and noninteractive, with a 120-second clone limit.

Source AST scanning currently targets Python, Java, JavaScript and Go. Binary inspection uses strings and optional symbols, with a pure-Python strings fallback when native tools are absent. Rules and package registries are curated, and all findings and migration recommendations require human review.

Live image scanning requires an external Trivy installation and registry access; the offline JSON route is verified, but live Trivy scans remain unverified here. The exporter uses CycloneDX 1.6 vocabulary; formal interoperability needs dedicated validation. SQLite, a single worker and an optional shared token support local review. Distributed workers, enterprise identity, tenant isolation, managed deployment and stronger operational controls remain future work.
