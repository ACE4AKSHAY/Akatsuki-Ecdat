# ECDAT Cryptographic Asset Discovery

ECDAT is a local-first React dashboard and FastAPI pipeline that discovers cryptographic assets in source code, dependency manifests, lightweight binary evidence, infrastructure configuration, certificates, and container package inventories. It normalizes findings into a CycloneDX-aligned CBOM model, estimates migration urgency with Mosca's inequality, recommends migration actions, and exports reviewable reports.

## Current capability

- Scan a local file or directory through a bounded static snapshot.
- Clone and scan a public HTTPS Git repository from an allowed host.
- Upload one source file or a ZIP workspace up to 20 MB.
- Analyze a CycloneDX or Trivy JSON package inventory, or invoke an installed Trivy executable for a live image reference.
- Run the existing M1 source, M2 dependency and binary, and M3 infrastructure and certificate scanners through one orchestrated pipeline.
- Search, filter, paginate, inspect, and compare risk findings in the responsive dashboard.
- Explore alternative quantum threat timelines without overwriting the saved assessment.
- Export PDF, CSV, XLSX, and CycloneDX JSON reports.
- Recover queued or interrupted jobs after an API restart with the persisted single-process worker queue.

The scanner reads files statically and does not execute the target project's code.

## Run locally

Python 3.10 or newer, Node.js 22.12 or newer, and Git are required. Trivy is optional and is only needed when a live container image reference is scanned.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In another terminal, from the repository root:

```sh
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:3000. For the shortest demonstration, choose `Local path` and scan `demo/workspace`. Relative paths resolve from the backend working directory.

## Input modes

| Mode | Value to provide | Processing |
| --- | --- | --- |
| Local path | Existing file or directory | Copies ordinary files into a bounded temporary snapshot before scanning |
| Git repository | Public HTTPS repository URL | Performs a shallow clone from an allowed host and scans a bounded snapshot |
| File or ZIP upload | Source file or ZIP workspace | Stores the upload in the ECDAT state directory; ZIP extraction rejects traversal, links, and encrypted members |
| Image inventory | CycloneDX or Trivy JSON file, or live image reference | Reads package evidence offline or invokes `trivy image --format cyclonedx` when Trivy is installed |

Default allowed Git hosts are GitHub, GitLab, and Bitbucket. Configure a comma-separated replacement list with `ECDAT_GIT_HOSTS`.

## Demonstration data

- `demo/workspace` contains a small Python, Nginx, and dependency example.
- `demo/image-inventory.json` is an offline container package inventory.
- `scripts/demo_smoke.py` runs both fixtures through the API and downloads all report formats.

## Documentation

- [`documentation/ECDAT_Technical_Reference.docx`](documentation/ECDAT_Technical_Reference.docx) explains the objective, architecture, modules, dependencies, technology stack, current outcome, limitations, references, and future scope.
- [`documentation/ECDAT_Usage_and_Demo_Guide.docx`](documentation/ECDAT_Usage_and_Demo_Guide.docx) provides setup, usage, demonstration steps, sample inputs, expected results, and troubleshooting guidance.

With the API running:

```sh
.venv/bin/python scripts/demo_smoke.py
```

The verified review build found 10 assets with 3 Critical results in `demo/workspace`, 2 assets in the offline image inventory, and 51 assets in a scan of this public Git repository. Counts can change when detection rules or repository content change.

## Application workflow

1. Start a scan and watch the queued, running, completed, or failed state.
2. Review risk distribution and the latest scan summary on Overview.
3. Search inventory by algorithm, location, or classification and combine it with risk filters.
4. Open an asset to inspect its occurrence, risk inputs, score, and migration recommendation.
5. Change the Z timeline on Risk Heatmap to compare urgency assumptions.
6. Export PDF, CSV, XLSX, or CycloneDX JSON from Recommendations.
7. Reopen earlier results with the paginated scan history selector.

There are no implicit demo results. Missing targets are rejected, completed empty scans contain zero assets, and API errors are displayed with retry controls.

## Configuration

- `DATABASE_URL` defaults to `sqlite:///./ecdat.db`.
- `ECDAT_STATE_DIR` defaults to `.ecdat` and stores uploads, temporary ingestion state, and the worker lock.
- `ECDAT_API_TOKEN` enables bearer-token protection for every endpoint except `/health`.
- `ECDAT_CORS_ORIGINS` accepts a comma-separated origin list. Local development origins are allowed by default.
- `ECDAT_GIT_HOSTS` accepts a comma-separated HTTPS Git host allowlist.
- `API_PROXY_TARGET` sets the Vite development proxy target and defaults to `http://127.0.0.1:8000`.

The API documentation is available at http://127.0.0.1:8000/docs. Frontend requests use `/api/*`; Vite removes that prefix before proxying to FastAPI. A production deployment must serve `frontend/dist` and apply the same proxy behavior.

## Validation

```sh
.venv-runtime/bin/pytest -q
cd frontend
npm test
npm run build
```

The current review build passes 66 backend tests and 14 frontend tests, and produces a successful frontend production build. For isolated API test storage, set `DATABASE_URL=sqlite:////absolute/path/to/test.db` before running pytest.

## Security and operational boundaries

- Local workspaces and Git clones are capped at 100 MB and 10,000 regular files after dependency and output exclusions. Symbolic links are not followed.
- Uploads are capped at 20 MB. ZIP input is capped at 100 MB expanded size and 10,000 entries.
- Git ingestion accepts HTTPS URLs without embedded credentials, query strings, fragments, or nonstandard ports. Clones are shallow, noninteractive, and time out after 120 seconds.
- The included queue is durable across API restarts but intentionally permits one worker for each state directory. It is not a distributed job system.
- Optional token authentication is a shared bearer token. Enterprise user accounts, SSO, roles, and tenant isolation remain future work.

## Current limitations

- Live image scanning depends on an external Trivy installation and access to the selected image registry. This environment verified the offline image-inventory path; Docker was unavailable and Trivy was not installed for a live image test.
- Source scanning currently targets Python, Java, JavaScript, and Go. Binary inspection is based on strings and symbols rather than disassembly.
- Package and algorithm matches come from curated registries and static rules. Findings, risk values, and recommendations require human review and are not a compliance certification.
- The exporter uses CycloneDX 1.6 vocabulary, but formal schema interoperability should be validated before production integration.
- The heatmap recomputes a temporary Z scenario; exported reports retain the saved scan assessment.
- SQLite and the single-worker queue suit local review and a controlled demo. Production use needs an external database, distributed workers, stronger identity controls, observability, retention controls, and deployment hardening.

Changes are prepared on `improve/integration-ui` for local review. No remote push or merge is required to inspect them.
