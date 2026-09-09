# Test code and sample scan inputs

ECDAT includes automated tests and deliberately chosen scanner inputs. The test inputs demonstrate detection behavior; they are not application dependencies, production cryptography, or certificates for hosting the dashboard.

## Automated checks

| Location | Purpose |
| --- | --- |
| `backend/tests/test_*.py` | Source, dependency, binary, infrastructure, certificate and seed-corpus scanner tests. |
| `tests/test_*.py` | API integration, normalization, risk, reports, ingestion, worker ownership, history deletion and launcher checks. |
| `frontend/src/api.test.ts` | API mapping, pagination and risk calculations used by the dashboard. |
| `frontend/src/heatmap.test.ts` | Decimal formatting, Windows path labels and complete heatmap grouping. |
| `conftest.py` | Gives the main pytest suite a temporary database and state directory, separate from normal scan history. |
| `tests/launcher_smoke.py` | Explicit process test after setup: LAN page, API proxy, token, scan, exports, deletion and service shutdown. |
| `.github/workflows/compatibility.yml` | Runs setup, tests, build and the process smoke check on Windows and Linux. Windows setup/tests use the actual batch file, from a checkout path containing spaces. |
| `ecdat/tests/` | Tests for the earlier standalone module package. They are outside the default integrated application's pytest test paths. |

Run `ecdat.bat test` on Windows, or `.venv/bin/python scripts/launcher.py test` on macOS/Linux. To run only the certificate rules on Windows: `.venv\Scripts\python.exe -m pytest backend\tests\test_infra_certs.py -q`. Run the additional process check with `.venv\Scripts\python.exe tests\launcher_smoke.py` after setup. It uses temporary storage and dynamically selected ports.

## Sample inputs

| File or directory | What to demonstrate |
| --- | --- |
| `demo/workspace/crypto_example.py` | Small source-code cryptography example for the basic demo. |
| `demo/workspace/nginx.conf` | Legacy TLS configuration example. |
| `demo/workspace/requirements.txt` | A dependency manifest to scan; do not install its packages to run ECDAT. Install the repository-root `requirements.txt` instead. |
| `demo/image-inventory.json` | Synthetic offline container/package inventory; it is not evidence from a live image scan. |
| `seed_corpus/python/`, `java/`, `javascript/`, `go/` | Positive source findings and false-positive traps (`fp_trap` / `FPTrap`) for scanner validation. |
| `seed_corpus/manifests/` | Sample Python, npm, Maven and Go dependency manifests. These are scanner inputs, not setup instructions. |
| `seed_corpus/configs/` and `seed_corpus/iac/` | Legacy/modern nginx TLS settings, Terraform and Dockerfile input examples. |
| `seed_corpus/binary/openssl_v1_0_2_strings.txt` | Text containing binary-style version/symbol evidence; not an executable binary. |
| `seed_corpus/certs/` | Four X.509 certificate fixtures described below. |

For the simplest demonstration, scan `demo/workspace` (10 assets, 3 Critical findings with defaults). Scan `seed_corpus` for broader coverage. Use File or ZIP upload to select files on a client device; Local path always refers to the computer running the backend. Source examples are read statically; there is no need to execute them.

## Certificate fixtures

All four files contain public self-signed certificates. Their names describe test properties, not a production trust recommendation. The certificate scanner's rules are tested in `backend/tests/test_infra_certs.py`.

| Certificate under `seed_corpus/certs/` | Encoded properties | Expected rule behavior |
| --- | --- | --- |
| `good_rsa2048.pem` | RSA 2048, SHA-256 signature, 365-day validity | Comparison fixture: no small-key, weak-signature or long-validity flags; self-signed may still be flagged. |
| `small_rsa1024.pem` | RSA 1024, SHA-256 signature, 365-day validity | Detect the undersized RSA key. |
| `sha1_signed.pem` | RSA 2048, SHA-1 signature, 365-day validity | Detect the weak SHA-1 signature. |
| `long_validity.pem` | RSA 2048, SHA-256 signature, 3650-day validity | Detect the excessive validity interval. |

To demonstrate one certificate, choose Local path and enter `seed_corpus/certs/small_rsa1024.pem`, or upload that PEM file. Review the detected primitive, evidence and recommendation. Other rules such as self-signed detection can also contribute findings.

Do not import these fixtures into Windows Trusted Root Certification Authorities, use them to configure server TLS, or treat the `good` filename as an assertion of present-day trust or validity. Local and LAN demonstration modes use HTTP. An HTTPS deployment needs a separate certificate issued for the actual server name and a TLS-terminating reverse proxy.
