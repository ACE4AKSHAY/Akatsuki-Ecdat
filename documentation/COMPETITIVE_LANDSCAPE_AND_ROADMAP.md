# ECDAT competitive landscape and upgrade roadmap

A research-based comparison of ECDAT against the open-source and commercial
cryptographic-discovery tools in the same space, the concrete gaps between
them, and a phased plan to close those gaps while sharpening what makes ECDAT
distinct. Researched November 2026.

## 1. The landscape

Cryptographic-inventory tooling falls into three groups, and no single tool
covers all of them:

| Group | What it sees | Tools |
| --- | --- | --- |
| Code and artefact scanners | Crypto API usage in source, containers, manifests | CBOMkit / sonar-cryptography, cdxgen, cryptobom-forge, ECDAT |
| Network scanners | Protocols, cipher suites and certificates services actually negotiate | testssl.sh, SSLyze, Nmap `ssl-enum-ciphers`, ssh-audit, pqaudit, AC-Scanner |
| Governance / BOM utilities | Validation, merge, diff, signing, policy, history | CycloneDX CLI, IntelliXBOM-class platforms |

### Open-source competitors

**CBOMkit (IBM Research, donated to the Post-Quantum Cryptography Alliance /
Linux Foundation, June 2025).** Five components: the
`sonar-cryptography` SonarQube plugin (CBOMkit-hyperion) detecting crypto API
usage in Java (JCA + Bouncy Castle), Python (pyca/cryptography) and Go, with
C# in development; `cbomkit-lib` to run the engine without a SonarQube
server; `cbomkit-action`, a GitHub Action for CI; `cbomkit-theia`, a scanner
for certificates, keys, secrets and config files in container images and
directories; and the `cbomkit` application that stores, visualises and
evaluates CBOMs against policy. Apache 2.0.

**cdxgen (OWASP).** The dominant SBOM generator now emits CBOM through a
`cbom` alias / `--include-crypto`: Java keystores and certificates, plus
source-level algorithm inventory for JavaScript and TypeScript. Defaults to
CycloneDX 1.7.

**cryptobom-forge (Santander Security Research).** Converts GitHub CodeQL
multi-repo analysis output (SARIF) into a CycloneDX CBOM, with rules-based
checks for weak algorithms and modes. GPL-3.0. Its leverage is CodeQL's deep
dataflow analysis across many repositories at once.

**Network scanners.** testssl.sh (TLS/SSL protocols, ciphers, flaws, JSON
output), SSLyze (JSON with a published schema, Mozilla baseline checks), Nmap
`ssl-enum-ciphers`, ssh-audit (SSH KEX/host-key/MAC algorithms, policy
audits). None emit CBOM directly; their output must be mapped. Newer 2026
projects close that gap: `qubitac/AC-Scanner` (TLS & SSH PQC scanner emitting
a CBOM aligned to NIST IR 8547) and `pqaudit` (scores TLS endpoints against
NIST IR 8547, CNSA 2.0 and FIPS 140-3).

**Crypto misuse detectors (academic line).** CryptoGuard, CogniCrypt
(CrySL rules) and CryptoLint perform deep static/dataflow analysis for
cryptographic API misuse — hardcoded keys, weak randomness, predictable IVs,
constant comparisons. They complement inventory scanners with misuse
detection, and recent work evaluates LLMs for the same task.

### Commercial vendors

IBM Quantum Safe, SandboxAQ (Cryptosense/AQtives), Keyfactor, Venafi,
Tychon CryptoIQ (eBPF endpoint sensors), InfoSec Global AgileSec (network and
endpoint sensors), Quantum Xchange (network appliances), Black Duck, JFrog
Xray, Cybeats SBOM Studio. Governance platforms such as IntelliXBOM
ingest CBOMs from open-source scanners and add policy, history, diffs and
compliance evidence — and notably target Indian regulatory frameworks
(CERT-In, RBI, SEBI, MeitY).

### Standards context

CycloneDX 1.6 (April 2024) introduced CBOM and was published as ECMA TR/115;
CycloneDX 1.7 (October 2025) expands the crypto model —
`relatedCryptoMaterial` for keys and tokens, protocol `cipherSuites`, and
more. NIST IR 8547 defines the algorithm transition posture, CNSA 2.0 the
national-security timeline, and NIST SP 1800-38 plus CISA's quantum-readiness
guidance make cryptographic discovery the mandated first step of every PQC
programme.

## 2. What ECDAT already has that others do not

ECDAT's differentiators are real and worth protecting:

- **A migration strategy engine, not just an inventory.** Every asset gets an
  action, a phase, ranked candidates with fit/maturity/latency/cost, blockers,
  assumptions and a numbered playbook with roles, evidence gates and rollback
  steps. CBOMkit and cryptobom-forge stop at "this asset is quantum
  vulnerable".
- **A versioned, human-reviewed policy registry** with four independent
  assessment axes (classical, quantum, standards maturity, usage context),
  validated in CI. Competitors hard-code their mappings.
- **Operational risk modelling**: Mosca's inequality with an interactive Z
  slider, composite scoring, readiness tiers and HNDL exposure.
- **Audited operator override** of inferred context — reconciliation between
  automated inference and human knowledge, with a trail.
- **A complete local-first product**: dashboard, reports (PDF/CSV/XLSX/CBOM),
  history, LAN sharing, no SonarQube or external server dependency.

## 3. What competitors have that ECDAT lacks

Prioritised by how much they matter to real PQC-migration programmes.

| # | Gap | Who has it | Why it matters |
| --- | --- | --- | --- |
| 1 | **Live network/TLS discovery** — negotiated protocols, suites and certificates of running services | testssl.sh, SSLyze, ssh-audit, AC-Scanner, pqaudit; commercial network sensors | Static config shows intent; the wire shows reality. CISA's pilot guidance treats network discovery as a mandatory inventory lane |
| 2 | **CI-native delivery** — GitHub Action, CLI-first mode, SARIF output | cbomkit-action, cryptobom-forge (CodeQL SARIF) | Inventory that is not in the pipeline goes stale; SARIF is the lingua franca of code-scanning integrations |
| 3 | **Misuse-level analysis** — hardcoded keys, weak randomness (`java.util.Random`, `Math.random`), IV/nonce reuse, constant-time comparison gaps | CryptoGuard, CogniCrypt, CodeQL rules | Inventory scanners answer "what is used"; misuse detectors answer "is it used correctly". The highest-severity findings live here |
| 4 | **Keys and secrets as first-class assets** (`relatedCryptoMaterial`: keys, tokens, secrets in repos/images) | cbomkit-theia, cdxgen (keystores), CycloneDX 1.7 model | A CBOM without the key material it protects understates exposure; hardcoded keys are a top finding of first inventories |
| 5 | **CBOM validation, diffing and signing** against the official schema | CycloneDX CLI; IntelliXBOM-class governance | Trust and drift: prove a CBOM is schema-valid, compare scans, sign releases |
| 6 | **CycloneDX 1.7** export | cdxgen, newer scanners | The spec is moving; expanded crypto fields land in 1.7 |
| 7 | **CVE / vulnerability correlation** per crypto library version | Black Duck, JFrog Xray; Trivy integration | "OpenSSL 3.0.12 present" is far more actionable with the CVE list attached |
| 8 | **Multi-repository / organisation-scale scanning** with fleet summary | cryptobom-forge (CodeQL multi-repo), commercial platforms | Enterprises scan hundreds of repos; per-scan dashboards do not aggregate |
| 9 | **Compliance-framework mapping** beyond NIST/CNSA — EU CRA, FIPS 140-3, CERT-In / RBI / SEBI / MeitY | IntelliXBOM-class platforms | Procurement and audit increasingly demand framework-shaped evidence; India-specific mapping is essentially unclaimed in open source |
| 10 | **Runtime/endpoint sensors** (eBPF tracing of OpenSSL calls) | Tychon, InfoSec Global | The most accurate inventory, at high operational cost — a roadmap item, not a near-term one |
| 11 | **HSM / KMS / cloud key inventory** | Venafi, Keyfactor, commercial | Usually needs API exports rather than scanning; long-term roadmap |

## 4. Upgrade plan

### Phase 1 — CI and interoperability (quick wins, weeks)

1. **SARIF export** in M9 alongside PDF/CSV/XLSX/JSON: findings and
   recommendations as SARIF 2.1.0 with level/taxonomy mapped from risk tier,
   so results appear in GitHub code scanning and any SARIF consumer.
2. **CLI-first scan mode and GitHub Action**: `ecdat-scan` already exists as
   a console entry point; extend it to run a full pipeline headlessly with
   CBOM/SARIF to stdout or files, then wrap it in an
   `ecdat-action` repository so CI runs produce CBOM + SARIF artifacts — the
   cbomkit-action pattern.
3. **CBOM schema validation**: validate the emitted document against the
   official CycloneDX 1.6 CBOM schema in CI (vendored schema, no runtime
   dependency), and keep the committed contract test pattern.
4. **CBOM diff / drift view**: store the previous CBOM per target and expose
   added/removed/changed assets between scans in the API and dashboard — the
   governance angle IntelliXBOM sells, as a built-in.

### Phase 2 — Network discovery lane (the biggest capability gap)

5. **M10 network scanner** that does not reinvent sensors: ingest the JSON
   output of testssl.sh, SSLyze and ssh-audit (all optionally installed), map
   negotiated protocols, cipher suites and certificates into CBOM protocol,
   algorithm and certificate assets, and merge them into the scan alongside
   M1–M3 findings.
6. **Configured-vs-negotiated reconciliation**: ECDAT already reads nginx and
   TLS config; once network results exist, flag drift (config says TLS 1.3,
   endpoint negotiates TLS 1.1) as its own finding class — no open-source
   tool does this reconciliation today.
7. **NIST IR 8547 transition posture**: add transition deadlines and
   disallowed-after dates for each algorithm family to the standards
   registry, and surface them in the roadmap (the AC-Scanner/pqaudit
   alignment).

### Phase 3 — Depth of analysis (credibility gap)

8. **Tier-3 misuse analysis** in the source scanner: hardcoded key/secret
   detection (entropy and naming heuristics emitting `relatedCryptoMaterial`
   key assets), weak randomness sources, ECB/IV anti-patterns beyond the
   call site. Dataflow-lite: resolve simple local variable chains before
   falling back to the line-level evidence model.
9. **CVE correlation**: map detected library + version (M2 already captures
   libraries) to OSV database records, and attach them to assets and
   reports.
10. **CycloneDX 1.7 export option** with `relatedCryptoMaterial` support,
    keeping 1.6 as the default until consumer tooling catches up.

### Phase 4 — Scale and compliance (enterprise posture)

11. **Multi-repository scanning**: accept a repository manifest (path list or
    CSV), queue one scan per target, and produce an organisation-level
    summary view that aggregates roadmaps and risk across scans.
12. **Compliance mapping module**: extend the registry with framework
    mappings — CERT-In directions, RBI/SEBI CSCRF expectations, MeitY PQC
    roadmap, EU CRA Annex I, FIPS 140-3 status — and render a
    framework-shaped report per scan. For an NTRO/SIH context this is the
    clearest differentiator: no open-source tool maps CBOM evidence to
    Indian regulatory frameworks.
13. **Longer-term**: eBPF runtime sensor (optional, Linux-only), HSM/KMS
    inventory via provider APIs, CBOM signing with hardware-rooted keys.

## 5. Where ECDAT should focus to stay unique

Competitors are converging on inventory + CBOM export. ECDAT should not race
them there; it should widen the lead in what comes *after* the inventory:

1. **Own the "so what" layer.** No open-source tool produces a phased,
   blocker-aware, role-assigned migration plan with rollback notes per asset.
   Keep deepening the strategy engine: effort estimation calibrated from
   observed evidence, ticket export (Jira/GitHub issues) from the roadmap,
   and per-playbook progress tracking.
2. **Own reconciliation.** The intersection of static discovery (M1–M3),
   network reality (Phase 2) and operator-confirmed context is a position no
   competitor occupies: one tool that says "your config claims X, your
   endpoint negotiates Y, your operator confirmed Z — here is the drift."
3. **Own the Indian compliance angle.** CERT-In / RBI / SEBI / MeitY mapping
   on top of a CBOM is essentially unclaimed in open source and directly
   relevant to the NTRO problem statement. It also generalises: the same
   mapping module serves EU CRA later.
4. **Stay dependency-light and local-first.** CBOMkit needs SonarQube;
   cryptobom-forge needs CodeQL. ECDAT runs from one Python process with
   optional external sensors — keep that as the deployment story, and make
   the "optional sensor" pattern (Trivy today, testssl.sh/ssh-audit next)
   the architecture signature.

## Sources

- [IBM/CBOM — Cryptography Bill of Materials toolset](https://github.com/IBM/CBOM)
- [Managing cryptography with CBOMkit — IBM Research](https://research.ibm.com/blog/quantum-safe-cbomkit)
- [IBM donates CBOM toolset to the Linux Foundation](https://research.ibm.com/blog/cryptographic-cbom-linux-foundation)
- [PQCA CBOMkit architecture](https://pqca.org/blog/2026/pqca-cbomkit-architecture/)
- [cbomkit/sonar-cryptography](https://github.com/cbomkit/sonar-cryptography)
- [Santandersecurityresearch/cryptobom-forge](https://github.com/Santandersecurityresearch/cryptobom-forge)
- [cdxgen/cdxgen](https://github.com/cdxgen/cdxgen)
- [CycloneDX CBOM capability](https://cyclonedx.org/capabilities/cbom/)
- [What's new in CycloneDX 1.7 — FOSSA](https://fossa.com/blog/whats-new-cyclone-dx-1-7/)
- [CBOM tools compared by discovery method — IntelliXBOM](https://intellixbom.com/resources/cbom/cbom-tools/)
- [Cryptographic Inventory Tools 2026 Survey — QNSQY](https://quantumsequrity.com/blog/crypto-inventory-tools)
- [qubitac/AC-Scanner — TLS/SSH PQC scanner emitting CBOM](https://github.com/qubitac/AC-Scanner)
- [pqaudit — TLS endpoint PQC scoring](https://lib.rs/crates/pqaudit)
- [CryptoGuard — high-precision crypto misuse detection](https://arxiv.org/html/1806.06881v5)
- [CISA — Strategy for migrating to automated PQC discovery and inventory tools](https://www.cisa.gov/resources-tools/resources/strategy-migrating-automated-post-quantum-cryptography-discovery-and-inventory-tools)
- [NIST IR 8547 — Transition to post-quantum cryptography standards](https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf)
- [Free quantum security tools — QRAMM](https://qramm.org/open-source-tools.html)
