<p align="center">
  <img src="firedamp_banner.svg" alt="Firedamp Banner" width="100%" />
</p>

<p align="center">
  <strong>Behavioral security regression and cross-tenant isolation testing framework for RAG & AI platforms.</strong>
</p>

<p align="center">
  <a href="wiki/Home.md">📖 Wiki Home</a> •
  <a href="wiki/Quickstart.md">⚡ Quickstart</a> •
  <a href="wiki/CLI-Reference.md">💻 CLI Reference</a> •
  <a href="wiki/CVE-Regression-Engine.md">🛡️ CVE Engine</a> •
  <a href="wiki/API-Authorization-Matrix.md">🧭 Auth Matrix</a> •
  <a href="wiki/Version-Ladder-Benchmark.md">📊 Version Ladder</a> •
  <a href="tests/integration/openwebui_cve_2026_28788/README.md">🧪 Integration Lab</a>
</p>

---

```text
                       .---.
                      /     \
                     | () () |    "If the canary falls silent,
                      \  ^  /      there is gas in the shaft."
                       |||||
                     /       \
                    |  CLEAR  |   --> No leaks detected in tested channels.
                    \_________/
```

Named after **firedamp**—the combustible gas historically detected using caged canaries in coal mines—**Firedamp** evaluates cross-tenant data isolation, authorization boundaries, and security regression resistance in Retrieval-Augmented Generation (RAG) platforms.

---

## 1. What Firedamp Does

In multi-tenant AI and RAG platforms (such as Open WebUI), documents and vector embeddings can cross tenant boundaries due to missing endpoint authorization, role or prefix validation flaws, or unescaped query filters.

Firedamp automates non-weaponized behavioral security testing across the retrieval and ingestion lifecycle:
1. **Plants High-Entropy Canaries**: Seeds verifiable synthetic canary tokens (`CANARY-FRDP-...`) into a data owner's private scope (**Alice**).
2. **Executes Adversarial Probes**: Fires unprivileged retrieval queries, direct API calls, and mutation requests as an unauthorized tenant (**Bob**).
3. **Classifies Telemetry**: Detects token bleed in chat completions, citation metadata, or direct vector responses, producing a deterministic verdict (`CLEAN`, `COMPROMISED`, or fail-closed `INCONCLUSIVE`) and a composite **Firedamp Index** (0.0 to 100.0).

---

## 2. Architecture & Probing Channels

```text
                          ┌──────────────────────────────────────────────┐
                          │                Firedamp CLI                  │
                          └──────────────────────┬───────────────────────┘
                                                 │
                                                 ▼
                          ┌──────────────────────────────────────────────┐
                          │               Orchestration                  │
                          │     (Session Management & Safe Airway)       │
                          └──────────────────────┬───────────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
              ┌───────────────────┐                             ┌───────────────────┐
              │   Alice Session   │                             │    Bob Session    │
              │  (Tenant / Owner) │                             │ (Untrusted Prober)│
              └─────────┬─────────┘                             └─────────┬─────────┘
                        │                                                 │
              Indexes Canary Documents                                 Dispatches
              CANARY-FRDP-<UUID>-<HASH>                            Multi-Channel Probes
                        │                                                 │
                        ▼                                                 ▼
             ┌───────────────────────────────────────────────────────────────────────┐
             │                         Target RAG Platform                           │
             │        (Open WebUI REST APIs, Vector DB, Knowledge Collections)       │
             └───────────────────────────────────┬───────────────────────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────┐
                                │     Probing & Leak Engine       │
                                │   (Exact Matcher & Substring    │
                                │    Entropy Context Inspector)   │
                                └────────────────┬────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────┐
                                │         Reporter & Score        │
                                │   [Clear] vs. [Gas Detected]    │
                                └─────────────────────────────────┘
```

Firedamp evaluates cross-tenant boundaries across six transmission channels:
- `direct_api`: Direct REST/RPC calls without prompt orchestration.
- `llm_prompt`: Adversarial semantic prompts targeting context bleed.
- `citation_metadata`: Document references, chunk headers, and citation sources.
- `write_mutation`: Cross-user batch mutation and file overwrites.
- `vector_payload`: Direct vector database filter and collection parameter queries.
- `lifecycle_event`: Temporal permission changes (sharing $\rightarrow$ revocation $\rightarrow$ verification).

---

## 3. Curated CVE Coverage

Firedamp maintains an audited 21-entry CVE catalog classified into three verified categories ([CVE_AUDIT.md](CVE_AUDIT.md)):

- **4 Executable Tier-1 Probes (Automated)**:
  - **`CVE-2026-44560`** (*Open WebUI <= 0.8.12, fixed in 0.9.0*): Direct collection vector retrieval authorization bypass in RAG chat completions (`POST /api/chat/completions`) via predictable collection identifiers (`file-<id>`). Application-layer authorization bypass; backend-agnostic.
  - **`CVE-2026-45398`** (*Open WebUI <= 0.9.4, fixed in 0.9.5*): Knowledge base raw UUID prefix validation bypass in collection retrieval routes (`POST /api/v1/retrieval/query/collection` and `POST /api/v1/retrieval/query/doc`) via `_validate_collection_access()`. Application-layer authorization bypass; backend-agnostic.
  - **`CVE-2026-28788`** (*Open WebUI < 0.8.6, fixed in 0.8.6*): Cross-user batch file overwrite in ingestion (`POST /api/v1/retrieval/process/files/batch`) due to missing server-side file ownership checks. Application-layer write-mutation flaw.
  - **`CVE-2026-54019`** (*Open WebUI < 0.9.6, fixed in 0.9.6*): Vector store query interpolation flaw when deployed with the Milvus multitenancy backend (`precondition: milvus_multitenancy`). Unescaped `resource_id` string concatenation allows boolean-true filter injection (`x' or resource_id != '' or resource_id == 'x`).
- **7 Documented Vulnerabilities**: Authoritatively tracked for catalog completeness without executable probe implementations in this repository (`CVE-2026-45301`, `CVE-2026-44557`, `CVE-2026-54016`, `CVE-2026-54010`, `CVE-2026-45349`, `CVE-2026-44561`, `CVE-2024-31621`).
- **10 Quarantined Historical Misattributions**: Third-party packages erroneously linked to RAG products in public databases, forensically quarantined in [`CVE_AUDIT.md`](CVE_AUDIT.md) (`CVE-2024-52306`, `CVE-2024-52307`, `CVE-2024-41133`, `CVE-2024-43407`, `CVE-2024-52308`, `CVE-2024-45388`, `CVE-2024-45389`, `CVE-2024-42475`, `CVE-2024-45391`, `CVE-2024-34359`).

Detailed technical specifications, bug classes, and references are documented in [wiki/CVE-Regression-Engine.md](wiki/CVE-Regression-Engine.md).

---

## 4. Empirical Validation & Differentiation

Firedamp strictly separates verification tiers to ensure reproducibility and prevent misleading claims:

1. **Unit Test Suite**: 267 tests verifying AST logic, canary generation, policy gates, adapters, and scoring without network access.
2. **Offline Simulation Harness**: 115 tests in `tests/integration/openwebui_cve_2026_28788/simulations/` evaluating verdict classification, evidence sanitization, and lab safety rules against mock HTTP payloads.
3. **Simulated Version Ladder Benchmark**: Evaluates detection accuracy across 5 Open WebUI release milestones (`v0.8.5` through `v0.9.6`) using deterministic in-memory simulation (`python3 tests/benchmark_ladder.py`). Zero false positives were observed in the modeled benchmark scenarios (this is an observation within the simulation and not a universal guarantee for real deployments).
4. **Live Docker Differential Validation (CVE-2026-28788)**: Real container differential execution against pinned upstream Open WebUI images:
   - **Open WebUI v0.8.5** (`COMPROMISED`): Unauthorized cross-user batch overwrite succeeded; Bob mutated Alice's file.
   - **Open WebUI v0.8.6** (`CLEAN`): Ownership check enforced; returned per-file `Permission denied: not file owner` in JSON `errors` (HTTP 200). Alice's content and SHA-256 digest remained unaltered.

*Note on Cleanup Limitations*: Targeted post-probe cleanup for write-mutation probes uses best-effort file content restoration and vector deletion (`RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED`). Content restoration, membership verification, and exhaustive vector cleanup are separate properties: the recorded reset evidence indicates `preserved_other_file_count: 0` and `verified_vector_cleanup: false`. Public top-k retrieval verified the absence of tracer tokens in nearest-neighbor lookups, but cannot prove exhaustive absence across the global embedding store.

---

## 5. Quickstart

### Prerequisites
- Python 3.10, 3.11, or 3.12.
- Git.
- Docker Engine (optional; only required for live container lab execution).

### Installation

#### Transparent Setup from Source (Recommended)
```bash
# 1. Clone the repository
git clone https://github.com/pr60t/firedamp.git
cd firedamp

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies in editable mode
pip install -e ".[dev]"

# 4. Verify CLI setup
firedamp --help
```

#### Optional Local Installer Script
For unattended local workstation setup, you can inspect and execute the safety-tested local installer:
```bash
bash install.sh
```
*(The installer validates Python 3.10+, enforces strict no-clobber staging, and never overwrites pre-existing user directories).*

### Run Instant Simulation (Dry-Run Mode)
```bash
firedamp scan --dry-run
```

---

## 6. CLI Overview

The `firedamp` CLI provides commands for scanning, target discovery, and version checking:

| Command | Description |
| :--- | :--- |
| `firedamp scan [OPTIONS]` | Executes isolation scans, CVE regression probes, and authorization matrix replays. |
| `firedamp list-targets` | Lists supported and planned target adapters. |
| `firedamp version` | Displays version and sensor status. |

### Key `firedamp scan` Options
- `-t, --target <str>`: Target platform adapter name (default: `openwebui`).
- `-u, --target-url <str>`: URL of an existing deployment (e.g. `http://localhost:8080`).
- `-v, --version <str>`: Container image tag for ephemeral Docker runs (default: `latest`).
- `-n, --canaries <int>`: Number of canary documents to plant (default: `4`).
- `-o, --output <str>`: Path to export audit report.
- `-f, --format <str>`: Audit report format: `json`, `markdown`, or `sarif` (default: `json`).
- `--fail-on-leak`: Exit code 1 if a canary leak is detected.
- `--dry-run`: Run simulated scan without network or Docker containers.
- `--cpu-only`: Run Docker target container without GPU/Ollama dependencies.
- `-s, --suite <str>`: Probing suite: `default`, `cve-regression`, `auth-matrix`, `lifecycle`, `write-poisoning`, `agent-memory`, `all` (default: `default`).
- `-sc, --scenario <str>`: Targeted attack scenario: `lifecycle`, `write-poisoning`, `agent-memory`.
- `-p, --policy <str>`: Path to declarative YAML policy file.
- `-db, --vector-db <str>`: Target vector database backend: `chroma`, `milvus`, `qdrant` (default: `chroma`).
- `-m, --multitenancy <str>`: Multitenancy architecture mode: `shared`, `isolated` (default: `shared`).

Full CLI usage instructions and recipe examples are available in [wiki/CLI-Reference.md](wiki/CLI-Reference.md) and [wiki/Use-Cases-&-Recipes.md](wiki/Use-Cases-&-Recipes.md).

---

## 7. API Authorization Matrix (RAG Autorize)

Firedamp implements multi-persona request capture and replay to detect broken object-level authorization across RAG APIs:
- Replays legitimate owner requests across 4 personas: **`Owner`** (Alice), **`Intruder`** (Bob), **`Ex-Member`** (Revoked), and **`Anonymous`** (Unauthenticated).
- Compares responses using **Structural Key Diffing (Jaccard Index)** and **Canary Matching** to detect leaks even behind soft HTTP 200 wrappers.
- For complete details, see [wiki/API-Authorization-Matrix.md](wiki/API-Authorization-Matrix.md).

---

## 8. Telemetry & Scoring

Audit results are summarized in the **Firedamp Index** (0.0 to 100.0), a composite metric calculated from:
- **Exfiltration Ratio (40%)**: Fraction of executed probes that retrieved sensitive data.
- **Canary Penetration (40%)**: Fraction of planted canary documents compromised.
- **Leak Severity Weight (20%)**: Weighted penalty for direct leaks (`DIRECT_LEAK`) versus contextual fragments (`CONTEXT_LEAK`).

An index of `0.0` represents a clean atmosphere (`AIRWAY SAFE`). Any score `> 0.0` indicates detected gas (`GAS DETECTED`). Detailed metric definitions are in [wiki/Understanding-Telemetry.md](wiki/Understanding-Telemetry.md).

---

## 9. Safe Integration Lab (CVE-2026-28788)

The repository provides an isolated differential lab harness in [`tests/integration/openwebui_cve_2026_28788/`](tests/integration/openwebui_cve_2026_28788/):
- **Pinned Loopback Ports**: `127.0.0.1:13085` (`v0.8.5`) and `127.0.0.1:13086` (`v0.8.6`).
- **Disposable Registry**: All write mutations require registration in `_TRUSTED_SCAN_REGISTRY` before execution.
- **Automated Evidence Sanitization**: Pipeline scrubs tokens, keys, hostnames, and local paths into sanitized bundles.

> [!CAUTION]
> Never execute write-poisoning or destructive probes against production deployments. Use dedicated, disposable local instances.

---

## 10. Repository Structure

```text
.
├── core/                # Canary generation, reporter, policy, & authorization matrix
│   ├── engine.py        # Cryptographic canary engine & zero-VRAM matcher
│   ├── matrix.py        # Read-only authorization matrix replay runner
│   ├── policy.py        # Declarative Policy-as-Code evaluator
│   ├── reporter.py      # Telemetry rendering, Firedamp Index & exports
│   └── target.py        # Remote and Docker target managers
├── adapters/            # Target platform drivers
│   ├── base.py          # TargetAdapter abstract protocol & registry
│   └── openwebui/       # Modular Open WebUI driver (auth, ingest, query, lifecycle)
├── probes/              # Behavioral regression suites & registries
│   ├── schemas/         # BugClass & ProbeChannel taxonomies
│   ├── scenarios/       # Lifecycle, write-poisoning, and agent memory scenarios
│   ├── cves/            # Tier-1 CVE fixtures (CVE-2026-44560, 45398, 28788, 54019)
│   ├── cve_registry.py  # Catalog loader and query engine
│   ├── disposable_registry.py  # Trusted scan disposable resource tracker
│   └── knowledge_membership.py # Shared paginated file-to-KB resolver
├── tests/               # Unit test suites & version ladder benchmark
│   └── integration/     # CVE-2026-28788 integration lab and offline simulations
├── wiki/                # Technical guides and architecture documentation
├── cli.py               # Command-line interface entrypoint
├── pyproject.toml       # PEP 621 package metadata & dependencies
├── CVE_AUDIT.md         # Authoritative 21-CVE forensic catalog audit
├── FINAL_AUDIT.md       # Repository audit findings and status register
└── README.md            # Project overview and reference manual
```

---

## 11. Documentation & Wiki Index

For in-depth guides and specifications, refer to the project wiki:
- [Home](wiki/Home.md): Project overview and portal.
- [Quickstart](wiki/Quickstart.md): Step-by-step setup and first scan.
- [CLI Reference](wiki/CLI-Reference.md): Complete options, flags, and usage guide.
- [CVE Regression Engine](wiki/CVE-Regression-Engine.md): Bug taxonomy, Tier-1 probes, and catalog.
- [API Authorization Matrix](wiki/API-Authorization-Matrix.md): Structural diffing and multi-persona replay.
- [Use Cases & Recipes](wiki/Use-Cases-&-Recipes.md): Practical commands for CI/CD and staging.
- [Version Ladder Benchmark](wiki/Version-Ladder-Benchmark.md): Simulated benchmark methodology and metrics.
- [Understanding Telemetry](wiki/Understanding-Telemetry.md): Scoring formulas and report formats.

---

## 12. License & Attribution

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

Firedamp was created to protect multi-tenant AI environments by detecting boundary leaks before they result in data breaches.
