<p align="center">
  <img src="firedamp_banner.svg" alt="Firedamp Banner" width="100%" />
</p>

<p align="center">
  <strong>Automated cross-tenant data leakage detection, boundary auditing, and vulnerability regression testing for RAG & AI platforms.</strong>
</p>

<p align="center">
  <a href="https://github.com/pr60t/firedamp/wiki">📖 Documentation Wiki</a> •
  <a href="#quickstart">⚡ Quickstart</a> •
  <a href="https://github.com/pr60t/firedamp/wiki/CVE-Regression-Engine">🛡️ CVE Engine</a> •
  <a href="https://github.com/pr60t/firedamp/wiki/CLI-Reference">💻 CLI Reference</a>
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

Named after **firedamp**—the odorless, explosive mine gas detected with caged canaries—**Firedamp** automatically catches cross-tenant data leakage and authorization failures in Retrieval-Augmented Generation (RAG) platforms before adversaries or auditors do.

### The Attack & Audit Cycle
1. **Plant:** Injects verifiable, high-entropy cryptographic **canary tokens** into private documents owned by **Alice**.
2. **Probe:** Dispatches multi-channel exfiltration and historical CVE regression probes as an unauthorized tenant (**Bob**).
3. **Detect:** Deterministically flags any tokens exposed in model responses, citation chunks, metadata, direct vector searches, or batch mutations.

---

## Key Capabilities

- 🔬 **Deterministic Zero-VRAM Assertions**: Cryptographic exact string matching evaluates token presence without LLM judges, GPU requirements, or latency overhead. *(A clean result indicates no leaks were found in the tested channels, not that isolation is mathematically proven).*
- 🛡️ **Tier-1 CVE Regression Suite**: Automated behavioral fixtures for known RAG authorization flaws (IDOR/BOLA routes, raw UUID bypasses, cross-user write overwrites, and vector filter injections).
- 🧩 **Modular Adapter Architecture**: Decomposed platform drivers (`auth`, `ingest`, `query`, `lifecycle`). **Open WebUI supported today. Dify, Flowise, and Langflow are planned.**
- 👥 **Multi-Tenant Persona Simulation**: Automated session orchestration managing authenticated data owners (Alice) and unauthorized queriers (Bob).
- 📊 **Firedamp Index (0–100)**: Quantitative risk score derived strictly from probe ratio, canary penetration, and severity weighting. **Any canary leak is a hard fail.**
- 🔄 **DevSecOps & CI/CD Gate**: Native non-zero exit codes on isolation failures (`--fail-on-leak`) with automated export to SARIF, Markdown, and JSON.

---

## Architecture Overview

```text
                          ┌──────────────────────────────────────────────┐
                          │                Firedamp CLI                  │
                          └──────────────────────┬───────────────────────┘
                                                 │
                                                 ▼
                          ┌──────────────────────────────────────────────┐
                          │               Orchestration                  │
                          │   (Docker Provisioning / Remote Airway)      │
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

### Probing Channels & Bug Classes
Firedamp tests authorization boundaries across 6 distinct transmission channels:
- `direct_api`: Direct REST/RPC calls without prompt orchestration.
- `llm_prompt`: Adversarial semantic prompts targeting context bleed.
- `citation_metadata`: Document references, chunk headers, and citation sources.
- `write_mutation`: Cross-user batch mutation and file overwrites.
- `vector_payload`: Direct vector database filter and collection parameter queries.
- `lifecycle_event`: Temporal permission changes (sharing $\rightarrow$ revocation $\rightarrow$ verification).

---

<a id="quickstart"></a>
## Quickstart

### ⚡ One-Line Install Script
Install Firedamp directly into `~/.local/bin/firedamp`:
```bash
curl -fsSL https://raw.githubusercontent.com/pr60t/firedamp/main/install.sh | bash
```

### 🧪 Instant Simulation (No Docker Required)
Test the full pipeline, UI telemetry, and reporting in simulation mode:
```bash
firedamp scan --dry-run
```

### 🛡️ Historical CVE Regression Probing
Run behavioral regression probes for known vulnerabilities (e.g. CVE-2026-44560, CVE-2026-45398, CVE-2026-28788):
```bash
firedamp scan --target-url http://localhost:8080 --suite cve-regression
```

### 🔍 Comprehensive Multi-Channel Audit
Audit an existing target with prompt-based extraction and CVE regression combined:
```bash
firedamp scan \
  --target openwebui \
  --target-url http://localhost:8080 \
  --suite all \
  --canaries 4 \
  --fail-on-leak
```

> ⚠️ **Permission & Data Notice:** Only test systems you own or have explicit written authorization to audit (disposable local/dev instances recommended). Cleanup removes files, collections, and chats created during the audit; test user accounts (`alice_owner`, `bob_attacker`) remain in the target database.

---

## Installation & Local Development

### Prerequisites
- Python 3.10+
- Docker Engine (optional, required only for ephemeral container provisioning)

### Setup
```bash
# Clone the repository
git clone https://github.com/pr60t/firedamp.git
cd firedamp

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

### Running Tests
Execute the deterministic test suite:
```bash
python3 -m unittest discover tests/ -v
# or using pytest:
pytest -v
```

---

## Project Structure

```text
.
├── core/                # Canary generation, reporter & target lifecycle
│   ├── engine.py        # Cryptographic canary engine & zero-VRAM matcher
│   ├── reporter.py      # Telemetry rendering, Firedamp Index & exports
│   └── target.py        # Docker SDK target orchestration & lifecycle
├── adapters/            # Target platform drivers
│   ├── base.py          # TargetAdapter abstract protocol & registry
│   └── openwebui/       # Modular Open WebUI driver (auth, ingest, query, lifecycle)
├── probes/              # Decoupled behavioral regression suites
│   ├── schemas/         # 8-Pillar BugClass & ProbeChannel taxonomies
│   ├── cves/            # Tier-1 CVE fixtures (CVE-2026-44560, 45398, 28788, 54019)
│   │   ├── cve_catalog.json # Machine-readable 21-CVE database
│   │   └── CVE_CATALOG.md   # Attack strategy reference manual
│   └── cve_registry.py  # Catalog loader and query engine
├── tests/               # Test suites (unit, mock E2E, adapter contracts, CVE probes)
├── assets/              # Rendered terminal report vector SVGs
├── wiki/                # Documentation wiki pages & guides
├── cli.py               # Typer / argparse CLI entrypoint
├── install.sh           # Automated shell installer script
├── pyproject.toml       # PEP 621 package metadata & entrypoints
├── LICENSE              # MIT License
└── README.md            # Project documentation & reference
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
