<p align="center">
  <img src="firedamp_banner.svg" alt="Firedamp Banner" width="100%" />
</p>

> Automated cross-tenant data leakage detection, isolation auditing, and vulnerability probing for Retrieval-Augmented Generation (RAG) platforms.
>
> 📖 **[Read the Documentation Wiki](https://github.com/pr60t/firedamp/wiki)** | **[Quickstart](https://github.com/pr60t/firedamp/wiki/Quickstart)** | **[CLI Reference](https://github.com/pr60t/firedamp/wiki/CLI-Reference)**

---

```
                       .---.
                      /     \
                     | () () |    "If the canary falls silent,
                      \  ^  /      there is gas in the shaft."
                       |||||
                     /       \
                    |  CLEAR  |   --> No leaks detected in tested channels.
                    \_________/
```

Named after **firedamp**—the odorless, explosive mine gas detected with caged canaries—**Firedamp** automatically catches cross-tenant data leakage in Retrieval-Augmented Generation (RAG) stacks before adversaries or auditors do.

### How It Works
1. **Plant:** Injects verifiable, high-entropy **canary tokens** into private documents owned by **Alice**.
2. **Probe:** Dispatches multi-vector exfiltration queries as an unauthorized user (**Bob**).
3. **Detect:** Deterministically flags any tokens exposed in assistant answers, citations, or background context chunks.

---

## Core Features

- 🎯 **Target-Agnostic Adapter Pattern**: Decoupled driver architecture. **Open WebUI supported today. Dify, Flowise, and Langflow are planned.**
- 🔬 **Deterministic Zero-VRAM Assertions**: Checks whether canary tokens appear in responses or context chunks using cryptographic token tracking and string/regex matching without LLM judges or GPU VRAM. **A clean result means no leak was found in the tested channels, not that isolation is proven.**
- 👥 **Multi-Tenant Persona Simulation**: Automated session orchestration simulating data owners (Alice) and malicious or unauthorized queriers (Bob).
- 📊 **Firedamp Index**: Quantitative 0–100 risk score factoring in probe ratio, canary penetration, and severity weighting. **Any leak is a hard fail.**
- 🚨 **Instant Visual Telemetry**: High-contrast, rich terminal interface showing real-time probe progress, "Clear" safety badges, or "Gas Detected" incident summaries.
- 🔄 **CI/CD Integration**: Zero-friction integration into automated testing pipelines with non-zero exit codes on isolation failures (`--fail-on-leak`).

---

## Architecture Overview

```
                          ┌──────────────────────────────────────────────┐
                          │                Firedamp CLI                  │
                          └──────────────────────┬───────────────────────┘
                                                 │
                                                 ▼
                          ┌──────────────────────────────────────────────┐
                          │               Orchestration                  │
                          │   (Docker Provisioning / Target Lifecycle)   │
                          └──────────────────────┬───────────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
              ┌───────────────────┐                             ┌───────────────────┐
              │   Alice Session   │                             │    Bob Session    │
              │  (Victim / Owner) │                             │(Attacker / Prober)│
              └─────────┬─────────┘                             └─────────┬─────────┘
                        │                                                 │
              Injects Canary Documents                                 Dispatches
              CANARY-FRDP-<UUID>                                   Exfiltration Probes
                        │                                                 │
                        ▼                                                 ▼
             ┌───────────────────────────────────────────────────────────────────────┐
             │                         Target RAG Platform                           │
             │                (e.g., Open WebUI, Vector DB, RAG API)                 │
             └───────────────────────────────────┬───────────────────────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────┐
                                │     Probing & Leak Engine       │
                                │   (Deterministic Matcher,       │
                                │    Entropy & Context Inspector) │
                                └────────────────┬────────────────┘
                                                 │
                                                 ▼
                                ┌─────────────────────────────────┐
                                │         Reporter & Score        │
                                │    [Clear] vs. [Gas Detected]   │
                                └─────────────────────────────────┘
```

### 1. Adapters (`firedamp.adapters`)
Adapters translate standard Firedamp lifecycle operations (user registration, document ingestion, collection assignment, semantic querying) into target-specific API calls. Each adapter implements the `TargetAdapter` interface, allowing new platforms to be plugged in with minimal boilerplate.

### 2. Canary Tokens (`firedamp.core.engine`)
Canaries are synthetically generated, high-entropy tokens with recognizable preambles and checksum validation:
```
CANARY-FRDP-9c8e14d2-7b19-4f22-92a1-0e19a3bb9f01-7A2F
```
These are embedded across realistic decoy documents (HR complaints, quarterly earnings, unreleased API keys, internal architecture notes). The target platform indexes them into its own vector space.

### 3. Deterministic Assertions (Zero GPU VRAM)
Traditional LLM evaluation frameworks (e.g. LLM-as-a-judge) require spinning up separate 70B parameter models, generating high latency and massive VRAM footprints. Firedamp operates deterministically:
- Inspects **both** raw retrieval context payloads (citations, chunk metadata) and final LLM responses.
- Evaluates token matches via cryptographic substring matching.
- Operates against local Docker containers running real CPU embeddings (Open WebUI's built-in SentenceTransformer) or connected to local Ollama instances (e.g. `llama3:8b`).

---

## Quickstart & CLI Usage

### One-Line Install Script
Install Firedamp directly with a single shell command:
```bash
curl -fsSL https://raw.githubusercontent.com/pr60t/firedamp/main/install.sh | bash
```

### Basic Scan (Ephemeral Docker Container)
Spin up an Open WebUI container, execute an Alice-to-Bob isolation scan, and tear it down automatically:
```bash
firedamp scan --target openwebui --version main --cpu-only
```

### Scan Existing Target Deployment
Scan an existing instance you own or have explicit written permission to test (disposable local/dev instances strongly recommended):
```bash
firedamp scan \
  --target openwebui \
  --target-url http://localhost:8080 \
  --canaries 4 \
  --fail-on-leak
```

> ⚠️ **Permission & Data Notice:** Only run Firedamp against systems you own or have explicit authorization to test. Cleanup removes the files, collections, and chats it creates; test user accounts (`alice_owner`, `bob_attacker`) remain in the target system.

### List Supported Adapters
```bash
firedamp list-targets
```

### Export Results to JSON for CI/CD
```bash
firedamp scan --target openwebui --output audit-report.json --fail-on-leak
```

---

## Installation & Local Development

### Prerequisites
- Python 3.10+
- Docker Engine (optional, required for automated container provisioning)

### Setup Virtual Environment
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
pytest -v
# or using standard library unittest:
python3 -m unittest discover tests/ -v
```

---

## Project Structure

```text
.
├── core/                # Canary engine, reporter, and target managers
│   ├── __init__.py
│   ├── engine.py        # Canary generation & deterministic leak detection
│   ├── reporter.py      # Telemetry rendering, Firedamp Index & exports
│   └── target.py        # Docker SDK target orchestration & lifecycle
├── adapters/            # Target platform drivers
│   ├── __init__.py      # Base TargetAdapter abstract protocol
│   └── openwebui.py     # Open WebUI REST API driver
├── tests/
│   └── test_canary.py   # Unit, E2E mocked, and adapter contract tests
├── assets/              # Rendered terminal report vector SVGs
├── wiki/                # Documentation wiki pages & guides
├── .agents/             # Agent rules and skills
├── .github/             # GitHub Actions CI workflows
├── cli.py               # Typer / argparse CLI entrypoint
├── install.sh           # Automated installer script
├── pyproject.toml       # PEP 621 package metadata & entrypoints
├── requirements.txt     # Production dependencies
├── requirements-dev.txt # Development & test dependencies
├── firedamp_banner.svg  # Project banner asset
├── firedamp_logo.svg    # Project logo asset
├── LICENSE              # MIT license
└── README.md            # Project documentation & reference
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

