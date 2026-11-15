<p align="center">
  <img src="firedamp_banner.svg" alt="Firedamp Banner" width="100%" />
</p>

> Automated cross-tenant data leakage detection, isolation auditing, and vulnerability probing for Retrieval-Augmented Generation (RAG) platforms.
>
> 📖 **[Read the Documentation Wiki](wiki/Home.md)** | **[Quickstart](wiki/Quickstart.md)** | **[CLI Reference](wiki/CLI-Reference.md)**

---

```
                       .---.
                      /     \
                     | () () |    "If the canary falls silent,
                      \  ^  /      there is gas in the shaft."
                       |||||
                     /       \
                    |  CLEAR  |   --> No cross-tenant RAG leaks detected.
                    \_________/
```

Named after **firedamp**—the odorless, explosive mine gas detected with caged canaries—**Firedamp** automatically catches cross-tenant data leakage in Retrieval-Augmented Generation (RAG) stacks before adversaries or auditors do.

### How It Works
1. **Plant:** Injects verifiable, high-entropy **canary tokens** into private documents owned by **Alice**.
2. **Probe:** Dispatches multi-vector exfiltration queries as an unauthorized user (**Bob**).
3. **Detect:** Deterministically flags any tokens exposed in assistant answers, citations, or background context chunks.

---

## Core Features

- 🎯 **Target-Agnostic Adapter Pattern**: Decoupled driver architecture supporting popular platforms (Open WebUI, Dify, Flowise, Langflow, custom enterprise RAG endpoints).
- 🔬 **Deterministic Zero-VRAM Assertions**: Verifies isolation boundaries using cryptographic token tracking and exact string/regex matches. **No expensive LLM judges or GPU VRAM required.**
- 👥 **Multi-Tenant Persona Simulation**: Automated session orchestration simulating data owners (Alice) and malicious or unauthorized queriers (Bob).
- 📊 **Firedamp Index**: Quantitative 0–100 risk scoring factoring in leakage blast radius, context exposure vs. generated text bleed, and ACL coverage.
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
These are embedded across realistic decoy documents (HR complaints, quarterly earnings, unreleased API keys, internal architecture notes) with realistic vector embeddings.

### 3. Deterministic Assertions (Zero GPU VRAM)
Traditional LLM evaluation frameworks (e.g. LLM-as-a-judge) require spinning up separate 70B parameter models, generating high latency and massive VRAM footprints. Firedamp operates deterministically:
- Inspects **both** raw retrieval context payloads (citations, chunk metadata) and final LLM responses.
- Evaluates token matches via cryptographic substring matching.
- Operates effortlessly against local Docker containers running on lightweight CPU-only mock embedding/chat endpoints.

---

## Quickstart & CLI Usage

### Basic Scan (Ephemeral Docker Container)
Spin up an Open WebUI container, execute an Alice-to-Bob isolation scan, and tear it down automatically:
```bash
firedamp scan --target openwebui --version 0.9.5
```

### Scan Existing Target Deployment
Point Firedamp directly at a staging or production RAG endpoint:
```bash
firedamp scan \
  --target openwebui \
  --target-url http://localhost:8080 \
  --canaries 10 \
  --fail-on-leak
```

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
git clone https://github.com/your-org/firedamp.git
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
```

---

## Project Structure

```
firedamp/
├── core/
│   ├── __init__.py      # Core module exports & versioning
│   ├── engine.py        # Canary generation & leak detection engine
│   ├── target.py        # Docker target orchestration & lifecycle
│   └── reporter.py      # Rich terminal UI & Firedamp Index computation
├── adapters/
│   ├── __init__.py      # Base TargetAdapter abstract protocol
│   └── openwebui.py     # Open WebUI API driver (Alice/Bob simulation)
├── tests/
│   └── test_canary.py   # Unit & integration assertions
├── cli.py               # Typer / Rich CLI entry point
├── pyproject.toml       # PEP 621 package & dependency metadata
├── requirements.txt     # Production dependencies
├── requirements-dev.txt # Development & test dependencies
├── firedamp_banner.svg  # Project banner asset
├── firedamp_logo.svg    # Project logo asset
├── todo.md             # Development roadmap & milestone tracker
├── wiki/               # GitHub Wiki documentation & operational guides
└── README.md            # Project documentation & reference
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

