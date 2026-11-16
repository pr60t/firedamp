# 📖 CLI Command Reference

Firedamp provides a unified command line interface for isolation scanning and ecosystem target discovery.

```bash
firedamp [COMMAND] [OPTIONS]
```

---

### Commands Overview

| Command | Description |
| :--- | :--- |
| `firedamp scan` | Executes a multi-tenant isolation audit and canary leak test. |
| `firedamp list-targets` | Displays available and planned platform target adapters. |
| `firedamp version` | Prints the Firedamp atmospheric sensor banner and version. |

---

### `firedamp scan` Options & Flags

| Flag | Short | Default | Description |
| :--- | :---: | :---: | :--- |
| `--target` | `-t` | `openwebui` | Target platform adapter name. |
| `--target-url` | `-u` | `None` | URL of an existing deployment (e.g. `http://localhost:8080`). Bypasses Docker. |
| `--version` | `-v` | `latest` | Container image tag when spinning up ephemeral Docker containers. |
| `--canaries` | `-n` | `4` | Number of canary documents to synthesize and plant. |
| `--output` | `-o` | `None` | Path to export the audit report file. |
| `--format` | `-f` | `json` | Report output format: `json`, `markdown`, or `sarif`. *(Auto-detected from file extension).* |
| `--cpu-only` | | `False` | Disables GPU/Ollama dependencies in Docker; runs RAG embeddings purely on CPU. |
| `--fail-on-leak` | | `False` | Halts execution with **exit code 1** if any canary leak is detected (ideal for CI/CD). |
| `--dry-run` | | `False` | Runs atmospheric simulation mode without network or Docker containers. |
| `--suite` | `-s` | `default` | Probing suite to execute: `default` (prompt strategies), `cve-regression` (Tier-1 CVE probes), `auth-matrix` (RAG Autorize table), `lifecycle`, `write-poisoning`, or `all`. |
| `--scenario` | `-sc` | `None` | Targeted scenario: `lifecycle` (Pillar 4 race & staleness) or `write-poisoning` (Pillar 5 cross-tenant injection). |
| `--vector-db` | `-db` | `chroma` | Target vector database backend: `chroma`, `milvus`, or `qdrant`. |
| `--multitenancy` | `-m` | `shared` | Multitenancy architecture mode: `shared` (metadata filtered) or `isolated` (dedicated partition). |

---

### Common Examples

#### 1. Audit with Automated Ephemeral Docker Container
```bash
firedamp scan --target openwebui --version main --cpu-only
```

#### 2. Audit an Existing Server & Export PR-Ready Markdown
```bash
firedamp scan --target-url http://localhost:8080 --output audit.md --format markdown
```

#### 3. Break CI Build on Gas Leak & Export SARIF for GitHub Security
```bash
firedamp scan --target openwebui --dry-run --output results.sarif --fail-on-leak
```

