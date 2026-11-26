# 🐤 Welcome to the Firedamp Wiki

> **Canaries for your RAG Stack:** Automated cross-tenant data leakage detection, isolation auditing, and vulnerability probing for Retrieval-Augmented Generation (RAG) platforms.

---

### What does Firedamp do in 10 seconds?
In coal mines, miners took caged canaries into underground shafts to detect odorless toxic gases (*firedamp*).

In modern multi-tenant AI platforms (like Open WebUI), proprietary documents often accidentally bleed across users due to misconfigured permissions or partitioned vector namespaces. **Firedamp** acts as your automated canary:

1. **Seeds** synthetic documents with verifiable **canary tokens** into a private user's scope (**Alice**).
2. **Probes** the platform using an unauthorized user (**Bob**) with adversarial prompt vectors.
3. **Alerts** you immediately if Alice's tokens leak into Bob's chat responses, citations, or background retrieval context chunks.

---

### 🗺️ Quick Navigation

| Guide | What's Inside |
| :--- | :--- |
| **[[Quickstart]]** | Install and run your first scan in under 60 seconds. |
| **[[CLI-Reference\|CLI Reference]]** | Complete cheat sheet of flags, options, and commands. |
| **[[CVE-Regression-Engine\|CVE Regression Engine]]** | Deep dive into the 8 bug classes, Tier-1 behavioral probes, and catalog. |
| **[[API-Authorization-Matrix\|API Authorization Matrix]]** | RAG Autorize request replay across Owner, Intruder, Ex-Member, Anonymous. |
| **[[Use-Cases-&-Recipes\|Use Cases & Recipes]]** | Ready-to-copy commands for Docker, staging servers, and CI/CD. |
| **[[Version-Ladder-Benchmark\|Version Ladder Benchmark]]** | Observed simulation benchmark results and metrics across 5 Open WebUI releases. |
| **[[Understanding-Telemetry\|Understanding Telemetry]]** | How the Firedamp Index (0-100) works and what breach reports mean. |

---

### 🔬 Evidence, Labs & Audits

| Resource | Description |
| :--- | :--- |
| **[CVE-2026-28788 Integration Lab](file:///home/user/firedamp/tests/integration/openwebui_cve_2026_28788/README.md)** | Step-by-step reproduction harness, Docker compose files, and scripts. |
| **[Sanitized Evidence Bundles](file:///home/user/firedamp/tests/integration/openwebui_cve_2026_28788/evidence/)** | Historical and offline simulation test evidence runs with cryptographic manifests. |
| **[CVE Forensic Catalog Audit (CVE_AUDIT.md)](file:///home/user/firedamp/CVE_AUDIT.md)** | Authoritative 21-vulnerability breakdown and historical misattribution audit. |
| **[Repository Audit & Findings (FINAL_AUDIT.md)](file:///home/user/firedamp/FINAL_AUDIT.md)** | Comprehensive security findings, remediation logs, and resolver architecture. |

---

### ⚡ Quick Install
Install the Firedamp CLI with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/pr60t/firedamp/main/install.sh | bash
```

### 🧪 One-Liner Quick Test
Don't have Docker running? Test the full pipeline instantly in simulation mode:

```bash
firedamp scan --dry-run
```

