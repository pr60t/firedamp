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
| **[[Use-Cases-&-Recipes\|Use Cases & Recipes]]** | Ready-to-copy commands for Docker, staging servers, and CI/CD. |
| **[[Understanding-Telemetry\|Understanding Telemetry]]** | How the Firedamp Index (0-100) works and what breach reports mean. |
| **[[Troubleshooting]]** | Quick fixes for Docker permissions, timeouts, and baseline warnings. |

---

### ⚡ One-Liner Quick Test
Don't have Docker running? Test the full pipeline instantly in simulation mode:

```bash
firedamp scan --dry-run
```

