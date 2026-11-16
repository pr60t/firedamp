# 🛠️ Real-World Use Cases & Recipes

Here are the most common ways to deploy and use Firedamp in practice.

---

### Recipe 1: Pre-Release Version Testing (Ephemeral Docker)
**Scenario:** You want to test whether a new version of Open WebUI (e.g. `main` or `v0.5.0`) has cross-tenant isolation vulnerabilities before deploying it to your team.

```bash
firedamp scan \
  --target openwebui \
  --version main \
  --cpu-only \
  --canaries 6
```

- **How it works:** Firedamp automatically pulls the image, starts an isolated test container on an ephemeral port, seeds Alice's private documents, tests Bob's access, reports the score, and tears down the container and its volumes cleanly.

---

### Recipe 2: Auditing an Existing Staging/Local Server
**Scenario:** You have an active Open WebUI instance already running at `http://localhost:8080` (or `http://rag-staging.internal:8080`) and want to check if existing tenant permissions work as expected.

```bash
firedamp scan \
  --target-url http://localhost:8080 \
  --canaries 4 \
  --output security-audit.md \
  --format markdown
```

> ⚠️ **Permission & Data Notice:** Only test systems you own or have explicit written authorization to audit (disposable local/dev instances are strongly recommended). Cleanup removes the files, collections, and chats created during the audit; test user accounts (`alice_owner`, `bob_attacker`) remain in the target database.

---

### Recipe 3: Historical CVE Regression Probing
**Scenario:** Verify that known authorization and boundary CVEs (such as predictable collection IDs, raw UUID bypasses, or cross-user write overwriting) are effectively patched on your target instance.

```bash
# Run only the Tier-1 CVE behavioral probes
firedamp scan \
  --target-url http://localhost:8080 \
  --suite cve-regression \
  --output cve-report.json

# Or run the full combined suite (prompts + CVE probes)
firedamp scan \
  --target-url http://localhost:8080 \
  --suite all \
  --fail-on-leak
```

---

### Recipe 4: API Authorization Matrix (RAG Autorize)
**Scenario:** Replay recorded Owner operations (document ingestion, queries, metadata mutations) against unprivileged Intruder, Ex-Member, and Anonymous roles to uncover IDOR/BOLA or broken object-level authorization via Jaccard key diffs.

```bash
firedamp scan \
  --target-url http://localhost:8080 \
  --suite auth-matrix \
  --output auth-matrix-report.json
```

---

### Recipe 5: Testing Non-Default Vector Database Architectures
**Scenario:** Audit enterprise deployments utilizing partitioned Milvus or Qdrant vector databases in shared metadata multitenancy mode.

```bash
firedamp scan \
  --target-url http://localhost:8080 \
  --vector-db milvus \
  --multitenancy shared \
  --suite all \
  --fail-on-leak
```

---

### Recipe 6: Continuous Integration in GitHub Actions (DevSecOps)
**Scenario:** You want every Pull Request or nightly build to verify that RAG permissions and vector database namespaces haven't broken.

Create `.github/workflows/audit.yml` in your repo:

```yaml
name: RAG Cross-Tenant Isolation Audit

on: [push, pull_request]

jobs:
  isolation-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .

      # Generate Markdown PR summary
      - name: Run Firedamp Audit
        run: |
          firedamp scan --target openwebui --cpu-only --output report.md --format markdown --dry-run
          cat report.md >> $GITHUB_STEP_SUMMARY

      # Break build and export SARIF if gas is detected
      - name: Enforce Zero-Leak Policy
        if: always()
        run: |
          firedamp scan --target openwebui --cpu-only --output results.sarif --format sarif --fail-on-leak --dry-run

      - name: Upload to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

