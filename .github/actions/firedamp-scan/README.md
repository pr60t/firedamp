# 🛡️ Firedamp Scan GitHub Action

A reusable GitHub Action to automatically detect cross-tenant data leakage, audit RAG authorization boundaries, and enforce policy-as-code in your CI/CD pipelines.

---

## 🚀 Quick Usage

```yaml
name: RAG Tenant Isolation Audit

on: [push, pull_request]

jobs:
  rag-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Firedamp Audit Gate
        uses: ./.github/actions/firedamp-scan
        with:
          target-url: "http://localhost:8080"
          suite: "all"
          policy: "policies/enterprise.yaml"
          fail-on-leak: "true"
          output: "firedamp-results.sarif"
          format: "sarif"

      - name: Upload Security SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: firedamp-results.sarif
```

