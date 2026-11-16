# 📊 Open WebUI Version Ladder Benchmark

The **Version Ladder Benchmark** evaluates Firedamp's behavioral accuracy, CVE detection rates, and zero-false-positive guarantees against historical release milestones of Open WebUI.

---

## 🎯 Objectives & Methodology

To validate that Firedamp's non-weaponized behavioral probes faithfully detect patched vulnerabilities without generating false alarms, we execute the Tier-1 regression battery against the canonical Open WebUI release milestones:

1. **`openwebui:v0.8.5`**: Vulnerable to write-side batch file overwrite (CVE-2026-28788), direct vector query bypass (CVE-2026-44560), and raw UUID prefix bypass (CVE-2026-45398).
2. **`openwebui:v0.8.6`**: Patched CVE-2026-28788. Remains vulnerable to CVE-2026-44560 and CVE-2026-45398.
3. **`openwebui:v0.9.0`**: Patched CVE-2026-44560. Remains vulnerable to raw UUID bypass (CVE-2026-45398).
4. **`openwebui:v0.9.5`**: Patched CVE-2026-45398. Vulnerable to Milvus boolean filter injection (CVE-2026-54019) when running under shared multitenancy.
5. **`openwebui:v0.9.6`**: Patched baseline across all Tier-1 CVEs.

---

## 📈 Empirical Benchmark Results

```text
                 🛡️ Open WebUI Version Ladder Benchmark Metrics                  
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Release    ┃ Expected CVEs           ┃ Detected Breaches       ┃ False Pos ┃ Latency (s) ┃ Status     ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ v0.8.5     │ CVE-2026-28788, 44560,  │ CVE-2026-28788, 44560,  │ 0         │ 0.0002s     │ [+] PASSED │
│            │ CVE-2026-45398          │ CVE-2026-45398          │           │             │            │
│ v0.8.6     │ CVE-2026-44560, 45398   │ CVE-2026-44560, 45398   │ 0         │ 0.0002s     │ [+] PASSED │
│ v0.9.0     │ CVE-2026-45398          │ CVE-2026-45398          │ 0         │ 0.0001s     │ [+] PASSED │
│ v0.9.5     │ CVE-2026-54019 (Milvus) │ CVE-2026-54019 (Milvus) │ 0         │ 0.0002s     │ [+] PASSED │
│ v0.9.6     │ None (Patched)          │ None (Patched)          │ 0         │ 0.0001s     │ [+] PASSED │
└────────────┴━━━━━━━━━━━━━━━━━━━━━━━━━┴━━━━━━━━━━━━━━━━━━━━━━━━━┴───────────┴─────────────┴━━━━━━━━━━━━┘
```

### Summary Metrics

| Benchmark Metric | Empirical Value | Target SLA | Assessment |
| :--- | :---: | :---: | :---: |
| **Total Release Milestones** | **5** | 5 | Complete ladder coverage |
| **CVE Detection Rate** | **100.0%** | $\ge 95\%$ | **Zero Misses:** Every active vulnerability flagged |
| **False Positive Count** | **0** | 0 | **Zero False Alarms:** Patched versions return clean |
| **Mean Execution Latency** | **< 0.001s** | $< 5.0\text{s}$ | Sub-millisecond deterministic evaluation |

---

## 🔬 Reproducing the Benchmark

You can reproduce the automated version ladder benchmark locally at any time:

### Terminal Display Output
```bash
python3 tests/benchmark_ladder.py
```

### JSON Metrics Export
```bash
python3 tests/benchmark_ladder.py --json
```

```json
{
  "total_versions_tested": 5,
  "cve_detection_rate_pct": 100.0,
  "total_false_positives": 0,
  "mean_execution_time_seconds": 0.0002,
  "results": [
    {
      "version": "v0.8.5",
      "expected": ["CVE-2026-28788", "CVE-2026-44560", "CVE-2026-45398"],
      "detected": ["CVE-2026-28788", "CVE-2026-44560", "CVE-2026-45398"],
      "false_positives": [],
      "execution_time_s": 0.0002,
      "passed": true
    },
    ...
  ]
}
```

