# 📊 Open WebUI Version Ladder Benchmark (Simulation)

The **Version Ladder Benchmark** evaluates Firedamp's behavioral accuracy, CVE detection rates, and zero-false-positive guarantees against historical release milestones of Open WebUI.

> [!NOTE]
> **Execution Mode Notice:** The automated benchmark executed via `python3 tests/benchmark_ladder.py` runs against an in-memory behavioral simulation (`VersionLadderSimulatedAdapter`) to deterministically verify probe logic, preconditions, and exact canary token matching across versions without requiring external Docker daemons or network dependencies. Live container deployment tests against real Open WebUI container images require an external Docker daemon.
>
> **Live Differential Validation Cross-Reference:** CVE-2026-28788 also has a separate live Docker differential validation (Open WebUI v0.8.5 `COMPROMISED` vs v0.8.6 `CLEAN`) documented in [CVE-Regression-Engine.md](CVE-Regression-Engine.md#live-differential-validation--open-webui-v085-vs-v086).

---

## 🎯 Objectives & Methodology

To validate that Firedamp's non-weaponized behavioral probes faithfully detect patched vulnerabilities without generating false alarms, we execute the Tier-1 regression battery against the canonical Open WebUI release milestones:

1. **`openwebui:v0.8.5`**: Vulnerable to write-side batch file overwrite (CVE-2026-28788), direct vector query bypass (CVE-2026-44560), and raw UUID prefix bypass (CVE-2026-45398).
2. **`openwebui:v0.8.6`**: Patched CVE-2026-28788. Remains vulnerable to CVE-2026-44560 and CVE-2026-45398.
3. **`openwebui:v0.9.0`**: Patched CVE-2026-44560. Remains vulnerable to raw UUID bypass (CVE-2026-45398).
4. **`openwebui:v0.9.5`**: Patched CVE-2026-45398. Vulnerable to Milvus boolean filter injection (CVE-2026-54019) when running under shared multitenancy.
5. **`openwebui:v0.9.6`**: Patched baseline across all Tier-1 CVEs.

---

## 📈 Empirical Benchmark Results (Simulated)

```text
               🛡️ Open WebUI Version Ladder Benchmark (SIMULATION)
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Release  ┃ Target   ┃ Expected ┃ Detected  ┃ False    ┃ Latency   ┃ Ladder   ┃
┃ Tag      ┃ Mode     ┃ CVEs     ┃ Breaches  ┃ Positiv… ┃ (s)       ┃ Status   ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ v0.8.5   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+]      │
│          │          │ CVE-202… │ CVE-2026… │          │           │ PASSED   │
│          │          │ CVE-202… │ CVE-2026… │          │           │          │
│ v0.8.6   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+]      │
│          │          │ CVE-202… │ CVE-2026… │          │           │ PASSED   │
│ v0.9.0   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+]      │
│          │          │          │           │          │           │ PASSED   │
│ v0.9.5   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+]      │
│          │          │          │           │          │           │ PASSED   │
│ v0.9.6   │ simulat… │ None     │ None      │ 0        │ 0.0001s   │ [+]      │
│          │          │ (Clean)  │ (Clean)   │          │           │ PASSED   │
└──────────┴──────────┴──────────┴───────────┴──────────┴───────────┴──────────┘
```

### Summary Metrics

| Benchmark Metric | Empirical Value | Target SLA | Assessment |
| :--- | :---: | :---: | :---: |
| **Execution Mode** | **Simulated In-Memory** | N/A | Deterministic emulation (no live containers) |
| **Total Release Milestones** | **5** | 5 | Complete ladder coverage |
| **Simulated Scenario Pass Rate** | **100.0%** | $\ge 95\%$ | **Zero Misses:** Every active vulnerability flagged |
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
  "simulated_scenario_pass_rate_pct": 100.0,
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

