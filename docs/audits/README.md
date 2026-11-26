# Firedamp Security & Audit Index

This index reconciles Firedamp's historical audit reports with the current repository state on `fix/post-release-hardening` (post-`v0.1.0`).

## Historical Reports Archive

| Document | Audit Date | Baseline / Branch | Original Scope | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| [CVE_AUDIT.md](../../CVE_AUDIT.md) | 2026-11-18 | `fix/cve-catalog-integrity` | 21-entry CVE catalog & upstream advisory verification | Historical baseline; supplemented below |
| [FINAL_AUDIT.md](archive/FINAL_AUDIT.md) | 2026-11-24 | `a6fe4ef` / `fix/cve-catalog-integrity` | Pre-release snapshot, lab scripts, & split index | **Historically Remediated** (see register below) |
| [FINAL_AUDIT_REMEDIATION.md](archive/FINAL_AUDIT_REMEDIATION.md) | 2026-11-24–25 | Remediation overlay | High-priority destructive-op & lab-boundary fixes | **Superseded** by v0.1.0 & post-release hardening |

---

## Dated CVE Validation Status Supplement (Post-Nov 18, 2026)

> **Important:** The November 18, 2026 table in [CVE_AUDIT.md](../../CVE_AUDIT.md) accurately reflects the offline-only status at that date (`NOT TESTED (Simulation Only)`). The later differential container run for `CVE-2026-28788` occurred after that audit and is tracked separately below.

| CVE ID | Advisory Verification | Probe Implementation | Automated Simulation Coverage | Live Validation Status | Evidence Provenance & Limitations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2026-28788** | VERIFIED (`GHSA-jjp7-g2jw-wh3j`) | Implemented (`cve_2026_28788.py`) | Yes (unit + integration simulation suite) | **Operator-reported live differential** (`v0.8.5` `COMPROMISED` vs `v0.8.6` `CLEAN`) | **Operator-reported evidence.** Local container differential outputs were hashed and sanitized, but hashes alone do not independently authenticate evidence origin. Vector-store cleanup after reset remains unverified (`RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED`). |
| **CVE-2026-44560** | VERIFIED (`GHSA-h36f-rqpx-j5wx`) | Implemented (`cve_2026_44560.py`) | Yes (unit + simulated ladder) | **NOT LIVE-TESTED** (Simulation Only) | Passing simulation tests do **not** constitute live reproduction against an upstream container. |
| **CVE-2026-45398** | VERIFIED (`GHSA-4g37-7p2c-38r9`) | Implemented (`cve_2026_45398.py`) | Yes (unit + simulated ladder) | **NOT LIVE-TESTED** (Simulation Only) | Passing simulation tests do **not** constitute live reproduction against an upstream container. |
| **CVE-2026-54019** | VERIFIED (`GHSA-p5cp-r7rg-qpxc`) | Implemented (`cve_2026_54019.py`) | Yes (unit + simulated Milvus ladder) | **NOT LIVE-TESTED** (Simulation Only) | Requires `milvus_multitenancy`; skipped on Chroma targets (`SKIPPED`). |
| 7 Documented Entries | VERIFIED (1 conflicting NVD/GHSA) | Documented only | Schema validation only | **NOT TESTED** | No executable probe implementations exist. |
| 10 Quarantined Entries | VERIFIED (misattributed) | Rejected / Quarantined | Schema validation only | **NOT APPLICABLE** | Excluded from active probing. |

---

## Reconciled Historical Finding Register (`FINAL_AUDIT.md`)

| Finding ID | Summary | Status | Current Verification |
| :--- | :--- | :--- | :--- |
| **AUD-01** | Split Git index vs working tree | **Historically Remediated** | Cohesive commits landed in `v0.1.0` (`9e47ea3` / `269ce07`). |
| **AUD-02** | Fixture reset vector cleanup claim | **Historically Remediated** | `reset_fixture.py` reports `RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED`; covered in `simulations/test_reset_fixture.py`. |
| **AUD-03** | Lab loopback boundary enforcement | **Historically Remediated** | `lab_safety.py` enforces loopback `127.0.0.1:13085/13086`; covered in `simulations/test_lab_safety.py`. |
| **AUD-04** | Authorization matrix destructive ops | **Historically Remediated** | `core/matrix.py` is strictly read-only; covered in `tests/test_matrix.py`. |
| **AUD-05** | Live matrix owner baseline capture | **Historically Remediated** | Requires verified 2xx owner baseline; covered in `tests/test_matrix.py`. |
| **AUD-06** | Shared resolver malformed IDs | **Historically Remediated** | `probes/knowledge_membership.py` fails closed (`None`); covered in `tests/test_cve_probes.py`. |
| **AUD-07** | Write-poisoning disposable proof | **Historically Remediated** | `probes/scenarios/write_poisoning.py` requires `_TRUSTED_SCAN_REGISTRY` + baseline SHA-256 + KB membership. |
| **AUD-08** | Collection injection orphan Bob file | **Historically Remediated** | Preserves upload ID on link failure and performs targeted Bob-owned cleanup; covered in `tests/test_write_poisoning.py`. |
| **AUD-09** | Fabricated fallback target IDs | **Historically Remediated** | Zero fabricated fallback IDs remain; missing IDs yield `INCONCLUSIVE`. |
| **AUD-10** | `.gitignore` missing `.env` exclusions | **Historically Remediated** | `.gitignore` excludes `.env` and `.env.*` while keeping `.env.example`. |
| **AUD-11** | CLI labels non-leaks as "Passed" | **Historically Remediated & Hardened** | `ProbeStatus` (`CLEAN`, `COMPROMISED`, `INCONCLUSIVE`, `SKIPPED`) + `--require-complete` enforced across CLI, reporter, and policy. |
| **POST-01** | Hardcoded example CLI passwords (`FINAL_AUDIT_REMEDIATION.md` residual) | **Remediated (Post-v0.1.0)** | Removed from `cli.py`; replaced by `FIREDAMP_ALICE_PASSWORD` / `FIREDAMP_BOB_PASSWORD` validated pre-network (`tests/test_security_hardening.py`). |
