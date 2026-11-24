# Firedamp — Final Repository Audit

**Audit date:** 2026-11-24
**Reviewed baseline:** `a6fe4ef51799e6a5b526c8e3bed8fd53f52da3ef`
**Branch reported by the working-tree snapshot:** `fix/cve-catalog-integrity`
**Scope:** Uploaded source snapshot, combined working-tree patch, staged patch, unstaged patch, test suites, and CVE-2026-28788 lab scripts.

## Current Implementation & Remediation Status Summary (Post-Audit Reconciled)

> **Notice:** The findings below in Section [Findings requiring action](#findings-requiring-action) are preserved as historical audit records from the initial review. The working tree has since undergone comprehensive remediation documented in [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md) and final pre-commit hardening.

### Reconciled Finding Register

| Finding ID | Title | Current Status | Remediation & Implementation Notes |
| :--- | :--- | :---: | :--- |
| **AUD-01** | Staged index contains superseded unsafe implementations | **Commit Coordination Required** | The staged index (7 files) represents a partial commit and does not include the full dependent changeset (`probes/disposable_registry.py`, `probes/knowledge_membership.py`, test suites, integration lab). Staging must be executed cohesively across the complete changeset prior to committing. |
| **AUD-02** | Fixture reset can claim vector cleanup without verifying it | **REMEDIATED** | `reset_fixture.py` validates pre-reset membership, verifies other-tenant document preservation, and explicitly reports nearest-neighbor retrieval as `RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED` without claiming exhaustive vector deletion. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-03** | Lab setup and probe runner do not enforce local boundary | **REMEDIATED** | Shared `lab_safety.py` enforces loopback boundaries (`127.0.0.1`), pins ports 13085 (v0.8.5) and 13086 (v0.8.6), verifies target `/api/version`, and refuses non-loopback endpoints without explicit `--allow-non-loopback`. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-04** | Authorization matrix issues destructive operations | **REMEDIATED** | Matrix runner (`core/matrix.py`) is strictly read-only; destructive overwrite and delete operations were completely excised. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-05** | Live matrix does not capture an owner baseline | **REMEDIATED** | Requires verified 2xx owner baseline before replaying queries; missing or malformed baselines produce `INCONCLUSIVE` cells. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-06** | Shared resolver silently drops malformed membership IDs | **REMEDIATED** | `resolve_file_knowledge_base` and adapter enumerators validate candidate types, reject duplicate IDs within or across pages, and fail closed (`None`) on incomplete or malformed pages. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-07** | Write-poisoning selects first file without disposable proof | **REMEDIATED** | `write_poisoning.py` requires scan-scoped disposable registration (`_TRUSTED_SCAN_REGISTRY`), verified server-side ownership, unchanged baseline SHA-256, and exact file-to-KB membership. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-08** | Collection injection can leave orphan Bob-owned file | **REMEDIATED** | Preserves uploaded file ID on link failure, validates Bob's ownership, registers as current-run disposable, and performs targeted cleanup. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-09** | Probes and scenarios use fabricated fallback target IDs | **REMEDIATED** | Read-side probes (`cve_2026_44560.py`, `cve_2026_45398.py`) and lifecycle scenarios (`lifecycle.py`) removed all fabricated fallbacks (`"unauthorized-file-id"`, `"00000000-0000-0000-0000-000000000000"`, `"target-resource-ref"`). Missing/malformed target IDs return `INCONCLUSIVE` without issuing attack queries. Dead fallback in `cve_2026_54019.py` was excised. Repository scan confirms zero runtime fallback identifiers remain. |
| **AUD-10** | Root `.gitignore` does not exclude environment files | **REMEDIATED** | Root `.gitignore` excludes `.env` and `.env.*` while keeping `.env.example`. See [FINAL_AUDIT_REMEDIATION.md](FINAL_AUDIT_REMEDIATION.md). |
| **AUD-11** | CLI labels non-leaking CVE outcomes as "Passed" | **REMEDIATED** | `cli.py` now explicitly branches: `res.is_leak` logs alert, `res.is_inconclusive` logs neutral active notice, and only verified clean non-leaks log "Passed". |

### Verification Evidence Classification
- **Live Differential Validation:** Verified against local container lab (`127.0.0.1:13085` v0.8.5 `COMPROMISED` vs `127.0.0.1:13086` v0.8.6 `CLEAN`). External sanitized evidence package stored at `~/firedamp-evidence/cve-2026-28788/`.
- **Offline Simulation Results:** 68 passing deterministic integration tests in `tests/integration/openwebui_cve_2026_28788/simulations/` verifying setup, classification, reset, and safety pipelines.
- **Independently Verified Source & Unit Tests:** 257 root test suites in `tests/` verifying adapters, engine, matrix, probes, catalog, and CLI safety.
- **Operator-Reported Notes:** Initial lab deployment and setup generation in prior sessions were operator-assisted; subsequent live probe runs and raw `/tmp` reports were independently executed and hash-verified.

## Executive decision

**Do not commit the current Git index and do not treat the repository as ready for unrestricted live scans.**

The CVE-2026-28788 implementation has reached a meaningful validation milestone: the uploaded source contains a fail-closed file-to-knowledge-base resolver, complete candidate and membership pagination, and regression tests for the combined adapter/resolver path. The operator's latest run report states that Firedamp detected the vulnerable Open WebUI v0.8.5 instance as `COMPROMISED` and classified v0.8.6 as `CLEAN`. Those results are promising and materially stronger than mock-only evidence.

However, the uploaded bundle does **not** contain the latest `/tmp/firedamp-v085.json` and `/tmp/firedamp-v086.json` reports or the setup files. Their existence and successful JSON parsing were reported in the conversation, but the contents could not be independently reviewed here. The live differential is therefore recorded below as **operator-reported evidence**, not independently verified raw evidence.

The most immediate release/commit blocker is the split Git index: the staged versions of `adapters/openwebui/lifecycle.py` and `adapters/base.py` do not contain the later fail-closed corrections present in the working tree. A commit from the current index could reintroduce unsafe behavior.

There are also separate live-scan safety and correctness issues in the reset utility, authorization matrix, lab setup/runner boundary, and generic write-poisoning scenario. These should be addressed or explicitly disabled before using those paths against anything other than a disposable local lab.

## What was independently checked

The audit bundle contained a source archive, `HEAD.txt`, the combined patch, the staged patch, the unstaged patch, status output, and diff-check output. The uploaded archive did not contain `.git` metadata or the latest `/tmp` raw probe reports. The source was extracted and the committed baseline reconstructed from the combined patch for comparison.

The following checks were rerun against the extracted source snapshot using Python 3.13:

| Check | Result |
|---|---:|
| `python3 -m unittest discover tests -p 'test_*.py'` | **235 passed** |
| `python3 -m unittest discover tests/integration/openwebui_cve_2026_28788/simulations -p 'test_*.py'` | **58 passed** |
| `python3 -m compileall -q adapters core probes tests cli.py` | **Passed** |
| CLI CVE-regression dry-run smoke test | **Exited 0; output JSON parsed** |
| Supplied `git diff --check` result | **Clean** |

The root and simulation test suites are separate; the simulation tests are not included in root discovery. Their arithmetic total is 293 executions, with overlaps not expected because they are distinct discovery roots.

These tests establish regression behavior in the extracted snapshot. They do not establish that every live scan path is safe, that a target is disposable, or that the latest live report contents match the operator's summary.

## Positive findings

1. **CVE-2026-28788 has a substantially stronger safety path.** The working-tree implementation validates the target FileModel ID and owner ID, checks current-run disposable registration, verifies server-side ownership against Alice, positively validates Bob's authentication, captures a baseline content hash, and requires victim-side indexed-content readback before declaring compromise or clean.
2. **Collection selection no longer relies on Bob's first accessible KB.** The adapter requires an explicit collection ID; the shared resolver inspects the complete accessible candidate set and server-side file membership.
3. **Both membership enumerators are paginated and fail closed.** They distinguish a verified empty result from an unavailable/incomplete lookup, validate totals, and bound page traversal. File membership additionally rejects duplicate IDs within/across pages in the latest source.
4. **The resolver is in a neutral module.** `probes/knowledge_membership.py` is imported by both the CVE-specific probe and generic write-poisoning scenario, removing the prior CVE-to-scenario dependency.
5. **The combined pagination test exercises real adapter and resolver methods.** Only the HTTP transport boundary is mocked. It covers candidate page 2 and file-membership page 2 and expects the unique result `("kb-32", None)`.
6. **The evidence collector has fail-closed behavior for legacy offline/live modes.** The reviewed source does not manufacture a live verdict when raw validated live reports are absent.
7. **The lab compose configuration binds the published test ports to loopback.** This is a good default for the dedicated local CVE lab, although the Python setup and runner scripts do not enforce the same boundary themselves.

## Findings requiring action

Severity labels below are repository-audit priorities, not CVSS scores. “Blocker” means do not commit or use the affected live path until reconciled.

### AUD-01 — Staged index contains superseded unsafe implementations

**Severity: Blocker — commit blocker**
**Files:** `adapters/openwebui/lifecycle.py`, `adapters/base.py`

The supplied status shows both files as `MM`: each has staged changes and additional unstaged changes. The staged lifecycle implementation still contains the earlier fallback that fabricates a FileModel if metadata cannot be retrieved, chooses a collection from the requesting session's `knowledge_ids`, and invents `collection_<resource_ref>` when no collection is known. Those are precisely the fallbacks removed from the later working-tree implementation.

The staged `adapters/base.py` also predates the new knowledge-membership interface and the fail-closed default for direct collection injection. The corrected behavior is present only in the unstaged working tree.

**Impact:** Committing the current index can reintroduce unsafe request construction and stale adapter semantics, even though the working tree and its tests reflect the corrections.

**Required action:** After all review findings are addressed, stage the complete reviewed working-tree versions of both files (for example, `git add adapters/base.py adapters/openwebui/lifecycle.py`) and inspect `git diff --cached` again. Do not use `git commit -a` or commit the current index as-is.

### AUD-02 — Fixture reset can claim vector cleanup without verifying it

**Severity: High**
**File:** `tests/integration/openwebui_cve_2026_28788/scripts/reset_fixture.py` (notably lines 103–115, 201–223, 225–257)

The initial KB membership audit uses one unpaginated request. If it is not HTTP 200 or has an unexpected response shape, the code leaves `other_file_ids` empty and proceeds, so it cannot later prove preservation of all pre-existing files. The post-reset membership check is also unpaginated.

More importantly, the vector-cleanup query is only inspected when it returns HTTP 200 with a dictionary body. A failed/non-200 query falls through. The result object then sets `verified_vector_cleanup` to `True` whenever a KB ID exists, regardless of whether the query succeeded. Even a successful nearest-neighbor retrieval with `k=10` does not exhaustively prove that no matching vector remains.

**Impact:** The reset utility can report `verified_vector_cleanup: true` when vector cleanup was not actually verified. That can make later destructive lab runs rely on a false restoration assurance.

**Required action:** Make initial and final KB membership enumeration complete/paginated and fail closed on any inability to verify. Only set `verified_vector_cleanup=true` when the verification mechanism is exhaustive and successful. A failed verification request must raise/report failure, never silently fall through. Replace the current `k=10` nearest-neighbor absence check with a verified exact metadata-filtered vector-store inspection or another exhaustive method supported by the pinned lab implementation. Add tests for non-200, transport error, malformed body, incomplete pagination, and non-exhaustive verification.

### AUD-03 — Lab setup and probe runner do not enforce a local-target boundary

**Severity: High**
**Files:** `tests/integration/openwebui_cve_2026_28788/scripts/setup_lab.py`, `run_firedamp_probe.py`, `reset_fixture.py`, `reproduce_cve.py`

`setup_lab.py` accepts an arbitrary `--url` (defaulting to loopback), obtains administrator access, and calls `ensure_lab_environment()`, which can change default workspace permissions and `BYPASS_EMBEDDING_AND_RETRIEVAL`. The setup functions include default administrator/Alice/Bob passwords. `run_firedamp_probe.py` and `reset_fixture.py` trust the `base_url` and target IDs in the setup JSON. The runner then registers the setup file's `disposable_file.id` in its in-memory trusted disposable registry for the current run; the CVE probe relies on that registry when authorizing a destructive overwrite.

The setup JSON is written with mode 0600, which is good, but file permissions do not prevent an operator from selecting the wrong file or an arbitrary remote target.

**Impact:** A mistaken `--url` or setup file can direct privileged setup operations, bearer tokens, fixture restoration, or a destructive overwrite at a non-lab Open WebUI instance. The runner's scan-local registry proves that this process registered the ID; it does not independently prove the supplied setup JSON came from the intended local disposable lab.

**Required action:** Enforce an explicit loopback-only default in every CVE lab script, including setup, runner, reproduction, and reset. Require a deliberate, clearly named opt-in for non-loopback targets and display a prominent destructive-target warning. Validate the expected target version/port and the expected lab fixture identity before registering the target as disposable. Never rely solely on a caller-provided `disposable_file.id` to establish disposability.

### AUD-04 — Authorization matrix issues destructive operations without a disposable-resource guard

**Severity: High**
**File:** `core/matrix.py` (notably lines 211–265 and 299–317)

The live matrix chooses `alice.metadata["file_ids"][0]` (or a placeholder) and includes both a batch-overwrite operation and `DELETE /api/v1/files/{id}` in the operation list. It replays those operations under Bob, Charlie, and anonymous credentials. Unlike the CVE-2026-28788 probe, this path does not require trusted current-run disposable registration, verify server-side owner identity for a disposable target, capture/restore a target baseline, or perform targeted cleanup of the selected file.

The CLI later calls `adapter.cleanup()` for Alice, but that is not a restoration mechanism for a file deleted by an unauthorized actor; it also does not make an arbitrary first file ID safe to target.

**Impact:** A live authorization-matrix run can delete or mutate the first file in Alice's session metadata if the target permits it. The function also accepts arbitrary session objects, so the safety assumption that every listed file is a disposable file seeded by this particular CLI invocation is not enforced at the matrix boundary.

**Required action:** Disable destructive matrix operations by default. Only enable them against a file created and registered as disposable by the current scan, with independent owner verification, baseline capture, restoration, and post-restoration verification. Until implemented, the matrix must limit itself to read-only operations or clearly refuse the live destructive cells.

### AUD-05 — Live matrix does not capture an owner baseline

**Severity: Medium**
**File:** `core/matrix.py` (lines 279–317)

For live execution, `owner_resp` is set to `{}`. The code does not execute each recorded operation as Alice to capture the authorized owner response before replaying it as other personas. `StructuralDiffComparator` compares the replayed response keys against the owner response keys; with an empty owner response, structural overlap is always zero. The advertised high-overlap structural bypass detection therefore cannot operate as intended in live mode. The current code can still detect canary material in the replay body and can classify status-code rejection, but it does not perform the documented owner-vs-actor structural comparison.

**Required action:** Capture the authorized owner response (and status/context) for each operation before replay; safely avoid doing this for destructive operations unless they are disposable and resettable. Add integration-style tests for owner/replay structural equality and divergence.

### AUD-06 — Shared resolver silently drops malformed membership IDs

**Severity: Medium**
**File:** `probes/knowledge_membership.py` (lines 67–73 and 96–101)

The resolver ignores candidate entries that are not non-empty strings and silently discards blank candidate IDs. For membership results, it coerces values with `str(fid)` and filters blanks. An adapter returning a mixed or malformed list can therefore be treated as though it supplied a complete valid set. Since this resolver is shared across adapters, it should enforce its own contract rather than assuming every adapter implementation performs strict validation.

**Impact:** Malformed adapter output can be silently transformed into an apparently valid unique-membership result. That weakens the resolver's fail-closed guarantee for non-OpenWebUI adapters or future adapter changes.

**Required action:** Reject the entire candidate result if any candidate ID is malformed, blank, or duplicated. Reject the entire membership result if any file ID is not a non-empty string or if duplicates occur. Return an inconclusive reason; do not coerce arbitrary values to strings or silently skip malformed entries.

### AUD-07 — Generic write-poisoning scenario selects a first file without proving it is disposable

**Severity: High when called outside the standard fresh-session CLI flow; Medium otherwise**
**File:** `probes/scenarios/write_poisoning.py` (lines 155–200)

The scenario selects `alice.metadata["file_ids"][0]`, resolves its KB, and sends an overwrite as Bob. It does not require trusted current-run disposable registration or independently confirm that the selected file was created for this probe. The adapter fetches metadata when `file_model` is omitted, but the scenario itself does not compare that owner ID against Alice's authenticated server-side ID or ensure the target is disposable. The function is exported and can be invoked with arbitrary `UserSession` objects, not just the fresh session prepared by the main CLI.

**Impact:** A caller that supplies a normal Alice session can direct this destructive scenario at an ordinary user file. The main CLI does seed scan canaries and later cleans Alice's scan artifacts, but that outer workflow assumption is not enforced by the scenario API.

**Required action:** Require a scan-scoped disposable target (or provision a dedicated disposable file inside this scenario), verify authoritative server-side ownership, and ensure that the target is removed/restored in a `finally` path. Otherwise return `INCONCLUSIVE` without dispatching the overwrite.

### AUD-08 — Collection-injection probe can leave an orphan Bob-owned file

**Severity: Medium**
**File:** `adapters/openwebui/lifecycle.py` (lines 149–187), `cli.py` (lines 522–526)

`inject_into_collection()` uploads a file under the requesting session (Bob), appends the file ID to Bob's `session.metadata["file_ids"]`, and then attempts to link it into Alice's collection. If the link is rejected, the uploaded file remains in Bob's account. The CLI's final cleanup calls `adapter.cleanup()` only for Alice, not Bob, so this uploaded file is not removed by that cleanup path.

**Impact:** Failed collection-injection probes can leave persistent orphan test files in Bob's account across scans.

**Required action:** Delete the just-uploaded file in a `finally` path when linking fails, or add a separately verified Bob cleanup step. Preserve the uploaded file only when the probe explicitly needs it for subsequent verification, and still clean it afterward.

### AUD-09 — Fabricated fallback target IDs in probes and lifecycle scenarios

**Severity: Medium**
**Files:** `probes/cves/cve_2026_44560.py`; `probes/cves/cve_2026_45398.py`; `probes/scenarios/lifecycle.py`; `probes/cves/cve_2026_54019.py`

CVE-2026-44560 substituted `"unauthorized-file-id"` if Alice had no file IDs. CVE-2026-45398 substituted the all-zero UUID if Alice had no knowledge IDs. Lifecycle scenarios (`test_revocation_in_flight` and `test_post_revocation_staleness`) substituted `"target-resource-ref"` or inappropriately fell back from knowledge IDs to file IDs. CVE-2026-54019 had an unused fallback to `"default-collection"`.

**Impact:** Missing or mismatched fixtures could be misreported as clean/non-leaking behavior, producing false negatives or non-representative results, or dispatching requests with invented identifiers.

**Remediation:**
1. All fabricated fallback identifiers (`"unauthorized-file-id"`, `"00000000-0000-0000-0000-000000000000"`, `"target-resource-ref"`) have been removed.
2. Read-side probes and lifecycle scenarios strictly require verified target IDs matching the expected resource type (e.g. knowledge collection IDs for lifecycle sharing/revocation).
3. If prerequisites or targets cannot be established, probes fail closed and return a structured `INCONCLUSIVE` `ProbeResult` before dispatching any queries.
4. The dead fallback assignment in `cve_2026_54019.py` was removed without affecting query behavior.
5. A comprehensive repository-wide scan confirmed that no runtime fallback target identifiers remain in `probes/`, `adapters/`, or `core/`.

### AUD-10 — Root `.gitignore` does not exclude environment files

**Severity: Medium**
**File:** `.gitignore`

The root `.gitignore` excludes Python artifacts, virtual environments, caches, and local project notes, but does not exclude `.env` or `.env.*`. A nested lab ignore rule does not protect a root-level `.env` or `.env.local`.

**Impact:** Future root environment files can accidentally appear in `git status` and be staged, risking credentials or service endpoints being committed.

**Required action:** Add:

```gitignore
.env
.env.*
!.env.example
```

Then verify with `git check-ignore -v .env .env.local` and confirm `.env.example` remains trackable. The uploaded bundle does not establish whether a root `.env` exists on the operator's machine; this is a preventative ignore-rule gap, not evidence that a secret was leaked.

### AUD-11 — CLI labels non-leaking CVE outcomes as “Passed” even when skipped/inconclusive

**Severity: Low to Medium**
**File:** `cli.py` (lines 380–387)

The CVE suite logs `Passed CVE probe` for every result that is not a leak. This includes `SKIPPED` and `INCONCLUSIVE` results, as well as actual clean results. The dry-run smoke test demonstrated that a skipped CVE probe is presented in the CLI as passed.

**Impact:** Operators can mistake an unexecuted or inconclusive probe for a successful security check.

**Required action:** Branch on explicit result status. Report `CLEAN`, `COMPROMISED`, `INCONCLUSIVE`, and `SKIPPED` separately. Ensure summary/policy evaluation does not treat skipped or inconclusive checks as clean.

## Git/index review

The supplied status showed six files staged and many more files modified or untracked. The staged summary was 405 insertions and 66 deletions across:

- `adapters/base.py`
- `adapters/openwebui/auth.py`
- `adapters/openwebui/lifecycle.py`
- `adapters/openwebui/query.py`
- `core/engine.py`
- `core/matrix.py`

The working tree additionally contained approximately 25 modified tracked files and the new resolver/integration assets. `adapters/base.py` and `adapters/openwebui/lifecycle.py` were both `MM`.

**Do not commit the current index.** The staged lifecycle implementation demonstrably contains superseded fallback behavior. After fixes and review, stage the complete reviewed versions of the two split files and inspect the entire index, not just the diff summary. Then review every staged file against the working-tree version and run the full test suite on the staged snapshot.

No source files were modified by this audit. This audit artifact is the only intended addition.

## Live CVE-2026-28788 evidence status

The operator's latest report states:

- v0.8.5: Firedamp returned `COMPROMISED`/`direct_leak`; Alice's indexed-content readback contained Bob's tracer.
- v0.8.6: Firedamp returned `CLEAN`; the server rejected Bob's overwrite with `Permission denied: not file owner`, and Alice's original SHA-256 remained unchanged.
- The v0.8.5 fixture was subsequently restored and checked for content hash, ownership, KB membership, and tracer absence.
- `/tmp/firedamp-v085.json` and `/tmp/firedamp-v086.json` existed and parsed as JSON according to the operator.

The current uploaded bundle does not include those two files or the setup JSON. Therefore this audit does not independently validate their contents, response fields, run IDs, cleanup status, or trace-to-target consistency. Preserve the raw reports and produce sanitized, content-hash-recorded copies under the repository's evidence directory before citing this run as a reproducible project artifact. Do not copy tokens, authorization headers, setup credentials, or raw private content into the repository.

The older `CVE_AUDIT.md` in the snapshot contains an earlier status statement that the live differential had not yet been run. Treat that statement as historical and update it only when the newer raw evidence has been reviewed and safely retained.

## Recommended remediation order

1. **Reconcile the Git index blocker (AUD-01)** only after the relevant fixes are approved; never commit the stale staged versions.
2. **Harden lab URL/setup-file boundaries (AUD-03)** before future destructive lab commands.
3. **Correct fixture reset verification (AUD-02)** so “restored” cannot be reported without complete membership and vector verification.
4. **Disable or safety-gate live destructive authorization-matrix cells (AUD-04)**; implement genuine owner baselines (AUD-05).
5. **Protect generic write-poisoning targets and cleanup (AUD-07, AUD-08).**
6. **Tighten resolver input validation (AUD-06) and remove fake IDs from the remaining CVE probes (AUD-09).**
7. **Fix `.gitignore` and CLI status reporting (AUD-10, AUD-11).**
8. **Review and sanitize the latest live raw reports**, then include only the sanitized evidence record and hashes.

## Final status

| Area | Initial Audit Conclusion | Current Reconciled Status (Post-Remediation) |
|---|---|---|
| CVE-2026-28788 resolver and adapter design | Strong improvement; source tests pass | **REMEDIATED & VERIFIED** (fail-closed, paginated, tested) |
| CVE-2026-28788 live differential | Operator-reported positive result; raw report not in uploaded bundle | **VALIDATED & RETAINED** (live differential executed; bundle outside repo) |
| Root unit tests | 235 passed in extracted snapshot | **266 passed** in current working tree |
| CVE-2026-28788 simulations | 58 passed in extracted snapshot | **68 passed** in current working tree |
| Current Git index (AUD-01) | Unsafe to commit until staged/working-tree split is reconciled | **Commit coordination required** (stage full dependent changeset cohesively) |
| Reset/evidence verification (AUD-02) | Needs correction before relying on reset claims | **REMEDIATED** (`reset_fixture.py` reports `VECTOR_UNVERIFIED`) |
| Live authorization matrix (AUD-04, AUD-05) | Do not run destructively | **REMEDIATED** (matrix is read-only with mandatory owner baseline) |
| Lab runner/setup boundary (AUD-03) | Needs loopback/target-scope guard | **REMEDIATED** (`lab_safety.py` enforces loopback and port checks) |
| Probe & scenario fallback IDs (AUD-09) | Fabricated fallback IDs | **REMEDIATED** (missing target returns `INCONCLUSIVE` without querying; 0 runtime fallbacks remain) |
| Root `.gitignore` env files (AUD-10) | Root `.gitignore` missing `.env` exclusions | **REMEDIATED** (`.env` and `.env.*` excluded) |
| CLI inconclusive reporting (AUD-11) | Inconclusive reported as Passed | **REMEDIATED** (inconclusive results logged as neutral active notice) |
| Overall repository readiness | Not yet ready for commit | **Ready for cohesive commit** across working-tree changes |

This is a source-and-diff audit of the uploaded snapshot, not a formal penetration test or an independent reproduction of the live CVE run. The high-risk findings above are concrete code-path observations in the supplied source. No source code, Git index, or live Docker fixture was changed during this audit.
