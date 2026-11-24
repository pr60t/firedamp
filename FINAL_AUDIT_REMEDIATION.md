# Firedamp — Final Audit Remediation Addendum

**Scope:** Remediation against the high-priority findings recorded in `FINAL_AUDIT.md`, using the supplied repository snapshot. This addendum records the changes made in the remediation overlay; it does not replace the original audit.

## Summary

The high-priority destructive-operation and lab-boundary findings have been addressed in the supplied working-tree snapshot. Changes are intentionally conservative: when the adapter cannot establish ownership, provenance, exact membership, or a safe scoped operation, the probe returns `INCONCLUSIVE` or refuses the mutation rather than guessing.

## Findings addressed

### 1. Authorization matrix destructive-operation risk

- The authorization matrix is explicitly read-only: it compares owner baselines and replays metadata/content/knowledge-base reads plus vector retrieval queries.
- Destructive overwrite and DELETE operations are excluded from the matrix and remain the responsibility of separately guarded probes.
- Live matrix execution requires an exact file-to-KB resolution and a successful 2xx owner baseline for each operation. Malformed, missing, or failed owner baselines produce `INCONCLUSIVE` cells rather than a bypass classification.
- Added/retained regression coverage for failed and malformed owner baselines.

### 2. Lab setup and target-file trust

- Lab scripts share `lab_safety.py` validation: loopback targets are restricted to the pinned version/port pairs (`127.0.0.1:13085` for v0.8.5 and `127.0.0.1:13086` for v0.8.6); non-loopback use requires an explicit opt-in and expected supported version.
- Setup files are validated for restrictive filesystem permissions, lab identity/schema, distinct Alice/Bob identities and credentials, fixture identity, and baseline hash shape.
- Preflight independently verifies target version, Alice and Bob roles/IDs, Alice ownership of the declared KB, Alice ownership of the exact disposable file, exact KB membership, Bob's intended read access, and the pristine indexed-content baseline before destructive reproduction.
- Lab setup now creates a uniquely named disposable KB per run rather than reusing a KB based on its display name. This avoids attaching test files to a pre-existing user knowledge base.
- Setup now also refuses to create the disposable KB/file if Alice and Bob resolve to the same server-side user ID or bearer token. The provisioning simulation uses distinct mocked identities and covers the early-abort path.

### 3. Reset reporting and vector-store evidence

- Reset validates the target and full pre-reset KB membership before performing restoration.
- It requests targeted removal for the disposable file, restores indexed content, then independently checks the content hash, owner, target membership, and preservation of other file associations.
- The available nearest-neighbor/top-k retrieval query is not exhaustive evidence of vector absence. The reset therefore reports vector cleanup as **UNVERIFIED** and does not claim that all vector chunks were removed. A positive attacker-marker observation is treated as a failure.
- The explicit reset status remains `RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED`.

### 4. Generic write-poisoning and cleanup safeguards

- File-overwrite probes require a current-run registry entry, an exact disposable ID not present in the pre-scan ordinary-file snapshot, verified Alice/Bob identities, server-side file ownership, an unchanged scan-time baseline hash, and exact file-to-KB membership.
- Unresolved or ambiguous membership, missing provenance, malformed metadata, or failed readback prevents an overwrite or produces `INCONCLUSIVE`.
- Collection injection requires a current-run Alice disposable anchor, verified anchor ownership, exact KB membership, and server-side Alice ownership of the target KB.
- OpenWebUI upload responses preserve the newly created file ID even when KB linking fails. The scenario verifies Bob's ownership, registers that exact upload as a current-run disposable, and performs targeted cleanup. It refuses to delete a pre-existing Bob file ID.
- The base adapter's default collection-injection method remains fail-closed (`501`) instead of treating a collection ID as a file ID.
- OpenWebUI generic cleanup no longer deletes every file or KB listed in session metadata. It only considers current-run trusted disposable file IDs and rechecks authenticated identity and server-side ownership before deletion. It never deletes pre-existing knowledge bases.
- The delete-while-indexing lifecycle scenario now returns `INCONCLUSIVE` (or a non-mutating dry-run result) until a verified cancellable-ingestion handle and scoped cancellation API exist. It no longer invokes broad cleanup as part of that scenario.

## Additional correctness hardening

- The shared file-to-KB resolver rejects malformed, blank, or duplicate candidate KB IDs and malformed or duplicate file membership IDs instead of coercing or silently dropping them.
- `.gitignore` now excludes `.env` and `.env.*` files while allowing `.env.example`.
- CLI disposable registration retains ordinary file IDs for read-side probes but keeps a separate pre-existing-file snapshot and disposable allow-list for destructive probes.

## Verification performed on the supplied snapshot

| Check | Result |
|---|---:|
| `python3 -m unittest discover tests -p 'test_*.py'` | **251 passed** |
| `python3 -m unittest discover tests/integration/openwebui_cve_2026_28788/simulations -p 'test_*.py'` | **68 passed** |
| `python3 -m compileall -q adapters core probes cli.py tests/integration/openwebui_cve_2026_28788/scripts` | **Passed** |

No failures or errors were reported by the two discovery runs. The test totals are separate: the 67 integration simulation tests are outside `tests/` root discovery.

The working snapshot does not contain a `.git` directory, so `git diff --check` could not be run against the user's actual repository index in this environment. A temporary Git baseline comparison was used for whitespace checking of the remediation overlay; it does not alter the user's Git repository or index. After an additional setup-identity collision guard and regression test were added, root discovery remained at 251 tests and the simulation suite increased to 68 passing tests.

## Explicit limitations and deferred findings

- No live Docker probes were run during this remediation pass. The earlier v0.8.5/v0.8.6 live differential is an operator-reported result from the prior session. Its raw `/tmp/firedamp-v085.json` and `/tmp/firedamp-v086.json` files were not included in the uploaded audit bundle, so this addendum does not independently re-verify those reports.
- Vector cleanup remains unverified by design because the available public top-k query cannot prove exhaustive vector absence.
- The CLI reporting issue (AUD-11) where non-leak `INCONCLUSIVE` results were logged as “Passed” has been remediated in the final pre-commit pass: `cli.py` now branches on `res.is_inconclusive` to log neutral active notices.
- The CLI currently contains built-in example Alice/Bob credentials. Before treating the general-purpose CLI as production-ready for arbitrary targets, credential sourcing should be moved to explicit configuration/environment input and secrets must not be logged. This was not changed in this focused remediation pass.
- Historical fabricated fallback target IDs in read-side CVE probes and lifecycle scenarios (AUD-09: CVE-2026-44560, CVE-2026-45398, `probes/scenarios/lifecycle.py`, and `cve_2026_54019.py`) have been fully remediated: probes now require verified target IDs of the appropriate resource type and return `INCONCLUSIVE` without issuing attack queries when prerequisites are missing. Dead fallback code in `cve_2026_54019.py` has been excised, and a repository scan confirmed zero runtime fallback identifiers remain in `probes/`, `adapters/`, and `core/`.

## Repository application notes

This addendum and the accompanying overlay archive contain working-tree file contents only. They do not stage, unstage, reset, or commit anything. Applying the overlay in the user's checkout will update the working tree while leaving the existing Git index untouched. Review the resulting staged/unstaged differences before staging or committing.
