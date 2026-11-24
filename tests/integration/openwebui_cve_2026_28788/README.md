# CVE-2026-28788 Integration Testing & Evidence Lab

Reproducible, isolated integration testing and verification environment for **CVE-2026-28788** ([GHSA-jjp7-g2jw-wh3j](https://github.com/open-webui/open-webui/security/advisories/GHSA-jjp7-g2jw-wh3j)).

---

## 1. Vulnerability Overview

In Open WebUI prior to **v0.8.6**, the batch document reprocessing endpoint:
```http
POST /api/v1/retrieval/process/files/batch
```
failed to enforce ownership checks on the submitted file IDs. When an authenticated, non-admin user (e.g. Bob) had read access to a shared Knowledge Base containing files owned by another tenant (e.g. Alice), Bob could submit a `BatchProcessFilesForm` containing Alice's `FileModel` with modified `data.content`.

The backend updated `File.data.content` in the database directly, overwriting Alice's indexed text content with Bob's attacker-controlled tracer without requiring file ownership or write permissions.

In **v0.8.6**, Open WebUI introduced explicit ownership validation:
```python
db_file = Files.get_file_by_id(file.id)
if not (db_file.user_id == user.id or user.role == 'admin'):
    errors.append({"file_id": file.id, "status": "failed", "error": "Permission denied: not file owner"})
    continue
```
Returning `HTTP 200` with per-file failures in the `errors` array.

---

## 2. Lab Architecture & Ports

The environment runs isolated Docker containers bound strictly to the loopback interface (`127.0.0.1`):

| Service | Pinned Image Reference | Loopback Port | Purpose |
| :--- | :--- | :--- | :--- |
| `owui-vulnerable` | `ghcr.io/open-webui/open-webui:v0.8.5@sha256:6251d208f91373f755c6a42abdbf740d003775dcf2d78b8811a213a822e7350b` | `127.0.0.1:13085` | Demonstrates successful unauthorized overwrite |
| `owui-patched` | `ghcr.io/open-webui/open-webui:v0.8.6@sha256:4938a90d0b0fb2a7c361a254211704fab72e748c4c7649e5729947fdc56d9dea` | `127.0.0.1:13086` | Demonstrates authorization enforcement |

### Key Isolation Guarantees:
- **Dedicated Bridge Network:** `firedamp-cve-lab-net` prevents unintended inter-service crosstalk.
- **Isolated Volumes:** `firedamp-owui-v085-data` and `firedamp-owui-v086-data`.
- **Healthcheck Enabled:** Automatic container readiness probes via `/health`.

---

## 3. Directory Structure

```
tests/integration/openwebui_cve_2026_28788/
├── compose.yaml                      # Pinned Docker Compose environment
├── .env.example                      # Secret keys and configuration template
├── .gitignore                        # Lab ephemeral data ignores
├── README.md                         # Architecture and usage guide
├── requirements.txt                  # Python lab dependencies
├── fixtures/
│   ├── alice_original.txt            # Baseline tenant document
│   └── attacker_marker.txt           # Unique tracer payload
├── scripts/
│   ├── preflight.sh                  # Host, daemon, manifest, port preflight check
│   ├── setup_lab.py                  # User, KB, file provisioning via API
│   ├── reproduce_cve.py              # Direct HTTP exploit verification
│   ├── run_firedamp_probe.py         # Full Firedamp engine probe execution
│   ├── collect_evidence.py           # Automated evidence aggregator
│   └── cleanup_lab.sh                # Container and volume teardown
├── simulations/
│   ├── fixtures/                     # Upstream response vectors (v0.8.5, v0.8.6, errors)
│   └── test_response_classification.py # 100% offline deterministic test suite
├── evidence/                         # Versioned evidence bundles
│   ├── historical/                   # Preserved prior runs
│   ├── offline_simulation/           # Deterministic offline contract simulation runs
│   │   └── run_<timestamp>/          # Simulation artifacts, traces, verified checksums
│   └── live/                         # Live container exploit reproduction runs
│       └── run_<timestamp>/          # Live container artifacts, traces, verified checksums
```

---

## 4. Usage Instructions

### A. Preflight Environment Check
Run the preflight script to inspect Docker, image manifests, and port availability:
```bash
bash tests/integration/openwebui_cve_2026_28788/scripts/preflight.sh
```

### B. Offline Deterministic Verification (CI & Sandbox Safe)
When Docker daemon access is restricted, run the deterministic simulation suite directly:
```bash
python3 -m unittest discover tests/integration/openwebui_cve_2026_28788/simulations/ -v
```
This suite verifies:
1. Pinned vulnerable response classification (`COMPROMISED`).
2. Pinned patched response classification (`CLEAN`).
3. Rejection of contradictory responses (`INCONCLUSIVE`).
4. Rejection of unauthenticated attacker attempts (`INCONCLUSIVE`).
5. Pre-write safety gates against non-registered or unverified targets.

### C. Live Container Verification (Authorized Operator with Sudo or Rootless Docker)
When running on a host with authorized Docker access:
```bash
# Option 1: Using Sudo (when operator has sudo privileges)
USE_SUDO=1 bash tests/integration/openwebui_cve_2026_28788/scripts/preflight.sh --use-sudo
sudo docker compose -f tests/integration/openwebui_cve_2026_28788/compose.yaml up -d

# Option 2: Standard/Rootless Docker (when user has direct daemon access)
bash tests/integration/openwebui_cve_2026_28788/scripts/preflight.sh
docker compose -f tests/integration/openwebui_cve_2026_28788/compose.yaml up -d

# 2. Setup targets via API
python3 tests/integration/openwebui_cve_2026_28788/scripts/setup_lab.py --url http://127.0.0.1:13085 --output /tmp/setup-v085.json
python3 tests/integration/openwebui_cve_2026_28788/scripts/setup_lab.py --url http://127.0.0.1:13086 --output /tmp/setup-v086.json

# 3. Direct Exploit Reproduction
python3 tests/integration/openwebui_cve_2026_28788/scripts/reproduce_cve.py --setup-file /tmp/setup-v085.json
python3 tests/integration/openwebui_cve_2026_28788/scripts/reproduce_cve.py --setup-file /tmp/setup-v086.json

# 4. Run Firedamp Behavioral Probe
python3 tests/integration/openwebui_cve_2026_28788/scripts/run_firedamp_probe.py --setup-file /tmp/setup-v085.json
python3 tests/integration/openwebui_cve_2026_28788/scripts/run_firedamp_probe.py --setup-file /tmp/setup-v086.json

# 5. Teardown
bash tests/integration/openwebui_cve_2026_28788/scripts/cleanup_lab.sh
# Or with sudo: USE_SUDO=1 bash tests/integration/openwebui_cve_2026_28788/scripts/cleanup_lab.sh --use-sudo
```

### D. Automated Evidence Collection
Generate a timestamped, signed evidence bundle:
```bash
python3 tests/integration/openwebui_cve_2026_28788/scripts/collect_evidence.py
```
Outputs:
- `summary.md`: Human-readable markdown summary report.
- `evidence.json`: Main structured JSON evidence report.
- `environment.json`: Host, Docker, Python, kernel, git commit/branch, image digests, port availability.
- `image-manifest.json`: Exact pinned image references, architectures, and manifest digests.
- `setup-alice.json`: Alice persona, user ID, victim file ID, original file content hash, KB ID.
- `setup-bob.json`: Bob persona, user ID, shared KB read-only access.
- `vulnerable-v085.json`: Reproduction on v0.8.5 with explicit execution mode and expected verdict.
- `patched-v086.json`: Reproduction on v0.8.6 with explicit execution mode and expected verdict.
- `firedamp-v085.json`: Firedamp probe execution on v0.8.5.
- `firedamp-v086.json`: Firedamp probe execution on v0.8.6.
- `content-verification.json`: Cryptographic verification of baseline vs post-attack content.
- `controls.json`: Offline simulation suite execution results.
- `http-trace-redacted.jsonl`: Redacted HTTP requests and responses.
- `cleanup.json`: Cleanup authorization and verification record.
- `SHA256SUMS.txt`: Cryptographic SHA-256 checksums covering every file in the bundle.

---

## 5. Security & Safety Controls

1. **Readback Safety:**
   - Reads exclusively from `GET /api/v1/files/{id}/data/content` (where `File.data.content` lives).
   - Never infers vulnerability from `GET /api/v1/files/{id}/content` (the binary file).
2. **Scan-Scoped Registry & Provenance:**
   - Target files must be registered in the internal `TrustedScanDisposableRegistry`.
   - Rejects unverified or stale IDs in mutable session metadata.
3. **Fail-Closed Pre-Write Gate:**
   - Checks server-side ownership before sending any destructive HTTP requests.
   - If server metadata is missing or mismatched, aborts with `INCONCLUSIVE`.
4. **Authorized Cleanup:**
   - Only issues `DELETE` requests if the resource was provisioned by the current run and verified to belong to Alice.
