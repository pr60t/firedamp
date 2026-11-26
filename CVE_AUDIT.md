# Firedamp Security Regression Engine: Third-Pass Forensic Verification Audit & Data Integrity Report

> **Historical Record Notice (2026-11-18):**
> - **Audit Date:** 2026-11-18 | **Baseline Branch:** `fix/cve-catalog-integrity` | **Validation Type:** Advisory verification & offline simulation only (`NOT TESTED` against live containers as of 2026-11-18).
> - **Post-Audit Supplement:** For the later operator-reported live differential validation of `CVE-2026-28788` (Open WebUI `v0.8.5` vs `v0.8.6`) and current status across all entries, see [docs/audits/README.md](docs/audits/README.md).

- **Audit Date:** 2026-11-18
- **Audit Target:** `fix/cve-catalog-integrity` branch
- **Auditor:** Senior Application Security Researcher & Vulnerability Analyst
- **Standard of Review:** Absolute Forensic Rigor against upstream GitHub Security Advisories (GHSA), CVE.org, NIST NVD, and vendor bulletins.

---

## 1. Executive Summary & Audit Methodology

This report represents the third-pass, authoritative forensic verification of Firedamp's 21-CVE security regression system. It eliminates all residual errors, corrects version-source attribution conflicts, replaces obsolete PoC injection syntax, aligns probe execution paths with actual vulnerable source functions, documents verified attack preconditions across all 21 entries, and provides transparent disclosures regarding package isolation and Docker limitations.

### Strict Verification Classifications:
- **VERIFIED:** Confirmed by an authoritative record (CVE.org / NIST NVD / GHSA / Vendor Security Bulletin) with matching source implementation.
- **PARTIALLY VERIFIED:** Core vulnerability confirmed, but specific material details (such as branch-specific version tags or configuration triggers) have nuances across secondary databases.
- **CONFLICTING:** Authoritative sources officially disagree (e.g., NVD vs. vendor advisory on fixed version or CWE classification).
- **UNVERIFIED:** Lacks sufficient authoritative supporting evidence.
- **NOT TESTED:** No live target container reproduction was performed (due to offline/sandboxed environment without a Docker daemon).

---

## 2. Authoritative 21-Entry CVE Forensic Register

| # | CVE ID | Official GHSA ID | Authoritative Advisory URL | Product (Actual) | Affected Version Range | Patched Version | CWE Classification & Source Attribution | Probe Status | Advisory Verification | Live Probe Validation | Documented Preconditions |
|:---:|:---|:---|:---|:---|:---|:---|:---|:---:|:---:|:---:|:---|
| 1 | **CVE-2026-44560** | `GHSA-h36f-rqpx-j5wx` | [GHSA-h36f-rqpx-j5wx](https://github.com/open-webui/open-webui/security/advisories/GHSA-h36f-rqpx-j5wx) | Open WebUI | `<= 0.8.12` | `>= 0.9.0` | CWE-862 (NVD / Aggregated Advisory; unassigned in upstream GHSA) | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) | `authenticated_user`, `knowledge_of_victim_file_id_or_kb_uuid`, `already_indexed_vector_resource`. |
| 2 | **CVE-2026-45398** | `GHSA-4g37-7p2c-38r9` | [GHSA-4g37-7p2c-38r9](https://github.com/open-webui/open-webui/security/advisories/GHSA-4g37-7p2c-38r9) | Open WebUI | `<= 0.9.4` | `0.9.5` | CWE-639 (Insecure Direct Object Reference) [Read-Side Retrieval Scope] | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) | `authenticated_user`, `knowledge_of_victim_kb_uuid`. |
| 3 | **CVE-2026-28788** | `GHSA-jjp7-g2jw-wh3j` | [GHSA-jjp7-g2jw-wh3j](https://github.com/open-webui/open-webui/security/advisories/GHSA-jjp7-g2jw-wh3j) | Open WebUI | `< 0.8.6` | `0.8.6` | CWE-639 (Insecure Direct Object Reference) | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) | `authenticated_user`, `knowledge_of_victim_file_id`. |
| 4 | **CVE-2026-54019** | `GHSA-p5cp-r7rg-qpxc` | [GHSA-p5cp-r7rg-qpxc](https://github.com/open-webui/open-webui/security/advisories/GHSA-p5cp-r7rg-qpxc) | Open WebUI | `< 0.9.6` | `0.9.6` | CWE-862 & CWE-943 (Missing Auth & Query Injection, GHSA/NVD) | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) | `authenticated_user`, `milvus_backend`, `milvus_multitenancy`. |
| 5 | **CVE-2026-45301** | `GHSA-r8wh-8m7r-fh33` | [GHSA-r8wh-8m7r-fh33](https://github.com/open-webui/open-webui/security/advisories/GHSA-r8wh-8m7r-fh33) | Open WebUI | `< 0.3.16` | `0.3.16` | CWE-284 (Improper Access Control, GHSA/NVD) | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) | `authenticated_user`, `files_api_access`. |
| 6 | **CVE-2026-44557** | `GHSA-6c2x-gcp3-gp73` | [GHSA-6c2x-gcp3-gp73](https://github.com/open-webui/open-webui/security/advisories/GHSA-6c2x-gcp3-gp73) | Open WebUI | `< 0.9.0` | `0.9.0` | CWE-200 / CWE-862 / CWE-863 (NVD / Aggregated; unassigned in upstream GHSA) | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) | `authenticated_user`, `retrieval_query_access`. |
| 7 | **CVE-2026-54016** | `GHSA-cx9v-4qj2-jrw6` | [GHSA-cx9v-4qj2-jrw6](https://github.com/open-webui/open-webui/security/advisories/GHSA-cx9v-4qj2-jrw6) | Open WebUI | `< 0.9.6` | `0.9.6` | CWE-639 / CWE-862 (GHSA-cx9v-4qj2-jrw6) | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) | `authenticated_user`, `native_function_calling_enabled`, `model_without_attached_kb`, `knowledge_of_victim_kb_id`. |
| 8 | **CVE-2026-54010** | `GHSA-vrhc-3fr6-pc3c` | [GHSA-vrhc-3fr6-pc3c](https://github.com/open-webui/open-webui/security/advisories/GHSA-vrhc-3fr6-pc3c) | Open WebUI | `< 0.9.6` | `0.9.6` | CWE-284 / CWE-639 / CWE-862 (GHSA-vrhc-3fr6-pc3c) | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) | `authenticated_user`, `knowledge_of_victim_file_id`, `shared_chat_functionality`. |
| 9 | **CVE-2026-45349** | `GHSA-gfm2-xm6c-37qc` | [GHSA-gfm2-xm6c-37qc](https://github.com/open-webui/open-webui/security/advisories/GHSA-gfm2-xm6c-37qc) | Open WebUI | `<= 0.8.12` | `0.9.0` | CWE-639 (Authorization Bypass via Key, GHSA/NVD) | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) | `authenticated_user_api_key`, `knowledge_of_victim_chat_id`, `access_to_same_model`. |
| 10 | **CVE-2026-44561** | `GHSA-hmgr-67hw-j2cq` | [GHSA-hmgr-67hw-j2cq](https://github.com/open-webui/open-webui/security/advisories/GHSA-hmgr-67hw-j2cq) | Open WebUI | `< 0.9.0` | `0.9.0` | CWE-284 / CWE-863 (GHSA-hmgr-67hw-j2cq) | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) | `prior_channel_membership`, `knowledge_of_channel_id`, `channels_enabled`. |
| 11 | **CVE-2024-31621** | `GHSA-6wp6-22x5-rr3w` | [GHSA-6wp6-22x5-rr3w](https://github.com/advisories/GHSA-6wp6-22x5-rr3w) | FlowiseAI Flowise | `< 1.8.1` (GHSA) / `<= 1.6.2` (NVD) | `1.8.1` | CWE-94 / CWE-287 (Code Injection in api/v1) | `documented` | **CONFLICTING (VERSIONS)** | **NOT TESTED** (Documented Only) | `network_access_to_api_v1`. |
| 12 | **CVE-2024-52306** | `GHSA-8237-957h-h2c2` | [GHSA-8237-957h-h2c2](https://github.com/advisories/GHSA-8237-957h-h2c2) | Laravel Backpack FileManager | `< 2.0.2` and `>= 3.0.0, < 3.0.9` | `2.0.2` and `3.0.9` | CWE-502 (Insecure Deserialization) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `filemanager_endpoint_access`. PHP Laravel package; misattributed to Flowise. |
| 13 | **CVE-2024-52307** | `GHSA-2xrw-5f2x-m56j` | [GHSA-2xrw-5f2x-m56j](https://github.com/goauthentik/authentik/security/advisories/GHSA-2xrw-5f2x-m56j) | authentik IDP | `< 2024.8.5` and `2024.10.0 - 2024.10.2` | `2024.8.5` and `2024.10.3` | CWE-208 (Timing Attack on Metrics) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `metrics_endpoint_accessible`. Dual release branch patches confirmed. Misattributed to Flowise. |
| 14 | **CVE-2024-41133** | None (`HPESBNW04673`) | [HPESBNW04673](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04673en_us) | HPE Aruba EdgeConnect SD-WAN (ECOS) | ECOS 9.3 <= 9.3.3.0; 9.2 <= 9.2.9.0; 9.1 <= 9.1.11.0; 9.0/8.x all | `9.3.4.0` / `9.2.10.0` / `9.1.12.0` | CWE-78 (OS Command Injection) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `authenticated_admin_cli`. Proprietary router firmware; misattributed to Langflow. |
| 15 | **CVE-2024-43407** | `GHSA-7r32-vfj5-c2jv` | [GHSA-7r32-vfj5-c2jv](https://github.com/advisories/GHSA-7r32-vfj5-c2jv) | CKEditor 4 GeSHi Plugin | `< 4.25.0-LTS` | `4.25.0-LTS` | CWE-79 (Reflected XSS) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `geshi_plugin_enabled_php_host`. Rich-text editor; misattributed to Langflow. |
| 16 | **CVE-2024-52308** | `GHSA-p2h2-3vg9-4p87` | [GHSA-p2h2-3vg9-4p87](https://github.com/cli/cli/security/advisories/GHSA-p2h2-3vg9-4p87) | GitHub CLI (`gh`) | `<= 2.61.0` | `2.62.0` | CWE-78 (OS Command Injection via SSH) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `connect_to_malicious_codespace`. CLI utility; misattributed to Dify. |
| 17 | **CVE-2024-45388** | `GHSA-6xx4-x46f-f897` | [GHSA-6xx4-x46f-f897](https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-6xx4-x46f-f897) | Hoverfly API Simulation | `< 1.10.3` | `1.10.3` | CWE-22 (Path Traversal Arbitrary Read) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `simulation_endpoint_accessible`. Proxy tool; misattributed to Dify. |
| 18 | **CVE-2024-45389** | `GHSA-gprj-6m2f-j9hx` | [GHSA-gprj-6m2f-j9hx](https://github.com/CloudCannon/pagefind/security/advisories/GHSA-gprj-6m2f-j9hx) | Pagefind Static Search | `< 1.1.1` | `1.1.1` | CWE-79 (DOM Clobbering XSS) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `html_injection_capability`. Static search library; misattributed to LiteLLM. |
| 19 | **CVE-2024-42475** | `GHSA-332c-q46h-fg8f` | [GHSA-332c-q46h-fg8f](https://github.com/CORDEA/oauth/security/advisories/GHSA-332c-q46h-fg8f) | Nim `oauth` Library | `< 0.11` | `0.11` | CWE-330 (Insufficient State Entropy) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `oauth_state_usage`. Nim OAuth library; misattributed to LiteLLM. |
| 20 | **CVE-2024-45391** | `GHSA-4qrm-9h4r-v2fx` | [GHSA-4qrm-9h4r-v2fx](https://github.com/tinacms/tinacms/security/advisories/GHSA-4qrm-9h4r-v2fx) | TinaCMS | `< 1.6.2` | `1.6.2` | CWE-200 (Token Exposure in `tina-lock.json`) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `search_token_configured`. Headless CMS; misattributed to Milvus. |
| 21 | **CVE-2024-34359** | `GHSA-56xg-wfcc-g829` | [GHSA-56xg-wfcc-g829](https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829) | `llama-cpp-python` | `>= 0.2.30, <= 0.2.71` | `0.2.72` | CWE-76 (Equivalent Special Elements, GHSA/NVD) | `rejected` | **VERIFIED (QUARANTINED)** | **NOT APPLICABLE** (Quarantined) | `loading_untrusted_gguf_model`. Both GHSA and NVD agree on CWE-76; misattributed to ChromaDB. |

---

## 3. Detailed Audit & Factual Corrections Applied (Pass 3)

| CVE ID | Previous Second-Pass State | Third-Pass Corrected State | Upstream Authoritative Source |
|:---|:---|:---|:---|
| **CVE-2026-44560** | Claimed affected `< 0.9.0`; attack surface listed as `POST /api/v1/retrieval/query`; probe called direct vector endpoint. | Corrected affected versions to `<= 0.8.12` and fixed versions to `>= 0.9.0`. Attack surface updated to `POST /api/chat/completions`. Vulnerable component established as `get_sources_from_items()`. Probe repaired to dispatch chat completions with victim file attachments in `files`. | [GHSA-h36f-rqpx-j5wx](https://github.com/open-webui/open-webui/security/advisories/GHSA-h36f-rqpx-j5wx) |
| **CVE-2026-45398** | Listed CWE-863; affected `< 0.9.5`. | Corrected CWE to **CWE-639** (Insecure Direct Object Reference) as officially assigned by GHSA. Corrected affected versions to `<= 0.9.4`, fixed in `0.9.5`. | [GHSA-4g37-7p2c-38r9](https://github.com/open-webui/open-webui/security/advisories/GHSA-4g37-7p2c-38r9) |
| **CVE-2026-54019** | Contained obsolete `or 1==1` syntax in descriptions and comments; listed generic endpoint. | Replaced all occurrences of `1==1` with the verified advisory PoC `x' or resource_id != '' or resource_id == 'x`. Corrected affected endpoints to `POST /api/v1/retrieval/query/collection` and `POST /api/v1/retrieval/query/doc`. Preserved dual CWE classification (`CWE-862` & `CWE-943`). Defined separate vulnerable and patched behavioral telemetry. | [GHSA-p5cp-r7rg-qpxc](https://github.com/open-webui/open-webui/security/advisories/GHSA-p5cp-r7rg-qpxc) |
| **CVE-2026-54010** | Listed attack surface as `POST /api/v1/chats/new`. | Corrected attack surface to `POST /api/chat/completions` (or `POST /api/v1/chat/completions`). Corrected attack strategy and verification: attacker supplies victim file ID in `user_message.files`, creates a shared-chat link, and exploits `has_access_to_file()`. | [GHSA-vrhc-3fr6-pc3c](https://github.com/open-webui/open-webui/security/advisories/GHSA-vrhc-3fr6-pc3c) |
| **CVE-2024-31621** | Inaccurately attributed `< 1.6.6` to GHSA and described an unverified auth bypass fixed in 1.6.6. | Corrected: GHSA-6wp6-22x5-rr3w explicitly establishes affected versions as `< 1.8.1`, fixed in `1.8.1`. NVD CPE entry lists `<= 1.6.2`. Disclosed source conflict accurately. Reclassified strictly as code injection in `api/v1`. | [GHSA-6wp6-22x5-rr3w](https://github.com/advisories/GHSA-6wp6-22x5-rr3w) & [NVD CVE-2024-31621](https://nvd.nist.gov/vuln/detail/CVE-2024-31621) |
| **CVE-2024-52306** | Listed a single generic `< 3.0.9` affected range. | Corrected to account for both supported release branches: `< 2.0.2` (fixed in `2.0.2`) and `>= 3.0.0, < 3.0.9` (fixed in `3.0.9`). | [GHSA-8237-957h-h2c2](https://github.com/Laravel-Backpack/FileManager/security/advisories/GHSA-8237-957h-h2c2) |
| **CVE-2024-34359** | Second-pass report erroneously claimed GHSA listed CWE-94 while NVD listed CWE-76. | Corrected: Upstream advisory GHSA-56xg-wfcc-g829 officially classifies this vulnerability as **CWE-76**. Both GHSA and NVD agree; false conflict eliminated. | [GHSA-56xg-wfcc-g829](https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829) |
| **Preconditions** | Multiple catalog entries contained empty `attack_preconditions` arrays. | Audited all 21 records against upstream advisories. Added genuine prerequisites (authentication, victim resource IDs, vector DB backends, Milvus multitenancy, function calling, channel membership). Zero invented prerequisites. | Authoritative advisories 1-21 |

---

## 4. Deep-Dive Review of the Four Implemented Probes

### 1. `CVE-2026-44560` ([cve_2026_44560.py](probes/cves/cve_2026_44560.py))
- **Advisory:** `GHSA-h36f-rqpx-j5wx` (Open WebUI `<= 0.8.12`, fixed in `>= 0.9.0`).
- **Target Function:** `get_sources_from_items()` in `backend/open_webui/retrieval/utils.py`.
- **Pipeline:** Chat completion request pipeline (`POST /api/chat/completions`).
- **Probe Implementation:** The probe issues chat completions with Bob attaching Alice's private `file_id` in the `files` array.
- **Strengthened Detection:** Detection inspects the complete Open WebUI response across:
  1. Generated assistant message content (`choices[0].message.content`).
  2. Citation metadata (`choices[0].message.citations`).
  3. Source references (`choices[0].message.sources`).
  4. Attached context chunks (`choices[0].context` and top-level `context`).
  5. Full stringified raw JSON response payload fallback.
- **Verdict:** **Accurately Implemented.** Confirmed leak requires detecting the actual cryptographic canary token.

### 2. `CVE-2026-45398` ([cve_2026_45398.py](probes/cves/cve_2026_45398.py))
- **Advisory:** `GHSA-4g37-7p2c-38r9` (Open WebUI `<= 0.9.4`, fixed in `0.9.5`).
- **Target Function:** `_validate_collection_access()`.
- **Target Endpoints:** `POST /api/v1/retrieval/query/collection` and `POST /api/v1/retrieval/query/doc`. All unverified fallback routes (such as `GET /api/v1/knowledge/{id}`) were completely excised.
- **Probe Scope:** Specifically covers the **retrieval read-side raw UUID authorization bypass** via `adapter.query_collection` and `adapter.query_doc`. It does **not** test write-side collection injection routes (`/process/text`, `/process/file`, `/process/files/batch`) from the advisory.
- **Probe Execution:** Bob queries using Alice's knowledge base raw UUID (e.g. `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
- **Vulnerability Mechanism:** In `<= 0.9.4`, the validation helper verified `user-memory-*` and `file-*` prefixes but allowed raw knowledge base UUIDs to pass through unchecked into retrieval endpoints.
- **Behavioral Verification:** Bob receives 403 Forbidden on `>= 0.9.5`; extracts Alice's canary tokens on `<= 0.9.4`.
- **Verdict:** **Accurately Implemented (Scoped to Retrieval Read-Side).**

### 3. `CVE-2026-28788` ([cve_2026_28788.py](probes/cves/cve_2026_28788.py))
- **Advisory:** `GHSA-jjp7-g2jw-wh3j` (Open WebUI `< 0.8.6`).
- **Target Endpoint:** `POST /api/v1/retrieval/process/files/batch`. The unsupported fallback (`POST /api/v1/files/batch/process`) was removed.
- **Independent Mutation Verification:** A successful HTTP request (`status=True`) is **not** accepted as confirmed poisoning. The probe independently reads back Alice's file through legitimate verification routes (`GET /api/v1/files/{id}/content` as Alice):
  1. If `bob_tracer.token` is confirmed in Alice's file content, report confirmed integrity violation (`DIRECT_LEAK`).
  2. If readback succeeds but content was not mutated, report clean.
  3. If readback cannot be completed, report the outcome as **`INCONCLUSIVE`** with zero false positive leak assertions.
- **Verdict:** **Accurately Implemented with Independent Readback Verification.**

### 4. `CVE-2026-54019` ([cve_2026_54019.py](probes/cves/cve_2026_54019.py))
- **Advisory:** `GHSA-p5cp-r7rg-qpxc` (Open WebUI `< 0.9.6`).
- **Target Endpoints:** `POST /api/v1/retrieval/query/collection` and `POST /api/v1/retrieval/query/doc`. The legacy generic `/api/v1/retrieval/query` route was replaced.
- **Exact PoC Payload:** Matches the official advisory specification:
  ```json
  {
    "collection_names": ["x' or resource_id != '' or resource_id == 'x"],
    "query": "anything",
    "k": 10,
    "hybrid": false
  }
  ```
- **Technical Analysis:** In Milvus multitenancy mode, the collection name is mapped to `resource_id` in filter expressions: `expr = f"resource_id == '{resource_id}'"`. The advisory PoC `x' or resource_id != '' or resource_id == 'x'` evaluates to boolean true across all non-empty Milvus entity partitions, extracting cross-tenant chunks.
- **Behavioral Verification:** On `< 0.9.6` under `milvus_multitenancy`, the probe detects cross-tenant canary chunks. On `>= 0.9.6`, the input is sanitized/rejected with HTTP 400 Bad Request.
- **Verdict:** **Accurately Implemented.** Endpoints, method, and request payloads match official advisory.

---

## 5. Audit of Modified Tests

1. **[tests/test_cve_probes.py](tests/test_cve_probes.py):**
   - Updated `test_cve_2026_44560_clean` and `test_cve_2026_44560_leak` to assert calls to `adapter.query_rag(..., files=[{"type": "file", "id": "f123"}])` with channel `citation_metadata`. Reflects the real chat completion attack path.
   - Updated `test_cve_2026_54019_resource_id_injection_syntax` to verify that `resource_id` appears in the query string without `1==1`.
2. **[tests/test_openwebui_adapter.py](tests/test_openwebui_adapter.py):**
   - Asserts that `overwrite_resource` sends requests to `POST /api/v1/retrieval/process/files/batch` matching `GHSA-jjp7-g2jw-wh3j`.
3. **[tests/test_cve_catalog.py](tests/test_cve_catalog.py):**
   - 7 automated integrity tests enforcing strict schema rules, non-empty fields, valid reference URLs, Tier-1 probe file existence, and exclusion of quarantined records.

---

## 6. Independent Packaging & Isolation Verification

### Packaging & Isolated Environment Audit:
1. **Isolated Virtual Environment Creation:**
   ```bash
   $ python3 -m venv --without-pip /tmp/clean_isolated_venv
   $ python3 -m pip install --no-deps --target /tmp/clean_isolated_venv/lib/python3.12/site-packages /tmp/wheels/firedamp-0.1.0-py3-none-any.whl
   ```
2. **Dependency Resolution Limitation (Disclosed):**
   When executing from `/tmp/clean_isolated_venv` without `--system-site-packages`:
   ```
   ModuleNotFoundError: No module named 'rich'
   ```
   **Disclosure:** Because this execution sandbox has no outbound internet access to PyPI, third-party declared dependencies (`rich`, `typer`, `docker`, `httpx`, `pydantic`) cannot be downloaded from PyPI into a completely clean, isolated venv. Dependency resolution was bypassed via `--no-deps`. We do NOT claim a completely clean installation with full dependency resolution.
3. **Package Version Discrepancy (Disclosed):**
   - `pyproject.toml` declared `version = "0.1.0"`
   - `core/__init__.py` declared `__version__ = "0.1.0"`
   - `cli.py` declared `v0.1.0`
   - Generated wheel is `firedamp-0.1.0-py3-none-any.whl`
   - Documentation and `tests/benchmark_ladder.py` previously referenced `v0.2.0`
   **Audit Finding:** There is an explicit version mismatch between the declared packaging version (`0.1.0`) and the documentation/benchmark version (`0.2.0`). The packaging files declare `0.1.0`.

---

## 7. Complete Test Results

```bash
$ python3 -m unittest discover tests/ -v
Ran 74 tests in 0.066s
OK

$ python3 tests/benchmark_ladder.py
               🛡️ Open WebUI Version Ladder Benchmark (SIMULATION)
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Release  ┃ Target   ┃ Expected ┃ Detected  ┃ False    ┃ Latency   ┃ Ladder   ┃
┃ Tag      ┃ Mode     ┃ CVEs     ┃ Breaches  ┃ Positiv… ┃ (s)       ┃ Status   ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ v0.8.5   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+] PASS │
│ v0.8.6   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+] PASS │
│ v0.9.0   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+] PASS │
│ v0.9.5   │ simulat… │ CVE-202… │ CVE-2026… │ 0        │ 0.0001s   │ [+] PASS │
│ v0.9.6   │ simulat… │ None     │ None      │ 0        │ 0.0001s   │ [+] PASS │
└──────────┴──────────┴──────────┴───────────┴──────────┴───────────┴──────────┘
```

---

## 8. Explicit List of Unresolved Findings & Constraints

1. **Docker Target Environment (`NOT TESTED` for Live Containers):**
   No live Docker daemon exists in the sandbox. Behavioral probes are tested via unit mocks and in-memory simulated adapters (`VersionLadderSimulatedAdapter`). No live container vulnerable-versus-patched tests were performed. Probes remain classified as `implemented`, not `validated_vulnerable` or `validated_patched`.
2. **Documented CVE Probe Coverage:**
   The 7 documented CVEs (`CVE-2026-45301`, `CVE-2026-44557`, `CVE-2026-54016`, `CVE-2026-54010`, `CVE-2026-45349`, `CVE-2026-44561`, `CVE-2024-31621`) are verified references only and do not have executable Python probes.
3. **Repository State:**
   All changes remain uncommitted on branch `fix/cve-catalog-integrity`. The `main` branch has not been modified.

---

## 9. Addendum: 2026-11-23 Live Differential Validation & Verification

### Differential Validation Summary
On 2026-11-23, live differential validation of CVE-2026-28788 was performed against two locally deployed Open WebUI container environments:
- **Target 1:** Open WebUI v0.8.5 (vulnerable target: `http://127.0.0.1:13085`)
- **Target 2:** Open WebUI v0.8.6 (patched target: `http://127.0.0.1:13086`)

### Empirical Results & Probe Verdicts
1. **Direct Exploit Reproduction (`reproduce_cve_2026_28788.py`):**
   - **Open WebUI v0.8.5:** `VULNERABLE_CONFIRMED`
     - Attacker Bob successfully overwrote Alice's indexed file content in the shared knowledge base without file ownership. Tracer marker was verified in victim indexed content (`tracer_found_in_readback: true`).
   - **Open WebUI v0.8.6:** `PATCHED_CONFIRMED`
     - Open WebUI enforced file ownership validation on batch processing (`POST /api/v1/retrieval/process/files/batch`), rejecting Bob's unauthorized modification with `Permission denied: not file owner`. Alice's indexed content remained intact (`tracer_found_in_readback: false`).

2. **Firedamp Live Probing Engine (`run_firedamp_probe.py`):**
   - **Open WebUI v0.8.5:** Severity `direct_leak` (`is_vulnerable: true`, `is_clean: false`). Canaries successfully injected and recovered via readback.
   - **Open WebUI v0.8.6:** Severity `none` (`is_vulnerable: false`, `is_clean: true`). Batch modification rejected with permission denial; canary injection blocked.

### Evidence Bundle & Cryptographic Provenance
- The authoritative sanitized evidence package and manifest were generated by `collect_evidence.py` (`--mode live --raw-dir`).
- The evidence package is stored outside the source repository at `~/firedamp-evidence/cve-2026-28788/`.
- All raw evidence artifacts were cryptographically snapshotted and hash-verified without modification:
  - `firedamp-v085.json` (`cbdc303f3868c3c03ffba2c617407575bba77b36155733f86a65f88f0fb4f616`)
  - `firedamp-v086.json` (`fa59bb6ee4e03fe582b55da71e731a47b1379882cb322a69aa01b2c61b3aeea7`)
  - `reproduce-v085.json` (`9ba70934d0418fe1fcf43ebfc62e306677e2103ab09fb3022f4d6817f8bbf95a`)
  - `reproduce-v086.json` (`f15517ffe4f8b2d46f3f9226116ff01d514d0b3f22bb1e9ed3d6d258dbe0fe15`)
- The sanitized evidence bundle contains role-pseudonymized identifiers (`TARGET_FILE`, `TARGET_KNOWLEDGE_BASE`, `VICTIM_USER`, `ATTACKER_USER`) with complete credential redaction, preserving exact forensic status codes, hashes, and probe verdicts.
