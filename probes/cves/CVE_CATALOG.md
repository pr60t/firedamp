# Firedamp Multi-Tenant RAG CVE & Threat Taxonomy Catalog
**Forensic Audit Edition (v0.2.0)**

This document is the authoritative technical reference for all vulnerability classes, attack strategies, and defensive verification probes curated into Firedamp.

---

## 🎯 Scope & Curatorial Philosophy

Unlike general LLM red-teaming frameworks (such as Garak, PyRIT, or Promptfoo) that focus broadly on jailbreaks, toxic speech, and prompt injections, **Firedamp is purposefully dedicated to Tenant Isolation, Boundary Enforcement, and Authorization in RAG & AI Systems**.

In multi-tenant architectures, authorization failures allow one user (or tenant) to read, manipulate, or delete another tenant's indexed knowledge, embeddings, memory, or completions. Firedamp stores each vulnerability as a **deterministic behavioral regression probe (Canary In $\rightarrow$ Canary Out)**:
- **Zero weaponized exploits:** Probes only check for authorization boundaries using synthetic cryptographic canary tokens.
- **Zero false positives via exact token matching:** We evaluate exact matches against cryptographically signed tokens (`CANARY-FRDP-...`).
- **Zero GPU VRAM:** Operates deterministically without requiring expensive LLM-as-a-judge evaluators.

---

## 🔬 Rigorous Status Taxonomy: References vs. Probes

To maintain absolute credibility and trustworthiness, Firedamp explicitly delineates between:
1. **Implemented Probes (`implemented`)**: Executable Python probe modules exist in the codebase and are integrated into automated test suites and simulation benchmarks.
2. **Documented Vulnerabilities (`documented`)**: Real, authoritative CVEs verified against official CVE.org and NVD records that document known RAG/AI authorization vulnerabilities, but for which no executable probe script has yet been authored.
3. **Quarantined / Misattributed (`rejected`)**: Records from legacy catalogues that were incorrectly attributed to AI/RAG software (e.g. associating an enterprise SD-WAN or PHP CMS vulnerability with a vector database). These are retained in the forensic register to preserve audit traceability but are excluded from active scanning.

---

## 📋 Comprehensive 21-CVE Forensic Audit Register

| # | CVE ID | Official Advisory / GHSA | Vendor / Product | Authoritative Title & Bug Class | Affected / Fixed | Probe Status | Advisory Verification | Live Validation |
|---|---|---|---|---|---|---|---|---|
| 1 | **CVE-2026-44560** | [GHSA-h36f-rqpx-j5wx](https://github.com/open-webui/open-webui/security/advisories/GHSA-h36f-rqpx-j5wx) | Open WebUI | Direct Collection Vector Retrieval Authorization Bypass (CWE-862 [NVD/Aggregated; Unassigned in GHSA]) | `<= 0.8.12` / `>= 0.9.0` | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) |
| 2 | **CVE-2026-45398** | [GHSA-4g37-7p2c-38r9](https://github.com/open-webui/open-webui/security/advisories/GHSA-4g37-7p2c-38r9) | Open WebUI | Knowledge Base Raw UUID Prefix Validation Bypass (CWE-639) [Read-Side Scope] | `<= 0.9.4` / `0.9.5` | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) |
| 3 | **CVE-2026-28788** | [GHSA-jjp7-g2jw-wh3j](https://github.com/open-webui/open-webui/security/advisories/GHSA-jjp7-g2jw-wh3j) | Open WebUI | Cross-User Ingestion Overwrite via retrieval process_files_batch (CWE-639) | `< 0.8.6` / `0.8.6` | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) |
| 4 | **CVE-2026-54019** | [GHSA-p5cp-r7rg-qpxc](https://github.com/open-webui/open-webui/security/advisories/GHSA-p5cp-r7rg-qpxc) | Open WebUI | Milvus filter-expression injection / RAG tenant-isolation bypass (CWE-862 & CWE-943) | `< 0.9.6` / `0.9.6` | `implemented` | **VERIFIED** | **NOT TESTED** (Simulation Only) |
| 5 | **CVE-2026-45301** | [GHSA-r8wh-8m7r-fh33](https://github.com/open-webui/open-webui/security/advisories/GHSA-r8wh-8m7r-fh33) | Open WebUI | Broken Object Level Authorization on Files API (CWE-284) | `< 0.3.16` / `0.3.16` | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) |
| 6 | **CVE-2026-44557** | [GHSA-6c2x-gcp3-gp73](https://github.com/open-webui/open-webui/security/advisories/GHSA-6c2x-gcp3-gp73) | Open WebUI | Global Knowledge Base Enumeration via Meta-Collection (CWE-200 / CWE-862 / CWE-863) | `< 0.9.0` / `0.9.0` | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) |
| 7 | **CVE-2026-54016** | [GHSA-cx9v-4qj2-jrw6](https://github.com/open-webui/open-webui/security/advisories/GHSA-cx9v-4qj2-jrw6) | Open WebUI | Cross-Tenant File Enumeration via search_knowledge_files Tool (CWE-639 / CWE-862) | `< 0.9.6` / `0.9.6` | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) |
| 8 | **CVE-2026-54010** | [GHSA-vrhc-3fr6-pc3c](https://github.com/open-webui/open-webui/security/advisories/GHSA-vrhc-3fr6-pc3c) | Open WebUI | Forged Chat-File Association Privilege Escalation and Deletion (CWE-284 / CWE-639 / CWE-862) | `< 0.9.6` / `0.9.6` | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) |
| 9 | **CVE-2026-45349** | [GHSA-gfm2-xm6c-37qc](https://github.com/open-webui/open-webui/security/advisories/GHSA-gfm2-xm6c-37qc) | Open WebUI | Chat Completions API Improper Authorization Exposing Other Chats (CWE-639) [Requires Shared Model] | `< 0.9.0` / `0.9.0` | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) |
| 10 | **CVE-2026-44561** | [GHSA-hmgr-67hw-j2cq](https://github.com/open-webui/open-webui/security/advisories/GHSA-hmgr-67hw-j2cq) | Open WebUI | Persistent Channel Access for Deactivated/Removed Members (CWE-284 / CWE-863) | `< 0.9.0` / `0.9.0` | `documented` | **VERIFIED** | **NOT TESTED** (Documented Only) |
| 11 | **CVE-2024-31621** | [GHSA-6wp6-22x5-rr3w](https://github.com/advisories/GHSA-6wp6-22x5-rr3w) | FlowiseAI Flowise | Unauthenticated API Access and Code Injection in api/v1 (CWE-94 / CWE-287) | `< 1.8.1` (GHSA) / `<= 1.6.2` (NVD) | `documented` | **CONFLICTING** | **NOT TESTED** (Documented Only) |
| 12 | **CVE-2024-52306** | [GHSA-8237-957h-h2c2](https://github.com/advisories/GHSA-8237-957h-h2c2) | Backpack FileManager | Insecure Deserialization in Laravel Backpack FileManager (CWE-502) | `< 2.0.2` and `>= 3.0.0, < 3.0.9` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 13 | **CVE-2024-52307** | [GHSA-2xrw-5f2x-m56j](https://github.com/goauthentik/authentik/security/advisories/GHSA-2xrw-5f2x-m56j) | authentik | Timing Attack on Metrics Endpoint in authentik IDP (CWE-208) | `< 2024.8.5` & `2024.10.0-2024.10.2` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 14 | **CVE-2024-41133** | [HPESBNW04673](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04673en_us) | HPE Aruba SD-WAN | Authenticated Command Injection in EdgeConnect SD-WAN CLI (CWE-78) | Multiple ECOS branches (9.3, 9.2, 9.1) | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 15 | **CVE-2024-43407** | [GHSA-7r32-vfj5-c2jv](https://github.com/advisories/GHSA-7r32-vfj5-c2jv) | CKEditor 4 | Reflected Cross-Site Scripting in Code Snippet GeSHi Plugin (CWE-79) | `< 4.25.0-LTS` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 16 | **CVE-2024-52308** | [GHSA-p2h2-3vg9-4p87](https://github.com/cli/cli/security/advisories/GHSA-p2h2-3vg9-4p87) | GitHub CLI | Command Injection in gh codespace ssh/logs (CWE-78) | `<= 2.61.0` / `2.62.0` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 17 | **CVE-2024-45388** | [GHSA-6xx4-x46f-f897](https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-6xx4-x46f-f897) | Hoverfly | Directory Traversal Arbitrary File Read in /api/v2/simulation (CWE-22) | `< 1.10.3` / `1.10.3` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 18 | **CVE-2024-45389** | [GHSA-gprj-6m2f-j9hx](https://github.com/CloudCannon/pagefind/security/advisories/GHSA-gprj-6m2f-j9hx) | Pagefind | DOM Clobbering Script Loading in Pagefind Static Search (CWE-79) | `< 1.1.1` / `1.1.1` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 19 | **CVE-2024-42475** | [GHSA-332c-q46h-fg8f](https://github.com/CORDEA/oauth/security/advisories/GHSA-332c-q46h-fg8f) | Nim OAuth Library | Insufficient Entropy in OAuth generateState Function (CWE-330) | `< 0.11` / `0.11` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 20 | **CVE-2024-45391** | [GHSA-4qrm-9h4r-v2fx](https://github.com/tinacms/tinacms/security/advisories/GHSA-4qrm-9h4r-v2fx) | TinaCMS | Search Token Credential Exposure in tina-lock.json (CWE-200) | `< 1.6.2` / `1.6.2` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |
| 21 | **CVE-2024-34359** | [GHSA-56xg-wfcc-g829](https://github.com/abetlen/llama-cpp-python/security/advisories/GHSA-56xg-wfcc-g829) | llama-cpp-python | Server-Side Template Injection in GGUF Jinja2 Templates (CWE-76) | `>= 0.2.30, <= 0.2.71` / `0.2.72` | `rejected` | **QUARANTINED** | **NOT APPLICABLE** (Quarantined) |

---

## 🧪 Section 1: Active Executable Regression Probes (Tier-1 Suite)

The Tier-1 suite contains **4 executable, deterministic behavioral regression probes** targeting Open WebUI release milestones:

### 1. CVE-2026-44560: Direct Collection Vector Retrieval Authorization Bypass
- **Target:** Open WebUI `<= 0.8.12` (Patched in `>= 0.9.0`)
- **Component:** `get_sources_from_items` in chat-completion RAG pipeline (`POST /api/chat/completions`)
- **CWE:** CWE-862 (Missing Authorization) [Aggregated vulnerability databases / NVD; unassigned in upstream GHSA-h36f-rqpx-j5wx]
- **Attack Mechanism:** The chat completion source-resolution pipeline resolved file attachments in the `files` array without checking user authorization. An authenticated attacker could attach another user's `file_id` to extract indexed chunks into the chat context.
- **Probe Implementation:** [cve_2026_44560.py](cve_2026_44560.py)
- **Strengthened Detection:** Multi-channel inspection scans:
  1. Assistant message response content (`choices[0].message.content`).
  2. Citation metadata (`choices[0].message.citations`).
  3. Source references (`choices[0].message.sources`).
  4. Attached context blocks (`choices[0].context` and top-level `context`).
  5. Full raw JSON response payload fallback.
- **Behavioral Verification:** Bob sends a chat completion request attaching Alice's private `file_id` in `files`. The probe asserts zero canary tokens in the response or citation context.
- **Remediation:** Enforce user ownership validation on all file and collection resolution paths prior to executing vector searches. Patched in `v0.9.0`.

### 2. CVE-2026-45398: Knowledge Base Raw UUID Prefix Validation Bypass
- **Target:** Open WebUI `<= 0.9.4` (Patched in `0.9.5`)
- **Component:** `_validate_collection_access` in collection access validator
- **CWE:** CWE-639 (Insecure Direct Object Reference)
- **Attack Mechanism:** The authorization helper validated `user-memory-*` and `file-*` prefixes but permitted raw knowledge base UUIDs to pass through unchecked into retrieval endpoints.
- **Target Endpoints:** `POST /api/v1/retrieval/query/collection` and `POST /api/v1/retrieval/query/doc`. Unverified fallback routes were excised.
- **Probe Scope:** Specifically covers the **retrieval read-side raw UUID authorization bypass** via `adapter.query_collection` and `adapter.query_doc`. It does **not** test write-side collection injection routes (`/process/text`, `/process/file`, `/process/files/batch`) from the advisory.
- **Probe Implementation:** [cve_2026_45398.py](cve_2026_45398.py)
- **Behavioral Verification:** Alice creates a private knowledge base. Bob calls `adapter.query_collection` and `adapter.query_doc` with Alice's raw UUID. The probe asserts authorization denial and zero canary leakage.
- **Remediation:** Apply universal ACL validation across all resource identifiers, including raw UUIDs. Patched in `v0.9.5`.

### 3. CVE-2026-28788: Cross-User Batch File Overwrite via `retrieval/process/files/batch`
- **Target:** Open WebUI `< 0.8.6`
- **Component:** `POST /api/v1/retrieval/process/files/batch` (unsupported fallback to `/api/v1/files/batch/process` removed)
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Attack Mechanism:** The file batch processing endpoint lacked ownership checks, allowing an authenticated attacker to supply a victim's `file_id` and overwrite their stored content, poisoning subsequent RAG queries served to the LLM.
- **Probe Implementation:** [cve_2026_28788.py](cve_2026_28788.py)
- **Independent Mutation Verification:** The probe does not accept `status=True` as confirmed poisoning. It independently reads back Alice's file through legitimate verification routes (`read_file_content` via `GET /api/v1/files/{id}/content` as Alice) to verify whether `bob_tracer.token` actually mutated the victim's data. If readback cannot be completed, the outcome is reported as `INCONCLUSIVE`.
- **Behavioral Verification:** Bob dispatches an overwrite payload containing a unique synthetic tracer targeting Alice's `file_id`. The probe verifies that the server rejects the overwrite and Alice's document remains unmodified.
- **Remediation:** Validate file ownership on batch ingestion endpoints before mutating database records or re-indexing vector embeddings. Patched in `v0.8.6`.

### 4. CVE-2026-54019: Milvus filter-expression injection / RAG tenant-isolation bypass
- **Target:** Open WebUI `< 0.9.6` (under `milvus_multitenancy` mode)
- **Component:** Milvus vector store client filter formatting (`resource_id`)
- **Official Advisory:** [GHSA-p5cp-r7rg-qpxc](https://github.com/open-webui/open-webui/security/advisories/GHSA-p5cp-r7rg-qpxc)
- **Target Endpoints:** `POST /api/v1/retrieval/query/collection` and `POST /api/v1/retrieval/query/doc`
- **CWE:** CWE-862 (Missing Authorization) / CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
- **Attack Mechanism:** User-supplied collection names (treated as `resource_id`) were interpolated directly into Milvus query expressions without sanitization: `expr = f"resource_id == '{resource_id}'"`. An attacker supplying the advisory PoC payload `x' or resource_id != '' or resource_id == 'x` evaluates the expression to boolean true across all indexed records, bypassing tenant vector partitioning.
- **Probe Implementation:** [cve_2026_54019.py](cve_2026_54019.py)
- **Exact PoC Payload:**
  ```json
  {
    "collection_names": ["x' or resource_id != '' or resource_id == 'x"],
    "query": "anything",
    "k": 10,
    "hybrid": false
  }
  ```
- **Behavioral Verification:** Under Milvus multitenancy mode, Bob queries with the injection payload. The probe asserts that the engine rejects the injection and returns zero cross-tenant chunks.
- **Remediation:** Use parameterized filter expressions and strictly validate collection identifiers against an allowlist pattern (`^[a-zA-Z0-9_-]+$`). Patched in `v0.9.6`.

---

## 📖 Section 2: Documented Vulnerabilities (Verified References)

The following entries are verified vulnerabilities documented in Firedamp's catalog without standalone executable probe scripts:

1. **CVE-2026-45301**: Open WebUI `< 0.3.16` (Broken Object Level Authorization on `/api/v1/files/`, CWE-284, fixed in `v0.3.16`).
2. **CVE-2026-44557**: Open WebUI `< 0.9.0` (Global Knowledge Base Enumeration via `knowledge-bases` meta-collection, GHSA unassigned CWE, NVD assigns CWE-200 / CWE-862 / CWE-863, fixed in `v0.9.0`).
3. **CVE-2026-54016**: Open WebUI `< 0.9.6` (Cross-Tenant File Enumeration via `search_knowledge_files` tool, GHSA lists CWE-639 and CWE-862, fixed in `v0.9.6`).
4. **CVE-2026-54010**: Open WebUI `< 0.9.6` (Forged Chat-File Association Privilege Escalation and Deletion, GHSA lists CWE-284, CWE-639, and CWE-862, fixed in `v0.9.6`).
5. **CVE-2026-45349**: Open WebUI `<= 0.8.12` (Chat Completions API Improper Authorization Exposing Other Users' Chats, CWE-639, requires access to same model, fixed in `v0.9.0`).
6. **CVE-2026-44561**: Open WebUI `< 0.9.0` (Persistent Channel Access for Deactivated/Removed Members, GHSA lists CWE-284 and CWE-863, fixed in `v0.9.0`).
7. **CVE-2024-31621**: FlowiseAI Flowise `< 1.8.1` (GHSA) / `<= 1.6.2` (NVD) (Unauthenticated API Access and Remote Code Execution via `/api/v1` endpoints, CWE-94 / CWE-287, fixed in `v1.8.1`).

---

## 🚫 Section 3: Forensic Audit & Quarantine of Misattributed Records

During our forensic audit, 10 CVEs from early prototype databases were identified as misattributed to AI/RAG systems. They have been officially quarantined and marked `rejected`:

1. **CVE-2024-52306**: Belongs to **Backpack FileManager** (PHP/Laravel administration panel insecure deserialization in `mimes` parameter, fixed in 3.0.9). Not related to Flowise.
2. **CVE-2024-52307**: Belongs to **authentik** (Timing attack on Prometheus `/-/metrics/` endpoint to brute-force `SECRET_KEY`, fixed in 2024.10.3). Not related to Flowise.
3. **CVE-2024-41133**: Belongs to **HPE Aruba EdgeConnect SD-WAN** (Command injection in ECOS CLI allowing root execution, fixed in 9.3.4.0). Not related to Langflow.
4. **CVE-2024-43407**: Belongs to **CKEditor 4** (Reflected XSS in third-party GeSHi syntax highlighter plugin, fixed in 4.25.0-LTS). Not related to Langflow.
5. **CVE-2024-52308**: Belongs to **GitHub CLI** (`gh codespace ssh` / `gh codespace logs` command injection, fixed in 2.62.0). Not related to Dify.
6. **CVE-2024-45388**: Belongs to **Hoverfly** (Directory traversal arbitrary file read in `/api/v2/simulation`, GHSL-2023-274). Not related to Dify.
7. **CVE-2024-45389**: Belongs to **Pagefind** (DOM clobbering manipulating dynamic JavaScript dependency loading, fixed in 1.1.1). Not related to LiteLLM.
8. **CVE-2024-42475**: Belongs to **Nim OAuth Library** (Weak PRNG in `generateState` leading to CSRF, fixed in 0.11). Not related to LiteLLM.
9. **CVE-2024-45391**: Belongs to **TinaCMS** (Search token credential exposure in `tina-lock.json`, fixed in 1.6.2). Not related to Milvus.
10. **CVE-2024-34359**: Belongs to **llama-cpp-python** (Jinja2 Server-Side Template Injection in GGUF metadata, "Llama Drama", fixed in 0.2.72). Not related to ChromaDB tenant headers.

---

## 🛠️ Programmatic Access

Inspect and filter the curated CVE catalog directly in Python:

```python
from probes.cve_registry import load_cve_catalog, validate_cve_catalog

# Validate catalogue schema integrity
errors = validate_cve_catalog()
assert len(errors) == 0

# Load active verified CVEs (filters out rejected entries)
active_cves = load_cve_catalog(include_rejected=False)

# Load only implemented executable probes (returns 4 probes)
implemented_probes = load_cve_catalog(status="implemented")

# Load Open WebUI CVEs (returns 10 verified records)
owui_cves = load_cve_catalog(platform="openwebui")
```
