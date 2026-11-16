# Firedamp Multi-Tenant RAG CVE & Attack Strategy Catalog

This document is the authoritative technical reference for all vulnerability classes, attack strategies, and defensive verification probes curated into Firedamp.

---

## 🎯 Scope & Curatorial Philosophy

Unlike general LLM red-teaming frameworks (such as Garak, PyRIT, or Promptfoo) that focus broadly on jailbreaks, toxic speech, and prompt injections, **Firedamp is purposefully dedicated to Tenant Isolation, Boundary Enforcement, and Authorization in RAG & AI Systems**.

In multi-tenant architectures, authorization failures allow one user (or tenant) to read, manipulate, or delete another tenant's indexed knowledge, embeddings, memory, or completions. Firedamp stores each vulnerability as a **deterministic behavioral regression probe (Canary In $\rightarrow$ Canary Out)**:
- **No weaponized exploits:** Probes only check for authorization boundaries using synthetic cryptographic canary tokens.
- **Zero false positives via exact token matching:** We evaluate exact matches against cryptographically signed tokens (`CANARY-FRDP-...`).
- **Zero GPU VRAM:** Operates deterministically without requiring expensive LLM-as-a-judge evaluators.

---

## 🔬 The 8 Canonical Bug Classes & Attack Strategies

Every curated CVE belongs to one of 8 structural bug classes:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   FIREDAMP 8-PILLAR BUG TAXONOMY                       │
├──────────────────────────┬─────────────────────────────────────────────┤
│ 1. IDOR / Route Auth     │ Missing authorization on REST/RPC endpoints │
│ 2. Role / Level Bypass   │ UUID / Prefix validation flaws and ACL gaps │
│ 3. Revocation Staleness  │ Stale grants, cached tokens, lingering data │
│ 4. Vector Store Inject   │ Filter / boolean injection in vector DB     │
│ 5. Shared Store Scoping  │ Partition / tenant scoping failure in DB    │
│ 6. Cross-Tenant Memory   │ Semantic cache / agent scratchpad leakage   │
│ 7. Indirect Channels     │ Citations, link forgery, tool output bleed  │
│ 8. Write-Side Poisoning  │ Cross-tenant ingestion / file overwrites    │
└──────────────────────────┴─────────────────────────────────────────────┘
```

---

## 📋 Comprehensive Curated Vulnerability Register

### Class 1: Missing Authorization on Route (IDOR / BOLA)

#### 1. CVE-2026-44560: Direct Collection Vector Retrieval Bypass
- **Target:** Open WebUI `< 0.9.0`
- **CWE:** CWE-862 (Missing Authorization)
- **Mechanism:** In earlier versions, 3 of 5 code paths resolving file and knowledge-base references into vector queries ran without verifying ownership, relying on predictable collection names like `file-<id>`.
- **Attack Strategy:** Bob sends a raw vector query directly specifying Alice's `file-<id>` collection name in the payload.
- **Firedamp Defense Probe:** Alice seeds a private document containing a canary. Bob executes `query_resource_direct(BobSession, "file-" + alice_file_id)`. Firedamp asserts HTTP 403/404 and zero canaries returned.
- **Remediation:** Enforce ownership checks on all vector retrieval resolution controllers before issuing vector similarity queries.

#### 2. CVE-2026-45301: Broken Access Control on Files API
- **Target:** Open WebUI `< 0.9.1`
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Mechanism:** The REST endpoints `/api/v1/files/{id}` and `/api/v1/files/` lacked ownership filters, allowing any authenticated user to view metadata, download content, or issue DELETE requests.
- **Attack Strategy:** Bob iterates file IDs and reads or deletes Alice's private uploaded documents.
- **Firedamp Defense Probe:** Bob calls `GET /api/v1/files/{alice_file_id}` and `DELETE /api/v1/files/{alice_file_id}`. Firedamp asserts HTTP 403 Forbidden.
- **Remediation:** Add `WHERE user_id = :current_user` to all file database operations.

#### 3. CVE-2026-44557: Global Knowledge Base Meta-Collection Enumeration
- **Target:** Open WebUI `< 0.9.2`
- **CWE:** CWE-200 (Information Exposure)
- **Mechanism:** A system-level meta-collection endpoint exposed the catalog of all existing knowledge bases, their names, and owner UUIDs.
- **Attack Strategy:** Bob dumps the catalog to discover targets for targeted exfiltration.
- **Firedamp Defense Probe:** Bob queries the meta-collection endpoint. Firedamp asserts that Alice's private knowledge collections are omitted from the response.

#### 4. CVE-2026-54016: Cross-Tenant File Enumeration via `search_knowledge_files`
- **Target:** Open WebUI `< 0.9.4`
- **CWE:** CWE-200 (Information Exposure)
- **Mechanism:** The `search_knowledge_files` endpoint executed search queries against files without scoping results to collections owned by or shared with the caller.
- **Attack Strategy:** Bob searches with empty or wildcard queries (`*`) to enumerate all files uploaded across the instance.
- **Firedamp Defense Probe:** Bob invokes `search_knowledge_files` with wildcard queries; Firedamp verifies that only Bob's files are returned.

#### 5. CVE-2026-45349: Completions API Unchecked RAG Contexts
- **Target:** Open WebUI `< 0.9.4`
- **CWE:** CWE-862 (Missing Authorization)
- **Mechanism:** The chat completions endpoint accepted arbitrary collection IDs in the `rag_context` parameters without validating if the caller had read access to them.
- **Attack Strategy:** Bob sends a chat completion specifying Alice's collection ID in the request body.
- **Firedamp Defense Probe:** Bob sends a completion request referencing Alice's collection. Firedamp inspects both the generated stream and context chunks for canaries.

#### 6. CVE-2024-52306: Flowise Unauthenticated Chatflow Execution
- **Target:** Flowise `< 2.1.2`
- **CWE:** CWE-862 (Missing Authorization)
- **Mechanism:** Prediction endpoints `/api/v1/prediction/{id}` were callable without an API key or session token.
- **Attack Strategy:** An external attacker directly triggers execution of private RAG pipelines and captures retrieved context.
- **Firedamp Defense Probe:** An unauthenticated session issues POST to `/api/v1/prediction/{id}`; Firedamp asserts HTTP 401 Unauthorized.

#### 7. CVE-2024-41133: Langflow Unauthenticated Flow Execution
- **Target:** Langflow `< 1.0.12`
- **CWE:** CWE-862 (Missing Authorization)
- **Mechanism:** Unauthenticated HTTP requests to `/api/v1/process/{flow_id}` allowed running flows connected to vector stores.
- **Attack Strategy:** Remote unauthenticated users query internal knowledge stores.
- **Firedamp Defense Probe:** Unauthenticated request to `/api/v1/process/{flow_id}`; Firedamp asserts HTTP 401.

#### 8. CVE-2024-52308: Dify Dataset Permission Bypass
- **Target:** Dify `< 0.6.12`
- **CWE:** CWE-862 (Missing Authorization)
- **Mechanism:** The `/console/api/datasets/{id}/hit-testing` endpoint permitted users outside the target workspace to run similarity searches.
- **Attack Strategy:** Bob runs hit-testing queries against Alice's private dataset ID.
- **Firedamp Defense Probe:** Bob attempts hit-testing on Alice's dataset; Firedamp asserts HTTP 403 Forbidden.

#### 9. CVE-2024-45388: Dify Cross-Tenant Dataset File Export via IDOR
- **Target:** Dify `< 0.6.14`
- **CWE:** CWE-639 (IDOR)
- **Mechanism:** File download/export endpoints lacked workspace boundary validation.
- **Attack Strategy:** Bob passes Alice's document ID into file export routes to download raw training documents.
- **Firedamp Defense Probe:** Bob attempts downloading Alice's document; Firedamp asserts HTTP 403.

---

### Class 2: Role or Function-Level Authorization Bypass

#### 10. CVE-2026-45398: Knowledge Base UUID Prefix Bypass
- **Target:** Open WebUI `< 0.9.5`
- **CWE:** CWE-863 (Incorrect Authorization)
- **Mechanism:** The access-control helper strictly verified `user-memory-*` and `file-*` prefixed resources, but raw knowledge base UUIDs (which had no prefix) fell through to the query execution handler unchecked.
- **Attack Strategy:** Bob queries `/process/text` or `/query` using Alice's knowledge base UUID directly.
- **Firedamp Defense Probe:** Bob calls direct endpoints with Alice's raw UUID. Firedamp asserts authorization failure.
- **Remediation:** Remove prefix-dependent logic; require explicit permission checks on all identifiers.

#### 11. CVE-2024-31621: Flowise Credential IDOR
- **Target:** Flowise `< 1.4.3`
- **CWE:** CWE-639 (IDOR)
- **Mechanism:** API endpoints for credentials allowed reading connection strings (including vector DB API keys) by supplying an ID.
- **Attack Strategy:** Bob fetches Alice's vector database credentials to query her vector store directly out-of-band.
- **Firedamp Defense Probe:** Bob attempts to read credentials by ID; Firedamp asserts HTTP 403/404.

#### 12. CVE-2024-43407: Langflow Flow & Collection Manipulation Bypass
- **Target:** Langflow `< 1.0.15`
- **CWE:** CWE-863 (Incorrect Authorization)
- **Mechanism:** PATCH requests allowed modifying flow component connections without checking flow ownership.
- **Attack Strategy:** Bob updates Alice's flow definition to route retrievals to Bob's webhook or chat session.
- **Firedamp Defense Probe:** Bob sends a PATCH request to Alice's flow; Firedamp asserts HTTP 403.

---

### Class 3: Revocation & Lifecycle Staleness

#### 13. CVE-2026-44561: Deactivated Channel Member Persistent Access
- **Target:** Open WebUI `< 0.9.5`
- **CWE:** CWE-269 (Improper Privilege Management)
- **Precondition:** `channels_feature` enabled
- **Mechanism:** When a user was removed from a group or channel, cached ACL grants and active session contexts remained in memory, allowing continued querying of channel knowledge.
- **Attack Strategy:** Bob is granted access, then revoked. Bob queries immediately and periodically to exploit caching lag.
- **Firedamp Defense Probe:**
  1. Alice shares resource with Bob.
  2. Firedamp confirms Bob can read the canary.
  3. Alice revokes Bob's access.
  4. Firedamp immediately verifies Bob can no longer read the canary.
  5. Firedamp re-tests after 5 seconds to ensure no background cache reinvalidation occurs.
- **Remediation:** Evict all related cache keys and terminate associated active sessions upon revocation.

---

### Class 4: Vector Store Filter & Query Expression Injection

#### 14. CVE-2026-54019: Milvus Boolean Expression Filter Injection
- **Target:** Open WebUI `< 0.9.6`
- **CWE:** CWE-94 (Improper Control of Generation of Code / Expression Injection)
- **Precondition:** `milvus_multitenancy` mode enabled
- **Mechanism:** Open WebUI passed user-controlled collection names directly into Milvus boolean filter expressions without escaping or parameterization.
- **Attack Strategy:** Bob submits a collection query with a crafted payload:
  `collection_name = "target_collection' or 1==1 or collection_name == 'x"`
  This causes Milvus to evaluate the filter as always true, returning chunks belonging to all tenants.
- **Firedamp Defense Probe:** Firedamp constructs the SQL/expression injection payload in Bob's query under Milvus. Firedamp checks that the query is rejected and no foreign canaries are retrieved.
- **Remediation:** Strictly sanitize and regex-validate collection names (`^[a-zA-Z0-9_-]+$`) and use parameterized filter expressions.

---

### Class 5: Shared-Store Tenant Scoping & Partitioning

#### 15. CVE-2024-45391: Milvus Partition and Collection RBAC Privilege Bypass
- **Target:** Milvus `< 2.4.5`
- **CWE:** CWE-284 (Improper Access Control)
- **Precondition:** `milvus_rbac` enabled
- **Mechanism:** Milvus proxy coordinators failed to validate partition-level permissions when a query specified multiple partitions in `partition_names`.
- **Attack Strategy:** Low-privilege tenant queries restricted partitions containing other tenants' vectorized data.
- **Firedamp Defense Probe:** Bob executes partition query targeting Alice's private partition; Firedamp asserts permission denied.

#### 16. CVE-2024-34359: ChromaDB Tenant Header Spoofing
- **Target:** ChromaDB `< 0.4.24`
- **CWE:** CWE-284 (Improper Access Control)
- **Precondition:** Multi-tenant ChromaDB deployment
- **Mechanism:** The server trusted unauthenticated HTTP headers (`X-Chroma-Tenant`) to scope tenant databases without verifying the caller's JWT token identity.
- **Attack Strategy:** Bob sends queries with `X-Chroma-Tenant: alice_tenant`.
- **Firedamp Defense Probe:** Bob sends spoofed tenant headers; Firedamp verifies the server rejects or ignores client-supplied tenant headers.

#### 17. CVE-2024-42475: LiteLLM Virtual Key Team Scoping Bypass
- **Target:** LiteLLM `< 1.40.15`
- **CWE:** CWE-863 (Incorrect Authorization)
- **Mechanism:** Virtual API keys designated for one team were permitted to invoke models and retrieve contexts assigned to other teams.
- **Attack Strategy:** Attacker uses Team A API key to access Team B's model endpoint.
- **Firedamp Defense Probe:** Issue request with Team A key against Team B deployment; verify HTTP 403.

---

### Class 6: Cross-Tenant Memory & Semantic Cache Bleed

#### 18. CVE-2024-45389: LiteLLM Semantic Cache Collision
- **Target:** LiteLLM `< 1.44.0`
- **CWE:** CWE-200 (Information Exposure)
- **Precondition:** Redis / in-memory semantic cache enabled
- **Mechanism:** Cache keys were generated solely from prompt embedding similarity without incorporating tenant or user namespace salts.
- **Attack Strategy:** Alice queries her private knowledge base for sensitive financial earnings, populating the cache. Bob later asks a semantically identical question ("What were our quarterly earnings?") and receives Alice's cached response including her private retrieved data.
- **Firedamp Defense Probe:**
  1. Alice queries private document containing canary token (populating cache).
  2. Bob queries semantically identical query.
  3. Firedamp checks whether Bob's response contains Alice's canary token.
- **Remediation:** Namespace all semantic cache entries with `(tenant_id, user_id, hash(prompt))`.

---

### Class 7: Indirect Channels (Citations, Exports, Forged Links)

#### 19. CVE-2026-54010: Forged Chat-File Link Association
- **Target:** Open WebUI `< 0.9.3`
- **CWE:** CWE-639 (IDOR)
- **Mechanism:** In chat persistence routines, attaching a file ID to a chat message did not verify that the user owned that file ID, allowing read and delete access through the chat interface.
- **Attack Strategy:** Bob crafts a chat message payload referencing Alice's private `file_id`.
- **Firedamp Defense Probe:** Bob associates Alice's `file_id` with a new chat; Firedamp verifies the association is rejected with HTTP 403.

---

### Class 8: Write-Side Poisoning & Cross-Tenant Manipulation

#### 20. CVE-2026-28788: Cross-User Batch File Overwrite via `process_files_batch`
- **Target:** Open WebUI `< 0.8.6`
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Mechanism:** The `process_files_batch()` endpoint accepted an existing `file_id`. If an authenticated user provided another user's `file_id`, the server overwrote the file record and re-indexed the new content into the vector store under the original file's ownership.
- **Attack Strategy:** Bob discovers Alice's `file_id` and submits an overwrite payload containing misleading instructions or poisoned data. When Alice queries her RAG system, Bob's poisoned text is served to her LLM.
- **Firedamp Defense Probe:**
  1. Alice uploads clean document with `canary_alice`.
  2. Bob calls `process_files_batch()` with `alice_file_id` and `canary_bob_tracer`.
  3. Firedamp asserts the overwrite request is rejected with HTTP 403.
  4. Firedamp verifies Alice's document still contains `canary_alice` and zero traces of `canary_bob_tracer`.
- **Remediation:** Check ownership prior to mutating existing file records or launching background vector indexing jobs.

#### 21. CVE-2024-52307: Flowise Cross-Tenant Document Store Injection
- **Target:** Flowise `< 2.1.3`
- **CWE:** CWE-639 (IDOR)
- **Mechanism:** In document store components, document upsert operations did not validate workspace ownership of target store IDs.
- **Attack Strategy:** Bob upserts malicious vector embeddings into Alice's document store.
- **Firedamp Defense Probe:** Bob attempts document upsert specifying Alice's store ID; Firedamp asserts HTTP 403.

---

## 🛡️ Summary Defense Matrix

| Bug Class | Primary Attack Channel | Preconditions | Verification Strategy |
| :--- | :--- | :--- | :--- |
| **Class 1: IDOR / Route Auth** | Direct REST / RPC calls | None | Replay direct queries with Bob credentials; assert 403 and zero canary tokens. |
| **Class 2: Role / Level Bypass** | Direct API & query params | None | Test raw UUIDs, stripped prefixes, and privilege elevation vectors. |
| **Class 3: Revocation Staleness** | Lifecycle events | Active sharing feature | Grant $\rightarrow$ Verify read $\rightarrow$ Revoke $\rightarrow$ Verify immediate & delayed read fails. |
| **Class 4: Vector Store Inject** | Vector query payloads | Milvus / filter mode | Inject boolean clauses (`' or 1=1 or '`) in collection parameters; assert syntax rejection. |
| **Class 5: Shared Store Scoping** | Direct DB / proxy headers | Multi-tenant backend | Spoof tenant headers (`X-Chroma-Tenant`) or target foreign partitions. |
| **Class 6: Cross-Tenant Memory** | LLM prompt & cache | Cache / memory enabled | Seed cache with Alice's query; execute identical query as Bob; assert no token match. |
| **Class 7: Indirect Channels** | Chat links & exports | None | Associate foreign file IDs to Bob's chat; assert 403 Forbidden. |
| **Class 8: Write-Side Poisoning** | Ingestion & batch APIs | None | Attempt mutating or overwriting Alice's files; verify integrity of Alice's baseline. |

