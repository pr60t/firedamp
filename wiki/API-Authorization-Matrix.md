# 🧭 API Authorization Matrix (RAG Autorize)

The **API Authorization Matrix Engine** in Firedamp brings automated request capture, multi-persona replay, and structural diff analysis to Retrieval-Augmented Generation (RAG) platforms.

Inspired by Burp Suite's *Autorize* extension, Firedamp's matrix replay operates autonomously against RAG APIs to systematically expose IDOR, BOLA, privilege escalation, and broken object-level access controls across storage, retrieval, and mutation lifecycles.

---

## 🎯 Why RAG APIs Need Structural Diffing

Traditional authorization checkers simply look at HTTP response status codes:
- HTTP 200 = Success / Leak
- HTTP 401/403 = Access Denied

**In modern RAG and AI platforms, status code checks fail completely:**
1. **Soft-200 Wrappers:** Many AI gateways and framework routers return HTTP 200 for unauthorized queries with bodies like `{"error": "Unauthorized"}` or `{"detail": "Forbidden"}`.
2. **Empty Envelope Leaks:** When an unauthorized user queries a resource, the API may return HTTP 200 with `{"data": []}` (enforced) or `{"data": [{"id": "...", "content": "..."}]}` (bypass).
3. **Partial Object Serialization:** Some endpoints redact top-level fields but serialize sensitive document embeddings, chunks, or metadata keys.

To eliminate both false positives and false negatives without requiring an expensive LLM evaluator, Firedamp implements **Structural Key Diffing (Jaccard Index)** combined with **Deterministic Canary Matching**.

---

## 👥 The 4 Personas / Actor Roles

During an authorization matrix audit, every candidate operation is recorded under the legitimate data owner and then replayed across three distinct threat personas:

| Actor Role | Persona | Permissions Context | Expected Platform Response |
| :--- | :--- | :--- | :--- |
| **`Owner`** | **Alice** | Legitimate data owner & resource creator. | HTTP 200 with sensitive resource data and canary tokens. |
| **`Intruder`** | **Bob** | Authenticated cross-tenant user with no granted permissions. | HTTP 401/403/404 or empty envelope without canary. |
| **`Ex-Member`** | **Revoked** | Authenticated user whose shares/permissions were revoked. | HTTP 401/403/404 or empty envelope without canary. |
| **`Anonymous`** | **Unauthenticated** | No session cookies, JWTs, or API keys provided. | HTTP 401/403/404. |

---

## 🔬 Structural Diff Comparator

When a recorded `Owner` operation is replayed under another persona, the `StructuralDiffComparator` evaluates three distinct risk dimensions:

### 1. Cryptographic Canary Detection (`BYPASS_CANARY`)
If any seeded `CanaryToken` (e.g. `CANARY-FRDP-e67a4d08-...`) appears anywhere in the replay response body (even inside error strings or headers), Firedamp immediately flags a **critical canary exfiltration breach**.

### 2. Status Code Divergence (`ENFORCED`)
If the server responds with HTTP 401 (Unauthorized), 403 (Forbidden), or 404 (Not Found), access is strictly enforced.

### 3. Jaccard Key Tree Similarity (`BYPASS_STRUCTURAL`)
For responses returning HTTP 200, Firedamp recursively extracts all JSON keys from both the `Owner` baseline response and the `Replayed` response:

$$J(K_{owner}, K_{replay}) = \frac{|K_{owner} \cap K_{replay}|}{|K_{owner} \cup K_{replay}|}$$

- **$J < 0.30$ or Empty:** The replay returned a generic wrapper, error message, or empty collection $\rightarrow$ **`ENFORCED`**.
- **$J \ge 0.70$ (70% key overlap):** The server returned the full internal data schema to the unauthorized persona, indicating broken object-level authorization $\rightarrow$ **`BYPASS_STRUCTURAL`**.

---

## 📊 Verdict States

| Verdict | Meaning | Risk Level |
| :--- | :--- | :---: |
| `ENFORCED` | Replay rejected via 401/403/404 or empty/sub-threshold payload. | 🟢 Safe |
| `BYPASS_CANARY` | Sensitive canary token leaked directly in replay response body. | 🔴 Critical |
| `BYPASS_STATUS` | Replay succeeded with HTTP 200 and identical payload structure. | 🟠 High |
| `BYPASS_STRUCTURAL` | Replay returned HTTP 200 with high key overlap ($\ge 70\%$) without canary. | 🟡 Medium |
| `ANOMALY` | Server threw an unhandled 5xx exception or network parsing failure. | ⚪ Anomaly |

---

## 🚀 Running the Authorization Matrix

### Basic Authorization Matrix Scan
To audit all CRUD and retrieval endpoints on a target:
```bash
firedamp scan --target-url http://localhost:8080 --suite auth-matrix
```

### Combined Full Audit (Prompts + CVEs + Matrix)
Run the entire battery including prompt-based exfiltration, historical CVE regression, and the API authorization matrix:
```bash
firedamp scan --target-url http://localhost:8080 --suite all --fail-on-leak
```

### Dry-Run Simulation Mode
Test the authorization matrix pipeline locally without network access or active containers:
```bash
firedamp scan --dry-run --suite auth-matrix
```

---

## 🖥️ Telemetry Grid Output Example

When executed, Firedamp renders the authorization matrix as an ASCII/Rich grid:

```text
               API Authorization Matrix (RAG Autorize)               
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Operation           ┃ Intruder ┃ Ex-Member  ┃ Anonymous ┃ Key Diff  ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━┩
│ Query Private File  │ ENFORCED │ ENFORCED   │ ENFORCED  │ J=0.00    │
│ Direct Vector Fetch │ ENFORCED │ ENFORCED   │ ENFORCED  │ J=0.12    │
│ Overwrite Metadata  │ ENFORCED │ ENFORCED   │ ENFORCED  │ J=0.00    │
│ Delete Collection   │ ENFORCED │ ENFORCED   │ ENFORCED  │ J=0.00    │
└─────────────────────┴──────────┴────────────┴───────────┴───────────┘
```

If an endpoint fails authorization enforcement, the table highlights the failing persona in bold red:

```text
               API Authorization Matrix (RAG Autorize)               
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Operation           ┃ Intruder      ┃ Ex-Member ┃ Anonymous ┃ Key Diff  ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━┩
│ Direct Vector Fetch │ BYPASS_STATUS │ ENFORCED  │ ENFORCED  │ J=0.88    │
│ Download Raw File   │ BYPASS_CANARY │ ENFORCED  │ ENFORCED  │ J=1.00    │
└─────────────────────┴───────────────┴───────────┴───────────┴───────────┘
```

