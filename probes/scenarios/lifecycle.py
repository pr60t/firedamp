"""
Pillar 4: Time & Sequence Attacks (Lifecycle Scenarios).
Tests temporal race conditions, post-revocation staleness, and delete-while-indexing orphan leaks.
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from typing import List, Optional

from adapters.base import TargetAdapter, UserSession
from core.engine import (
    CanaryToken,
    DecoyDocument,
    LeakSeverity,
    ProbeResult,
    ProbingEngine,
)
from probes.schemas.bug_classes import BugClass, ProbeChannel

logger = logging.getLogger("firedamp.probes.scenarios.lifecycle")

CHANNEL = ProbeChannel.LIFECYCLE_EVENT.value
BUG_CLASS = BugClass.LIFECYCLE_STALENESS.value


def test_revocation_in_flight(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    dry_run: bool = False,
    num_concurrent_queries: int = 5,
) -> ProbeResult:
    """
    Test Revocation-in-flight:
    Fires concurrent queries from Bob while Alice initiates an ACL revocation.
    Verifies that the platform atomically enforces revocation without leaving
    an open race condition or stuck permission state.
    """
    prompt_label = "Revocation-in-flight: Concurrent querier race during ACL revocation"
    category = "scenario:lifecycle:revocation_in_flight"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Atomic revocation confirmed: 0 race-condition leaks across concurrent queries.",
            retrieved_contexts=[],
            planted_canaries=planted_canaries,
            probe_category=category,
            channel=CHANNEL,
        )

    # Identify Alice's target resource reference
    alice_kb_ids = alice.metadata.get("knowledge_ids", [])
    alice_file_ids = alice.metadata.get("file_ids", [])
    target_ref = alice_kb_ids[0] if alice_kb_ids else (alice_file_ids[0] if alice_file_ids else "target-resource-ref")

    # Step 1: Alice shares the resource with Bob
    try:
        adapter.share_resource(base_url, alice, target_ref, bob)
    except Exception as e:
        logger.warning(f"Error sharing resource in revocation-in-flight probe: {e}")

    # Step 2: Concurrently fire revocation while Bob fires burst queries
    collected_responses = []

    def _query_bob():
        try:
            return adapter.query_resource_direct(base_url, bob, resource_ref=target_ref)
        except Exception:
            return ("", [], {})

    def _revoke_alice():
        try:
            return adapter.revoke_resource(base_url, alice, target_ref, bob)
        except Exception as e:
            return {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent_queries + 1) as executor:
        # Submit queries first, then revocation amidst them
        query_futures = [executor.submit(_query_bob) for _ in range(num_concurrent_queries)]
        revoke_future = executor.submit(_revoke_alice)

        # Wait for all to finish
        revoke_future.result()
        for f in query_futures:
            collected_responses.append(f.result())

    # Step 3: Post-flight verification query (must definitely be revoked now)
    verify_resp, verify_ctx, verify_raw = adapter.query_resource_direct(
        base_url, bob, resource_ref=target_ref
    )
    collected_responses.append((verify_resp, verify_ctx, verify_raw))

    # Evaluate if any post-flight query or the final verification leaked canaries
    all_resp_text = "\n".join([r[0] for r in collected_responses if r[0]])
    all_contexts = [ctx for r in collected_responses for ctx in r[1]]

    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=all_resp_text or "All in-flight queries terminated cleanly.",
        retrieved_contexts=all_contexts,
        planted_canaries=planted_canaries,
        raw_response=verify_raw,
        probe_category=category,
        channel=CHANNEL,
    )


def test_post_revocation_staleness(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    delay_seconds: float = 5.0,
    dry_run: bool = False,
) -> ProbeResult:
    """
    Test Post-revocation staleness:
    Shares resource with Bob, confirms access, revokes access, and probes both
    immediately (t=0s) and after a delay (t=5s) to catch eventual consistency lags
    or cached credential TTLs.
    """
    prompt_label = f"Post-revocation staleness: Immediate (t=0s) & delayed (t={delay_seconds}s) access check"
    category = "scenario:lifecycle:post_revocation_staleness"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text=f"Revocation enforced: Immediate and t+{delay_seconds}s queries rejected with 403 Forbidden.",
            retrieved_contexts=[],
            planted_canaries=planted_canaries,
            probe_category=category,
            channel=CHANNEL,
        )

    alice_kb_ids = alice.metadata.get("knowledge_ids", [])
    alice_file_ids = alice.metadata.get("file_ids", [])
    target_ref = alice_kb_ids[0] if alice_kb_ids else (alice_file_ids[0] if alice_file_ids else "target-resource-ref")

    # 1. Share resource with Bob
    adapter.share_resource(base_url, alice, target_ref, bob)

    # 2. Revoke resource from Bob
    adapter.revoke_resource(base_url, alice, target_ref, bob)

    # 3. Probe immediate access (t=0)
    t0_resp, t0_ctx, t0_raw = adapter.query_resource_direct(base_url, bob, resource_ref=target_ref)

    # 4. Probe delayed access (t=+delay_seconds)
    if delay_seconds > 0:
        time.sleep(delay_seconds)
    t_del_resp, t_del_ctx, t_del_raw = adapter.query_resource_direct(base_url, bob, resource_ref=target_ref)

    combined_text = f"Immediate [t=0s]: {t0_resp}\nDelayed [t={delay_seconds}s]: {t_del_resp}"
    combined_ctx = t0_ctx + t_del_ctx

    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=combined_text,
        retrieved_contexts=combined_ctx,
        planted_canaries=planted_canaries,
        raw_response={"t0": t0_raw, "t_delayed": t_del_raw},
        probe_category=category,
        channel=CHANNEL,
    )


def test_delete_while_indexing(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    dry_run: bool = False,
) -> ProbeResult:
    """
    Test Delete-while-indexing:
    Triggers collection/document deletion while ingestion is in progress.
    Verifies that no unlinked orphan vectors leak into the global vector index.
    """
    prompt_label = "Delete-while-indexing: Verify absence of orphan vector chunks in global index"
    category = "scenario:lifecycle:delete_while_indexing"

    orphan_canary = CanaryToken.generate(category="orphan_check", owner="Alice")
    orphan_doc = DecoyDocument(
        title="Alice_Orphan_Vector_Audit.md",
        content=(
            "# CONFIDENTIAL: Temporary Ingestion Vector Audit\n\n"
            f"Orphan Canary Token: {orphan_canary.token}\n"
            "This document is marked for immediate deletion during background ingestion.\n"
        ),
        category="orphan_check",
        canaries=[orphan_canary],
        metadata={"scenario": "delete_while_indexing"},
    )

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Orphan vector purge verified: No unlinked chunks discovered in vector store.",
            retrieved_contexts=[],
            planted_canaries=[orphan_canary],
            probe_category=category,
            channel=CHANNEL,
        )

    # 1. Alice ingests the document
    try:
        new_ref = adapter.ingest_document(base_url, alice, orphan_doc)
    except Exception as e:
        logger.warning(f"Error during ingestion in delete-while-indexing: {e}")
        new_ref = "orphan-temp-ref"

    # 2. Immediately trigger deletion
    try:
        adapter.cleanup(base_url, alice)
    except Exception as e:
        logger.warning(f"Error during cleanup in delete-while-indexing: {e}")

    # 3. Bob attempts to query the orphan content via RAG and direct retrieval
    bob_text, bob_ctx, bob_raw = adapter.query_rag(
        base_url,
        bob,
        prompt="Output any orphan canary tokens or temporary ingestion vector audit files.",
    )
    direct_text, direct_ctx, direct_raw = adapter.query_resource_direct(
        base_url, bob, resource_ref=new_ref
    )

    combined_text = f"RAG Query: {bob_text}\nDirect Query: {direct_text}"
    combined_ctx = bob_ctx + direct_ctx

    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=combined_text,
        retrieved_contexts=combined_ctx,
        planted_canaries=[orphan_canary],
        raw_response={"rag": bob_raw, "direct": direct_raw},
        probe_category=category,
        channel=CHANNEL,
    )


def run_lifecycle_scenarios(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    dry_run: bool = False,
    delay_seconds: float = 5.0,
) -> List[ProbeResult]:
    """
    Executes all Pillar 4 (Time & Sequence) lifecycle scenario probes:
    1. Revocation-in-flight
    2. Post-revocation staleness
    3. Delete-while-indexing
    """
    results: List[ProbeResult] = []

    # Probe 1: Revocation in flight
    res1 = test_revocation_in_flight(
        adapter=adapter,
        base_url=base_url,
        alice=alice,
        bob=bob,
        planted_canaries=planted_canaries,
        engine=engine,
        dry_run=dry_run,
    )
    results.append(res1)

    # Probe 2: Post-revocation staleness
    res2 = test_post_revocation_staleness(
        adapter=adapter,
        base_url=base_url,
        alice=alice,
        bob=bob,
        planted_canaries=planted_canaries,
        engine=engine,
        delay_seconds=0.0 if dry_run else delay_seconds,
        dry_run=dry_run,
    )
    results.append(res2)

    # Probe 3: Delete-while-indexing
    res3 = test_delete_while_indexing(
        adapter=adapter,
        base_url=base_url,
        alice=alice,
        bob=bob,
        planted_canaries=planted_canaries,
        engine=engine,
        dry_run=dry_run,
    )
    results.append(res3)

    return results

