"""
Pillar 5: Write-Side Poisoning (Cross-Tenant Indirect Injection).
Tests cross-tenant collection injection and document overwrites.
Evaluates whether an unauthorized user (Bob) can inject content into Alice's scope,
causing Alice's subsequent benign queries to return Bob's poisoned tracer tokens.
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger("firedamp.probes.scenarios.write_poisoning")

CHANNEL = ProbeChannel.WRITE_MUTATION.value
BUG_CLASS = BugClass.WRITE_SIDE_ACCESS.value


def test_cross_tenant_collection_injection(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    engine: ProbingEngine,
    dry_run: bool = False,
) -> ProbeResult:
    """
    Test Cross-Tenant Collection Injection:
    Bob attempts to upload and link a poisoned document into Alice's private knowledge collection.
    Alice subsequently queries her knowledge collection to verify whether Bob's injected
    canary tracer is returned in her benign retrieval results.
    """
    prompt_label = "Cross-tenant collection injection: Bob injects document into Alice's KB"
    category = "scenario:write_poisoning:collection_injection"

    bob_tracer = CanaryToken.generate(category="write_poison", owner="Bob")
    poison_doc = DecoyDocument(
        title="Bob_Poison_Tracer.md",
        content=(
            "# ADVERSARIAL INJECTION PAYLOAD\n\n"
            f"Integrity Compromise Tracer: {bob_tracer.token}\n"
            "Unauthorized cross-tenant knowledge injection.\n"
        ),
        category="write_poison",
        canaries=[bob_tracer],
        metadata={"attacker": "bob"},
    )

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Cross-tenant collection injection rejected: Access denied with 403 Forbidden.",
            retrieved_contexts=[],
            planted_canaries=[bob_tracer],
            probe_category=category,
            channel=CHANNEL,
        )

    alice_kb_ids = alice.metadata.get("knowledge_ids", [])
    target_kb_id = alice_kb_ids[0] if alice_kb_ids else "target-alice-kb"

    # Step 1: Bob attempts to inject his poisoned document into Alice's collection
    inject_res = adapter.inject_into_collection(
        base_url=base_url,
        session=bob,
        target_collection_id=target_kb_id,
        document=poison_doc,
    )

    # Step 2: Alice queries her own knowledge collection to verify integrity
    alice_query = "Summarize recent project updates, audit logs, and document integrity tokens."
    alice_text, alice_ctx, alice_raw = adapter.query_rag(base_url, alice, alice_query)

    # Step 3: Evaluate if Bob's tracer leaked into Alice's baseline
    eval_result = engine.evaluate_response(
        prompt=prompt_label,
        response_text=alice_text,
        retrieved_contexts=alice_ctx,
        planted_canaries=[bob_tracer],
        raw_response={"injection_response": inject_res, "alice_query": alice_raw},
        probe_category=category,
        channel=CHANNEL,
    )

    # If the injection API explicitly returned success and Alice retrieved the tracer
    if eval_result.is_leak:
        return eval_result

    # If the injection API accepted the payload without error, flag as potential integrity risk
    has_error = (
        isinstance(inject_res, dict)
        and (
            "error" in inject_res
            or inject_res.get("code") in (401, 403, 404, 405)
            or inject_res.get("status") in ("failed", "forbidden")
        )
    )

    if not has_error and isinstance(inject_res, dict) and inject_res.get("status") is True:
        return ProbeResult(
            probe_id="poison_inj",
            probe_prompt=prompt_label,
            probe_category=category,
            target_response=f"VULNERABLE: Collection injection accepted: {str(inject_res)[:100]}",
            retrieved_contexts=[f"Injected tracer: {bob_tracer.token}"],
            leaked_canaries=[bob_tracer.token],
            severity=LeakSeverity.CONTEXT_LEAK,
            channel=CHANNEL,
        )

    return eval_result


def test_cross_tenant_file_overwrite(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    engine: ProbingEngine,
    dry_run: bool = False,
) -> ProbeResult:
    """
    Test Cross-Tenant File Overwrite:
    Bob attempts to overwrite or mutate an existing file owned by Alice.
    Alice subsequently performs direct retrieval and RAG queries on her file
    to verify whether Bob's poisoned payload replaced or mutated her data.
    """
    prompt_label = "Cross-tenant file overwrite: Bob mutates Alice's document"
    category = "scenario:write_poisoning:file_overwrite"

    bob_overwrite_tracer = CanaryToken.generate(category="write_poison", owner="Bob")
    payload = f"OVERWRITE MUTATION TRACER: {bob_overwrite_tracer.token}"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Cross-tenant file overwrite rejected: 403 Forbidden.",
            retrieved_contexts=[],
            planted_canaries=[bob_overwrite_tracer],
            probe_category=category,
            channel=CHANNEL,
        )

    alice_file_ids = alice.metadata.get("file_ids", [])
    target_file_id = alice_file_ids[0] if alice_file_ids else "target-alice-file"

    # Step 1: Bob attempts to overwrite Alice's file
    overwrite_res = adapter.overwrite_resource(
        base_url=base_url,
        session=bob,
        resource_ref=target_file_id,
        payload=payload,
    )

    # Step 2: Alice inspects her file via direct retrieval and RAG query
    alice_text, alice_ctx, alice_raw = adapter.query_resource_direct(
        base_url=base_url,
        session=alice,
        resource_ref=target_file_id,
    )

    eval_result = engine.evaluate_response(
        prompt=prompt_label,
        response_text=alice_text,
        retrieved_contexts=alice_ctx,
        planted_canaries=[bob_overwrite_tracer],
        raw_response={"overwrite_res": overwrite_res, "alice_raw": alice_raw},
        probe_category=category,
        channel=CHANNEL,
    )

    if eval_result.is_leak:
        return eval_result

    # Check if overwrite API reported success without permission error
    has_error = (
        isinstance(overwrite_res, dict)
        and (
            "error" in overwrite_res
            or overwrite_res.get("code") in (401, 403, 404, 405)
            or overwrite_res.get("status") in ("failed", "forbidden")
        )
    )

    if not has_error and isinstance(overwrite_res, dict) and overwrite_res.get("status") is True:
        return ProbeResult(
            probe_id="poison_ow",
            probe_prompt=prompt_label,
            probe_category=category,
            target_response=f"VULNERABLE: Overwrite mutation accepted: {str(overwrite_res)[:100]}",
            retrieved_contexts=[f"Overwritten tracer: {bob_overwrite_tracer.token}"],
            leaked_canaries=[bob_overwrite_tracer.token],
            severity=LeakSeverity.DIRECT_LEAK,
            channel=CHANNEL,
        )

    return eval_result


def run_write_poisoning_scenarios(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    engine: ProbingEngine,
    dry_run: bool = False,
) -> List[ProbeResult]:
    """
    Executes all Pillar 5 (Write-Side Poisoning) scenario probes:
    1. Cross-tenant collection injection
    2. Cross-tenant file overwrite
    """
    results: List[ProbeResult] = []

    res1 = test_cross_tenant_collection_injection(
        adapter=adapter,
        base_url=base_url,
        alice=alice,
        bob=bob,
        engine=engine,
        dry_run=dry_run,
    )
    results.append(res1)

    res2 = test_cross_tenant_file_overwrite(
        adapter=adapter,
        base_url=base_url,
        alice=alice,
        bob=bob,
        engine=engine,
        dry_run=dry_run,
    )
    results.append(res2)

    return results

