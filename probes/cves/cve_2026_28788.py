"""
Behavioral Regression Probe for CVE-2026-28788.
Target: Open WebUI < 0.8.6
Bug Class: Write-Side Access & Poisoning
Channel: write_side

Mechanism:
The process_files_batch() endpoint allowed any authenticated user to overwrite
another user's file by supplying their file_id, serving the overwritten content to the
LLM in subsequent RAG queries.
"""

from typing import List, Optional
from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult, LeakSeverity

CVE_ID = "CVE-2026-28788"
CHANNEL = "write_side"
BUG_CLASS = "write_side_access_poisoning"
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
    """Execute behavioral regression probe for CVE-2026-28788."""
    alice_file_ids = alice.metadata.get("file_ids", [])
    target_file_id = alice_file_ids[0] if alice_file_ids else "unauthorized-file-id"

    # Synthetic tracer representing Bob's overwrite payload
    bob_tracer = CanaryToken.generate(category="write_poison", owner="Bob")
    prompt_label = f"Cross-user batch file overwrite targeting '{target_file_id}' (CVE-2026-28788)"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Batch file overwrite rejected with 403 Forbidden.",
            retrieved_contexts=[],
            planted_canaries=[bob_tracer],
            probe_category=f"cve_regression:{CVE_ID}",
            channel=CHANNEL,
        )

    # Bob attempts to mutate Alice's file
    res = adapter.overwrite_resource(
        base_url,
        bob,
        resource_ref=target_file_id,
        payload=f"POISONED TRACER: {bob_tracer.token}",
    )

    # If the endpoint accepted Bob's overwrite without permission error, it's an integrity violation
    has_error = (
        "error" in res
        or res.get("code") in (401, 403, 404, 405)
        or res.get("status") in ("failed", "forbidden")
    )

    if not has_error and res.get("status") is True:
        # Overwrite succeeded: report as DIRECT_LEAK / integrity violation
        return ProbeResult(
            probe_id="cve28788",
            probe_prompt=prompt_label,
            probe_category=f"cve_regression:{CVE_ID}",
            target_response=f"VULNERABLE: Overwrite accepted by server: {str(res)[:100]}",
            retrieved_contexts=[f"Injected tracer: {bob_tracer.token}"],
            leaked_canaries=[bob_tracer.token],
            severity=LeakSeverity.DIRECT_LEAK,
            channel=CHANNEL,
        )

    # Blocked properly
    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=f"Server rejected overwrite: {str(res)[:100]}",
        retrieved_contexts=[],
        planted_canaries=[bob_tracer],
        raw_response=res,
        probe_category=f"cve_regression:{CVE_ID}",
        channel=CHANNEL,
    )

