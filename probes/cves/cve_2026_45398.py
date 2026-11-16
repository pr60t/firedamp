"""
Behavioral Regression Probe for CVE-2026-45398.
Target: Open WebUI < 0.9.5
Bug Class: Role or Function-Level Authorization Bypass (Prefix/UUID Bypass)
Channel: direct_api

Mechanism:
The access-check helper strictly validated 'user-memory-*' and 'file-*' prefixes,
allowing knowledge-base raw UUIDs to pass through unchecked into retrieval query
endpoints (/process/text, /process/file, /query).
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
    alice_kb_ids = alice.metadata.get("knowledge_ids", [])
    target_uuid = alice_kb_ids[0] if alice_kb_ids else "00000000-0000-0000-0000-000000000000"

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

    resp_text, retrieved_ctx, raw_resp = adapter.query_resource_direct(
        base_url,
        bob,
        resource_ref=target_uuid,
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

