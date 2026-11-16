"""
Behavioral Regression Probe for CVE-2026-44560.
Target: Open WebUI < 0.9.0
Bug Class: Missing Authorization on Route (IDOR/BOLA)
Channel: direct_api

Mechanism:
Earlier versions permitted direct vector queries referencing predictable collection
names like 'file-<id>' without verifying whether the requesting user owned the file.
"""

from typing import List, Optional
from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult, LeakSeverity

CVE_ID = "CVE-2026-44560"
CHANNEL = "direct_api"
BUG_CLASS = "missing_authorization_on_route"
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
    """Execute behavioral regression probe for CVE-2026-44560."""
    alice_file_ids = alice.metadata.get("file_ids", [])
    target_ref = f"file-{alice_file_ids[0]}" if alice_file_ids else "file-unauthorized-target"

    prompt_label = f"Direct vector query against unauthorized collection '{target_ref}' (CVE-2026-44560)"

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
        resource_ref=target_ref,
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

