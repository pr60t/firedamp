"""
Behavioral Regression Probe for CVE-2026-28788.
Target: Open WebUI < 0.8.6 (Fixed in 0.8.6)
Bug Class: Write-Side Access & Poisoning
Channel: write_side
Advisory: GHSA-jjp7-g2jw-wh3j

Mechanism:
The POST /api/v1/retrieval/process/files/batch endpoint omitted ownership and
authorization checks, allowing any authenticated user to overwrite another user's
indexed file contents (File.data.content in the database) by supplying their file_id.

Readback Safety & Provenance Verification Strategy:
1. Trusted Scan-Scoped Registry:
   - Tracks disposable resources provisioned specifically during the active scan run in a trusted internal registry.
   - Rejects unverified self-attestations in mutable metadata.
   - Requires an authentic run ID from the scan execution context; aborts if missing.
2. Mandatory Pre-Write Safety Gate:
   Before calling overwrite_resource(), requires:
     a. Trusted current-run disposable resource registration in internal registry.
     b. Authoritative server-side ownership verification via adapter.get_file_metadata().
     c. Confirmed target existence on the target platform.
     d. Successfully retrieved indexed baseline content.
     e. Valid baseline SHA-256 digest computation.
   If any condition fails, aborts with INCONCLUSIVE without sending any overwrite request.
3. Positive Attacker Authentication Validation:
   - Uses explicit adapter.validate_session() to positively confirm attacker authentication.
   - Never infers authentication from empty resource lists or swallowed HTTP 401/403 errors.
4. Strict Response Contract Handling:
   - Rejects contradictory responses where target appears in both results[] and errors[].
   - HTTP 405 is never treated as an authorization block.
   - HTTP 404 is never classified as CLEAN without positive auth validation and authorization-specific rejection evidence.
5. Targeted Cleanup:
   - Uses adapter.delete_file() to delete exclusively the disposable file created for this probe.
   - Explicitly tracks and reports cleanup success or failure.
   - Never weakens a COMPROMISED result to CLEAN on cleanup failure.
6. Non-Destructive Dry-Run:
   - Evaluated before provisioning or modifying any remote resource.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, DecoyDocument, ProbingEngine, ProbeResult, LeakSeverity
from probes.knowledge_membership import resolve_file_knowledge_base

logger = logging.getLogger("firedamp.probes.cve_2026_28788")

CVE_ID = "CVE-2026-28788"
CHANNEL = "write_side"
BUG_CLASS = "write_side_access_poisoning"
PRECONDITION = None

MAX_ASYNC_READBACK_RETRIES = 3
ASYNC_RETRY_DELAY_SECONDS = 0.05


# Shared registry remains imported here for backwards-compatible public test helpers.
from probes.disposable_registry import (
    TrustedScanDisposableRegistry,
    _TRUSTED_SCAN_REGISTRY,
    register_trusted_disposable_resource,
    clear_trusted_registry,
)

def _compute_sha256(content: Any) -> Optional[str]:
    """Computes SHA-256 hex digest for string or byte content."""
    if isinstance(content, str):
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    if isinstance(content, (bytes, bytearray)):
        return hashlib.sha256(content).hexdigest()
    return None


def _validate_attacker_identity(adapter: TargetAdapter, base_url: str, bob: UserSession) -> Tuple[bool, Optional[str]]:
    """
    Validates attacker's authentication and confirms that the session positively belongs
    to the expected Bob attacker persona using adapter.get_authenticated_user_id().
    Returns (True, None) on verified identity match.
    Returns (False, diagnostic_error_string) on failure.
    Does not infer identity from resource enumeration or generic boolean session validity.
    """
    if not bob:
        return False, "INCONCLUSIVE: Attacker session object is missing."

    expected_bob_id = bob.metadata.get("user_id") if isinstance(bob.metadata, dict) else None
    if not expected_bob_id or not isinstance(expected_bob_id, str) or not expected_bob_id.strip():
        return False, "INCONCLUSIVE: Expected attacker server user ID is missing or empty in session context for Bob; aborting probe."

    try:
        if not hasattr(adapter, "get_authenticated_user_id"):
            return (
                False,
                "INCONCLUSIVE: Adapter does not support authoritative user ID retrieval (get_authenticated_user_id); "
                "aborting probe.",
            )

        auth_user_id = adapter.get_authenticated_user_id(base_url, bob)
        if not auth_user_id or not isinstance(auth_user_id, str) or not auth_user_id.strip():
            return False, "INCONCLUSIVE: Attacker authentication failed or returned empty server user ID; aborting probe."

        if auth_user_id.strip() != expected_bob_id.strip():
            return (
                False,
                f"INCONCLUSIVE: Authenticated session identity '{auth_user_id}' does not match "
                f"expected attacker persona ID '{expected_bob_id}'; aborting probe.",
            )

        return True, None
    except Exception as exc:
        logger.debug(f"Attacker authentication validation failed: {exc}")
        return False, f"INCONCLUSIVE: Attacker authentication encountered transport error: {exc}"





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
    # 1. Non-destructive Dry-Run Guard: Checked before any provisioning or network calls
    if dry_run:
        return ProbeResult(
            probe_id="cve28788",
            probe_prompt="Cross-user batch file overwrite (dry run) (CVE-2026-28788)",
            probe_category=f"cve_regression:{CVE_ID}",
            target_response="SKIPPED: Dry-run enabled; no resource was provisioned and no vulnerability test was executed.",
            retrieved_contexts=[],
            leaked_canaries=[],
            severity=LeakSeverity.NONE,
            channel=CHANNEL,
        )

    # 2. Authoritative Engine Run ID Verification (fail-closed, no fallback)
    authoritative_run_id = getattr(engine, "run_id", None)
    if not authoritative_run_id or not isinstance(authoritative_run_id, str) or not authoritative_run_id.strip():
        return ProbeResult(
            probe_id="cve28788",
            probe_prompt="Cross-user batch file overwrite (CVE-2026-28788)",
            probe_category=f"cve_regression:{CVE_ID}",
            target_response=(
                "INCONCLUSIVE: Engine run ID is missing or empty; aborting to prevent untracked destructive operations."
            ),
            retrieved_contexts=[],
            leaked_canaries=[],
            severity=LeakSeverity.NONE,
            channel=CHANNEL,
        )

    current_run_id = authoritative_run_id.strip()

    alice_run_id = alice.metadata.get("run_id") if isinstance(alice.metadata, dict) else None
    if alice_run_id is not None:
        if not isinstance(alice_run_id, str) or alice_run_id.strip() != current_run_id:
            return ProbeResult(
                probe_id="cve28788",
                probe_prompt="Cross-user batch file overwrite (CVE-2026-28788)",
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Alice session run ID '{alice_run_id}' conflicts with "
                    f"authoritative engine run ID '{current_run_id}'; aborting."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )

    # 3. Identify or Provision Target in Trusted Registry
    target_file_id: Optional[str] = None
    provisioned_by_this_probe: bool = False
    ownership_verified_for_cleanup: bool = False
    candidate_ids = alice.metadata.get("disposable_file_ids", []) if isinstance(alice.metadata, dict) else []
    ordinary_file_ids = (
        alice.metadata.get("ordinary_file_ids", alice.metadata.get("file_ids", []))
        if isinstance(alice.metadata, dict) else []
    )

    if candidate_ids:
        for cid in candidate_ids:
            # Reject if present in ordinary user files
            if isinstance(ordinary_file_ids, list) and cid in ordinary_file_ids:
                logger.warning(f"Candidate '{cid}' is present in ordinary file_ids; rejected.")
                continue
            # Must be registered in trusted registry under current_run_id
            if _TRUSTED_SCAN_REGISTRY.is_registered(current_run_id, cid, alice.username):
                target_file_id = cid
                break

        if target_file_id is None:
            # Candidate disposable IDs were provided, but failed trusted scan registry verification
            logger.warning(
                "Disposable candidate IDs in alice.metadata failed trusted scan registry verification. "
                "Aborting destructive probe."
            )
            return ProbeResult(
                probe_id="cve28788",
                probe_prompt="Cross-user batch file overwrite (CVE-2026-28788)",
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    "INCONCLUSIVE: Target resource in disposable_file_ids failed trusted "
                    "scan-scoped registry verification; aborting probe to prevent unsafe overwrite."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
    else:
        # Dynamically provision a dedicated disposable decoy file specifically for this scan run
        disposable_canary = CanaryToken.generate(category="disposable_victim", owner=alice.username)
        disposable_doc = DecoyDocument(
            title="disposable_victim_target.md",
            category="disposable_regression_target",
            content=f"BASELINE_DISPOSABLE_INDEXED_DATA: {disposable_canary.token}",
            canaries=[disposable_canary],
        )
        try:
            provisioned_id = adapter.ingest_document(base_url, alice, disposable_doc)
            if not provisioned_id or not isinstance(provisioned_id, str):
                raise ValueError("Adapter returned empty or non-string file ID during provisioning")

            # Register in trusted internal scan-scoped registry
            _TRUSTED_SCAN_REGISTRY.register(
                run_id=current_run_id,
                resource_id=provisioned_id,
                owner=alice.username,
                provisioning_status="provisioned",
            )
            alice.metadata.setdefault("disposable_file_ids", []).append(provisioned_id)
            alice.metadata.setdefault("disposable_provenance", {})[provisioned_id] = {
                "file_id": provisioned_id,
                "provisioned_by": "firedamp",
                "owner": alice.username,
                "run_id": current_run_id,
                "active": True,
            }
            target_file_id = provisioned_id
            provisioned_by_this_probe = True
        except Exception as exc:
            logger.error(f"Could not provision disposable file dynamically: {exc}")
            return ProbeResult(
                probe_id="cve28788",
                probe_prompt="Cross-user batch file overwrite (CVE-2026-28788)",
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    "INCONCLUSIVE: Disposable victim resource provisioning failed; "
                    "aborting probe to prevent unsafe overwrite."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )

    prompt_label = f"Cross-user batch file overwrite targeting disposable file '{target_file_id}' (CVE-2026-28788)"
    final_result: Optional[ProbeResult] = None

    try:
        # 4. Mandatory Pre-Write Safety Gate
        # Pre-write Guard 4a: Must be in trusted registry under current run
        if not _TRUSTED_SCAN_REGISTRY.is_registered(current_run_id, target_file_id, alice.username):
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Target resource '{target_file_id}' is not registered in trusted "
                    f"registry for run '{current_run_id}'; aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Pre-write Guard 4b & 4c: Independently verify server-side metadata and exact existence
        server_meta = adapter.get_file_metadata(base_url, alice, target_file_id)
        if server_meta is None or not isinstance(server_meta, dict):
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Authoritative server-side metadata for '{target_file_id}' "
                    "could not be retrieved; aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        if server_meta.get("id") != target_file_id:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Server-side metadata ID '{server_meta.get('id')}' does not match "
                    f"target file ID '{target_file_id}'; aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Pre-write Guard 4c: Strict fail-closed server-side user_id verification
        alice_server_user_id = alice.metadata.get("user_id") if isinstance(alice.metadata, dict) else None
        if not alice_server_user_id or not isinstance(alice_server_user_id, str) or not alice_server_user_id.strip():
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Authoritative victim server user ID is missing or empty in session context for '{alice.username}'; "
                    "aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        server_file_user_id = server_meta.get("user_id")
        if not server_file_user_id or not isinstance(server_file_user_id, str) or not server_file_user_id.strip():
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Authoritative server-side user_id is missing or empty in file metadata for '{target_file_id}'; "
                    "aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        if server_file_user_id.strip() != alice_server_user_id.strip():
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Server-side file user_id '{server_file_user_id}' does not match "
                    f"victim server user_id '{alice_server_user_id}'; aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Server-side ownership confirmed to match Alice's verified server user ID
        ownership_verified_for_cleanup = True

        # Pre-write Guard 4d: Positively verify attacker authentication and identity (must be Bob)
        bob_auth_valid, bob_auth_err = _validate_attacker_identity(adapter, base_url, bob)
        if not bob_auth_valid:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=bob_auth_err or "INCONCLUSIVE: Attacker authentication failed.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Pre-write Guard 4e & 4f: Successfully retrieve indexed baseline content and valid SHA-256 digest
        pre_content = adapter.read_file_content(base_url, alice, target_file_id)
        if pre_content is None:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Failed to retrieve indexed baseline content for '{target_file_id}'; "
                    "aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        pre_hash = _compute_sha256(pre_content)
        if pre_hash is None:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Failed to compute baseline SHA-256 digest for '{target_file_id}'; "
                    "aborting destructive operation."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        baseline_confirmed = True

        # 5. Execute Unauthorized Overwrite Attempt as Bob
        bob_tracer = CanaryToken.generate(category="write_poison", owner=bob.username)
        poison_payload = f"POISONED TRACER: {bob_tracer.token}"

        target_kb, res_err = resolve_file_knowledge_base(
            adapter=adapter,
            base_url=base_url,
            session=alice,
            target_file_id=target_file_id,
        )
        if not target_kb:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Could not establish authoritative knowledge base for target file "
                    f"'{target_file_id}': {res_err}"
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        try:
            res = adapter.overwrite_resource(
                base_url,
                bob,
                resource_ref=target_file_id,
                payload=poison_payload,
                collection_name=target_kb,
                file_model=server_meta,
            )
        except TypeError as err:
            logger.error(f"TypeError calling overwrite_resource: {err}")
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: TypeError calling overwrite_resource: {err}",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        if not isinstance(res, dict):
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: Malformed non-dict response received from overwrite endpoint: {type(res)}",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        code = res.get("code") or res.get("status_code")

        # Rule: Do not classify HTTP 405 as proof of an authorization block
        if code == 405 or "Method Not Allowed" in str(res):
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response="INCONCLUSIVE: Overwrite endpoint returned HTTP 405 Method Not Allowed; cannot establish authorization enforcement.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Rule: Strict handling of HTTP 404
        if code == 404:
            is_auth_valid, auth_err = _validate_attacker_identity(adapter, base_url, bob)
            err_text = str(res.get("error", "")).lower()
            has_auth_rejection_evidence = any(
                kw in err_text for kw in ("permission denied", "unauthorized", "forbidden", "not owner")
            )

            if not is_auth_valid or not has_auth_rejection_evidence or not baseline_confirmed:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=(
                        auth_err
                        if not is_auth_valid
                        else (
                            "INCONCLUSIVE: Overwrite endpoint returned HTTP 404 Not Found; "
                            "cannot establish authorization enforcement without confirmed auth and authorization-specific rejection evidence."
                        )
                    ),
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            post_content = adapter.read_file_content(base_url, alice, target_file_id)
            post_hash = _compute_sha256(post_content)
            if post_content is not None and post_hash == pre_hash and bob_tracer.token not in str(post_content):
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response="CLEAN: Server returned authorization-specific rejection under HTTP 404 and original indexed content remains intact.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response="INCONCLUSIVE: Server returned HTTP 404 on overwrite, but post-attempt indexed content could not be verified intact.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Rule: HTTP 401/403 confirmed authorization rejection at router level
        if code in (401, 403):
            is_auth_valid, auth_err = _validate_attacker_identity(adapter, base_url, bob)
            if not is_auth_valid:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=auth_err or f"INCONCLUSIVE: Overwrite attempt returned HTTP {code}, but attacker authentication could not be validated via independent session validation.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            post_content = adapter.read_file_content(base_url, alice, target_file_id)
            post_hash = _compute_sha256(post_content)
            if post_content is None or post_hash is None:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"INCONCLUSIVE: Server rejected overwrite with HTTP {code}, but indexed-content endpoint cannot be accessed to establish document integrity.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            post_str = str(post_content)
            if bob_tracer.token in post_str:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"COMPROMISED: Despite rejection code {code}, attacker tracer was verified in victim indexed content: {post_str[:100]}",
                    retrieved_contexts=[f"Injected tracer verified in victim file: {bob_tracer.token}"],
                    leaked_canaries=[bob_tracer.token],
                    severity=LeakSeverity.DIRECT_LEAK,
                    channel=CHANNEL,
                )
                return final_result

            if post_hash == pre_hash and bob_tracer.token not in post_str:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"CLEAN: Server rejected unauthorized overwrite with HTTP {code}, attacker authentication verified, and original indexed content remains intact.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: Server rejected overwrite with HTTP {code}, but post-attempt indexed content hash changed unexpectedly.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Exact enforcement of BatchProcessFilesResponse contract: results[] and errors[]
        results_list = res.get("results")
        errors_list = res.get("errors")

        if results_list is None and errors_list is None:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: Malformed response shape; missing results and errors lists: {str(res)[:100]}",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        target_result_entry = None
        if isinstance(results_list, list):
            for item in results_list:
                if isinstance(item, dict) and item.get("file_id") == target_file_id:
                    target_result_entry = item
                    break

        target_error_entry = None
        if isinstance(errors_list, list):
            for item in errors_list:
                if isinstance(item, dict) and item.get("file_id") == target_file_id:
                    target_error_entry = item
                    break

        # Contradictory Batch Response Guard: Reject if target appears in BOTH results and errors
        if target_result_entry is not None and target_error_entry is not None:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=(
                    f"INCONCLUSIVE: Contradictory batch response; target file '{target_file_id}' "
                    "appeared in both results[] and errors[] lists."
                ),
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # If target appears in neither results nor errors:
        if target_result_entry is None and target_error_entry is None:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: Response omitted target file '{target_file_id}' from both results and errors lists.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Scenario A: Target in errors[] -> Check for confirmed ownership/authorization rejection
        if target_error_entry is not None:
            error_msg = str(target_error_entry.get("error", "")).lower()
            auth_rejection_keywords = [
                "permission denied",
                "not file owner",
                "not owner",
                "unauthorized",
                "forbidden",
                "access denied",
            ]
            is_ownership_rejection = any(kw in error_msg for kw in auth_rejection_keywords)

            if not is_ownership_rejection:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"INCONCLUSIVE: Server returned generic per-file error '{target_error_entry.get('error')}', not a confirmed ownership rejection.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            is_auth_valid, auth_err = _validate_attacker_identity(adapter, base_url, bob)
            if not is_auth_valid:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=auth_err or f"INCONCLUSIVE: Server returned per-file authorization rejection ({target_error_entry.get('error')}), but attacker authentication could not be validated via independent session validation.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            post_content = adapter.read_file_content(base_url, alice, target_file_id)
            post_hash = _compute_sha256(post_content)
            if post_content is None or post_hash is None:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"INCONCLUSIVE: Server rejected with '{target_error_entry.get('error')}', but indexed-content endpoint cannot be accessed to establish document integrity.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            post_str = str(post_content)
            if bob_tracer.token in post_str:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"COMPROMISED: Despite rejection in errors list, attacker tracer was verified in victim indexed content: {post_str[:100]}",
                    retrieved_contexts=[f"Injected tracer verified in victim file: {bob_tracer.token}"],
                    leaked_canaries=[bob_tracer.token],
                    severity=LeakSeverity.DIRECT_LEAK,
                    channel=CHANNEL,
                )
                return final_result

            if post_hash == pre_hash and bob_tracer.token not in post_str:
                final_result = ProbeResult(
                    probe_id="cve28788",
                    probe_prompt=prompt_label,
                    probe_category=f"cve_regression:{CVE_ID}",
                    target_response=f"CLEAN: Server returned per-file authorization rejection ({target_error_entry.get('error')}), attacker authentication verified, and original indexed content remains intact.",
                    retrieved_contexts=[],
                    leaked_canaries=[],
                    severity=LeakSeverity.NONE,
                    channel=CHANNEL,
                )
                return final_result

            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: Server rejected with '{target_error_entry.get('error')}', but post-attempt indexed content hash changed unexpectedly.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        # Scenario B: Target in results[] -> Must be exact status == "completed"
        status_val = target_result_entry.get("status")
        if status_val != "completed":
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"INCONCLUSIVE: Target entry status was '{status_val}', expected exact 'completed'.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        post_content = None
        post_str = None

        for attempt in range(MAX_ASYNC_READBACK_RETRIES):
            post_content = adapter.read_file_content(base_url, alice, target_file_id)
            if post_content is not None:
                post_str = post_content if isinstance(post_content, str) else (
                    post_content.decode("utf-8", errors="replace") if isinstance(post_content, (bytes, bytearray)) else str(post_content)
                )
                if bob_tracer.token in post_str:
                    break
            if attempt < MAX_ASYNC_READBACK_RETRIES - 1:
                time.sleep(ASYNC_RETRY_DELAY_SECONDS)

        if post_content is None or post_str is None:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response="INCONCLUSIVE: Server accepted batch overwrite in results[], but post-overwrite indexed content could not be accessed.",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
                channel=CHANNEL,
            )
            return final_result

        if bob_tracer.token in post_str:
            final_result = ProbeResult(
                probe_id="cve28788",
                probe_prompt=prompt_label,
                probe_category=f"cve_regression:{CVE_ID}",
                target_response=f"COMPROMISED: Overwrite mutation proven in victim indexed content via authorized readback path: {post_str[:100]}",
                retrieved_contexts=[f"Injected tracer verified in victim file: {bob_tracer.token}"],
                leaked_canaries=[bob_tracer.token],
                severity=LeakSeverity.DIRECT_LEAK,
                channel=CHANNEL,
            )
            return final_result

        final_result = ProbeResult(
            probe_id="cve28788",
            probe_prompt=prompt_label,
            probe_category=f"cve_regression:{CVE_ID}",
            target_response="INCONCLUSIVE: Server reported overwrite completed in results[], but attacker tracer was absent from indexed content after bounded retries.",
            retrieved_contexts=[],
            leaked_canaries=[],
            severity=LeakSeverity.NONE,
            channel=CHANNEL,
        )
        return final_result

    except Exception as exc:
        logger.exception(f"Unexpected exception during probe execution: {exc}")
        final_result = ProbeResult(
            probe_id="cve28788",
            probe_prompt=prompt_label,
            probe_category=f"cve_regression:{CVE_ID}",
            target_response=f"INCONCLUSIVE: Probe encountered unexpected exception: {exc}",
            retrieved_contexts=[],
            leaked_canaries=[],
            severity=LeakSeverity.NONE,
            channel=CHANNEL,
        )
        return final_result

    finally:
        # Guarantee targeted cleanup only if this probe invocation actually provisioned the resource
        if provisioned_by_this_probe and target_file_id:
            # SAFETY REQUIREMENT: Only invoke adapter.delete_file() when BOTH conditions are true:
            # 1. Resource was provisioned by this exact probe invocation (provisioned_by_this_probe).
            # 2. Authoritative server-side ownership was independently verified to match Alice (ownership_verified_for_cleanup).
            # If ownership is missing, unavailable, or mismatched, do NOT issue DELETE.
            if not ownership_verified_for_cleanup:
                logger.warning(
                    f"Targeted cleanup skipped for disposable file '{target_file_id}': "
                    "server-side ownership could not be verified."
                )
                if final_result is not None:
                    final_result.target_response += (
                        " [CLEANUP SKIPPED: Server-side ownership could not be verified; manual cleanup may be required.]"
                    )
            else:
                try:
                    cleanup_success = adapter.delete_file(base_url, alice, target_file_id)
                    if cleanup_success:
                        _TRUSTED_SCAN_REGISTRY.mark_cleaned_up(current_run_id, target_file_id)
                        if final_result is not None:
                            final_result.target_response += f" [Cleanup: disposable file '{target_file_id}' deleted successfully]"
                    else:
                        logger.warning(f"Targeted cleanup failed for disposable file '{target_file_id}'")
                        if final_result is not None:
                            final_result.target_response += f" [CLEANUP FAILED: Unable to delete disposable resource '{target_file_id}']"
                except Exception as exc:
                    logger.warning(f"Targeted cleanup encountered exception for disposable file '{target_file_id}': {exc}")
                    if final_result is not None:
                        final_result.target_response += f" [CLEANUP FAILED: Exception while deleting disposable resource '{target_file_id}': {exc}]"

    return final_result
