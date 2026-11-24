"""
Pillar 5: Write-Side Poisoning (Cross-Tenant Indirect Injection).
Tests cross-tenant collection injection and document overwrites.
Evaluates whether an unauthorized user (Bob) can inject content into Alice's scope,
causing Alice's subsequent benign queries to return Bob's poisoned tracer tokens.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

from adapters.base import TargetAdapter, UserSession
from core.engine import (
    CanaryToken,
    DecoyDocument,
    LeakSeverity,
    ProbeResult,
    ProbingEngine,
)
from probes.schemas.bug_classes import BugClass, ProbeChannel
from probes.knowledge_membership import resolve_file_knowledge_base
from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY

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
    """Attempt collection injection only against a verified Alice disposable anchor.

    OpenWebUI creates a new file owned by Bob before attempting to link it into
    Alice's KB. The returned upload ID is registered and cleaned as a separate
    Bob-owned disposable resource after independent server-side owner checks.
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
            response_text="DRY RUN: collection-injection mutation was not executed.",
            retrieved_contexts=[],
            planted_canaries=[bob_tracer],
            probe_category=category,
            channel=CHANNEL,
        )

    alice_meta = alice.metadata if isinstance(alice.metadata, dict) else {}
    bob_meta = bob.metadata if isinstance(bob.metadata, dict) else {}
    run_id = getattr(engine, "run_id", None)
    if not isinstance(run_id, str) or not run_id.strip() or alice_meta.get("run_id") != run_id or bob_meta.get("run_id") != run_id:
        return ProbeResult(
            probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: Missing or mismatched current scan run ID; collection injection refused.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )

    ordinary_ids = alice_meta.get("ordinary_file_ids", alice_meta.get("file_ids", []))
    disposable_ids = alice_meta.get("disposable_file_ids", [])
    target_file_id = next((
        item.strip() for item in disposable_ids
        if isinstance(item, str) and item.strip()
        and (not isinstance(ordinary_ids, list) or item.strip() not in ordinary_ids)
        and _TRUSTED_SCAN_REGISTRY.is_registered(run_id, item.strip(), alice.username)
    ), None) if isinstance(disposable_ids, list) else None
    if not target_file_id:
        return ProbeResult(
            probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: No current-run trusted Alice disposable anchor is available; no injection attempted.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )

    expected_alice_id = alice_meta.get("user_id")
    expected_bob_id = bob_meta.get("user_id")
    bob_disposable_ids = bob_meta.get("disposable_file_ids", [])
    bob_file_ids = bob_meta.get("file_ids", [])
    if not isinstance(bob_disposable_ids, list) or not isinstance(bob_file_ids, list):
        return ProbeResult(
            probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: Bob disposable/file metadata is malformed; no injection attempted.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )
    if not all(isinstance(value, str) and value.strip() for value in (expected_alice_id, expected_bob_id)) or expected_alice_id == expected_bob_id:
        return ProbeResult(
            probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: Distinct authenticated Alice/Bob server identities are required; no injection attempted.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )

    uploaded_file_id: Optional[str] = None
    registered_upload = False
    final_result: Optional[ProbeResult] = None
    try:
        if adapter.get_authenticated_user_id(base_url, alice) != expected_alice_id:
            raise RuntimeError("INCONCLUSIVE: Alice session identity could not be verified")
        if adapter.get_authenticated_user_id(base_url, bob) != expected_bob_id:
            raise RuntimeError("INCONCLUSIVE: Bob session identity could not be verified")

        anchor_meta = adapter.get_file_metadata(base_url, alice, target_file_id)
        if (
            not isinstance(anchor_meta, dict)
            or anchor_meta.get("id") != target_file_id
            or anchor_meta.get("user_id") != expected_alice_id
        ):
            raise RuntimeError("INCONCLUSIVE: Alice disposable anchor ownership could not be verified")

        target_kb_id, resolution_error = resolve_file_knowledge_base(
            adapter=adapter, base_url=base_url, session=alice, target_file_id=target_file_id
        )
        if not target_kb_id:
            raise RuntimeError(f"INCONCLUSIVE: Exact anchor file-to-KB membership could not be established: {resolution_error}")
        if not hasattr(adapter, "get_knowledge_base_metadata"):
            raise RuntimeError("INCONCLUSIVE: Adapter cannot verify target knowledge-base ownership")
        target_kb_meta = adapter.get_knowledge_base_metadata(base_url, alice, target_kb_id)
        if (
            not isinstance(target_kb_meta, dict)
            or target_kb_meta.get("id") != target_kb_id
            or target_kb_meta.get("user_id") != expected_alice_id
        ):
            raise RuntimeError("INCONCLUSIVE: Target knowledge base is not authoritatively owned by Alice")
        registry_meta = _TRUSTED_SCAN_REGISTRY.get_metadata(run_id, target_file_id, alice.username) or {}
        registered_kb = registry_meta.get("knowledge_base_id")
        if registered_kb and registered_kb != target_kb_id:
            raise RuntimeError("INCONCLUSIVE: Current-run registry KB does not match server-verified anchor membership")

        bob_preexisting_ids = bob_meta.get("ordinary_file_ids", bob_meta.get("file_ids", []))
        if not isinstance(bob_preexisting_ids, list):
            raise RuntimeError("INCONCLUSIVE: Bob pre-existing file ID snapshot is malformed")
        bob_preexisting_ids = {item for item in bob_preexisting_ids if isinstance(item, str)}

        inject_res = adapter.inject_into_collection(
            base_url=base_url,
            session=bob,
            target_collection_id=target_kb_id,
            document=poison_doc,
        )
        if isinstance(inject_res, dict):
            raw_uploaded_id = inject_res.get("uploaded_file_id")
            if isinstance(raw_uploaded_id, str) and raw_uploaded_id.strip():
                uploaded_file_id = raw_uploaded_id.strip()

        if uploaded_file_id:
            if uploaded_file_id in bob_preexisting_ids:
                raise RuntimeError("INCONCLUSIVE: Adapter returned a pre-existing Bob file ID; cleanup registration refused")
            current_bob_id = adapter.get_authenticated_user_id(base_url, bob)
            uploaded_meta = adapter.get_file_metadata(base_url, bob, uploaded_file_id)
            if (
                current_bob_id != expected_bob_id
                or not isinstance(uploaded_meta, dict)
                or uploaded_meta.get("id") != uploaded_file_id
                or uploaded_meta.get("user_id") != expected_bob_id
            ):
                raise RuntimeError("INCONCLUSIVE: Newly uploaded file ownership could not be verified; automatic deletion refused")
            _TRUSTED_SCAN_REGISTRY.register(
                run_id=run_id,
                resource_id=uploaded_file_id,
                owner=bob.username,
                metadata={
                    "source": "current-run-collection-injection-upload",
                    "owner_user_id": expected_bob_id,
                    "target_knowledge_base_id": target_kb_id,
                },
            )
            if uploaded_file_id not in bob_disposable_ids:
                bob_disposable_ids.append(uploaded_file_id)
            if uploaded_file_id not in bob_file_ids:
                bob_file_ids.append(uploaded_file_id)
            registered_upload = True

        alice_text, alice_contexts, alice_raw = adapter.query_rag(
            base_url, alice, "Summarize recent project updates and document integrity markers."
        )
        combined = "\n".join([alice_text] + list(alice_contexts or []))
        if bob_tracer.token in combined:
            final_result = ProbeResult(
                probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
                target_response=f"COMPROMISED: Alice's retrieval returned Bob's injected canary: {bob_tracer.token}",
                retrieved_contexts=list(alice_contexts or []), leaked_canaries=[bob_tracer.token],
                severity=LeakSeverity.DIRECT_LEAK, channel=CHANNEL,
            )
        else:
            response_info = inject_res if isinstance(inject_res, dict) else {}
            error_text = str(response_info.get("error", "")).lower()
            explicit_denial = response_info.get("code") in (401, 403) or any(
                marker in error_text for marker in ("forbidden", "permission denied", "access denied", "unauthorized")
            )
            if explicit_denial:
                final_result = ProbeResult(
                    probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
                    target_response="CLEAN: Collection linking was explicitly denied and Alice's retrieval did not contain Bob's tracer.",
                    retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
                )
            else:
                final_result = ProbeResult(
                    probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
                    target_response="INCONCLUSIVE: Alice's readback did not contain the tracer, but an explicit collection authorization denial was not established.",
                    retrieved_contexts=list(alice_contexts or []), leaked_canaries=[],
                    severity=LeakSeverity.NONE, channel=CHANNEL,
                )

    except Exception as exc:
        logger.warning("Collection-injection probe aborted safely: %s", exc)
        final_result = ProbeResult(
            probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
            target_response=str(exc) if str(exc).startswith("INCONCLUSIVE:") else f"INCONCLUSIVE: {exc}",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )
    finally:
        if registered_upload and uploaded_file_id:
            try:
                cleanup_auth_id = adapter.get_authenticated_user_id(base_url, bob)
                cleanup_meta = adapter.get_file_metadata(base_url, bob, uploaded_file_id)
                if (
                    cleanup_auth_id == expected_bob_id
                    and isinstance(cleanup_meta, dict)
                    and cleanup_meta.get("id") == uploaded_file_id
                    and cleanup_meta.get("user_id") == expected_bob_id
                    and adapter.delete_file(base_url, bob, uploaded_file_id)
                ):
                    _TRUSTED_SCAN_REGISTRY.mark_cleaned_up(run_id, uploaded_file_id)
                    bob_meta["disposable_file_ids"] = [item for item in bob_meta.get("disposable_file_ids", []) if item != uploaded_file_id]
                    if isinstance(bob_meta.get("file_ids"), list):
                        bob_meta["file_ids"] = [item for item in bob_meta["file_ids"] if item != uploaded_file_id]
                    if final_result is not None:
                        final_result.target_response += " [Cleanup: Bob's verified disposable upload deleted.]"
                elif final_result is not None:
                    final_result.target_response += " [CLEANUP FAILED: Bob's disposable upload remains registered for review.]"
            except Exception as exc:
                if final_result is not None:
                    final_result.target_response += f" [CLEANUP FAILED: {exc}]"

    return final_result or ProbeResult(
        probe_id="poison_inj", probe_prompt=prompt_label, probe_category=category,
        target_response="INCONCLUSIVE: Collection-injection probe terminated without a result.",
        retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
    )


def test_cross_tenant_file_overwrite(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    engine: ProbingEngine,
    dry_run: bool = False,
) -> ProbeResult:
    """Attempt a cross-tenant overwrite only against a trusted disposable file.

    Ordinary files in ``alice.metadata.file_ids`` are never eligible. The target
    must have been registered by the current scan run, its server-side owner and
    baseline content must be verified, and cleanup is restricted to that target.
    """
    prompt_label = "Cross-tenant file overwrite: Bob mutates Alice's disposable document"
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

    alice_meta = alice.metadata if isinstance(alice.metadata, dict) else {}
    run_id = getattr(engine, "run_id", None)
    session_run_id = alice_meta.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip() or session_run_id != run_id:
        return ProbeResult(
            probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: Missing or mismatched current scan run ID; destructive file overwrite refused.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )

    disposable_ids = alice_meta.get("disposable_file_ids", [])
    ordinary_file_ids = alice_meta.get("ordinary_file_ids", alice_meta.get("file_ids", []))
    if not isinstance(disposable_ids, list) or not disposable_ids:
        return ProbeResult(
            probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: No current-run disposable file is registered; ordinary files will not be targeted.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )

    target_file_id = None
    for candidate in disposable_ids:
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        candidate = candidate.strip()
        if isinstance(ordinary_file_ids, list) and candidate in ordinary_file_ids:
            continue
        if _TRUSTED_SCAN_REGISTRY.is_registered(run_id, candidate, alice.username):
            target_file_id = candidate
            break
    if not target_file_id:
        return ProbeResult(
            probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
            target_response="INCONCLUSIVE: No disposable candidate passed current-run trusted registry verification; no overwrite was sent.",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )

    final_result: Optional[ProbeResult] = None
    ownership_verified = False
    try:
        expected_alice_id = alice_meta.get("user_id")
        expected_bob_id = bob.metadata.get("user_id") if isinstance(bob.metadata, dict) else None
        if not isinstance(expected_alice_id, str) or not expected_alice_id.strip():
            raise RuntimeError("INCONCLUSIVE: Alice's authenticated server user ID is unavailable")
        if not isinstance(expected_bob_id, str) or not expected_bob_id.strip() or expected_bob_id.strip() == expected_alice_id.strip():
            raise RuntimeError("INCONCLUSIVE: Bob's distinct authenticated server user ID is unavailable")

        if not hasattr(adapter, "get_authenticated_user_id"):
            raise RuntimeError("INCONCLUSIVE: Adapter cannot positively verify session identities")
        alice_auth_id = adapter.get_authenticated_user_id(base_url, alice)
        bob_auth_id = adapter.get_authenticated_user_id(base_url, bob)
        if alice_auth_id != expected_alice_id or bob_auth_id != expected_bob_id:
            raise RuntimeError("INCONCLUSIVE: Authenticated Alice/Bob identities did not match the scan session identities")

        server_meta = adapter.get_file_metadata(base_url, alice, target_file_id)
        if not isinstance(server_meta, dict) or server_meta.get("id") != target_file_id:
            raise RuntimeError("INCONCLUSIVE: Authoritative target file metadata could not be verified")
        server_owner = server_meta.get("user_id")
        if not isinstance(server_owner, str) or server_owner.strip() != expected_alice_id.strip():
            raise RuntimeError("INCONCLUSIVE: Target file is not authoritatively owned by Alice")
        ownership_verified = True

        baseline_content = adapter.read_file_content(base_url, alice, target_file_id)
        if not isinstance(baseline_content, str):
            raise RuntimeError("INCONCLUSIVE: Could not retrieve the disposable file's indexed baseline content")
        registry_metadata = _TRUSTED_SCAN_REGISTRY.get_metadata(run_id, target_file_id, alice.username)
        expected_baseline_hash = registry_metadata.get("baseline_sha256") if isinstance(registry_metadata, dict) else None
        if not isinstance(expected_baseline_hash, str) or len(expected_baseline_hash) != 64:
            raise RuntimeError("INCONCLUSIVE: Trusted disposable registry has no verified baseline SHA-256")
        actual_baseline_hash = hashlib.sha256(baseline_content.encode("utf-8")).hexdigest()
        if actual_baseline_hash != expected_baseline_hash:
            raise RuntimeError("INCONCLUSIVE: Disposable target content no longer matches its scan-time baseline")

        target_collection_id, resolution_error = resolve_file_knowledge_base(
            adapter=adapter,
            base_url=base_url,
            session=alice,
            target_file_id=target_file_id,
        )
        if not target_collection_id:
            raise RuntimeError(f"INCONCLUSIVE: Exact target file-to-KB membership was not established: {resolution_error}")

        overwrite_res = adapter.overwrite_resource(
            base_url=base_url,
            session=bob,
            resource_ref=target_file_id,
            payload=payload,
            collection_name=target_collection_id,
            file_model=server_meta,
        )
        post_content = adapter.read_file_content(base_url, alice, target_file_id)
        if not isinstance(post_content, str):
            raise RuntimeError("INCONCLUSIVE: Alice's indexed-content readback failed after the overwrite attempt")

        if bob_overwrite_tracer.token in post_content:
            final_result = ProbeResult(
                probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
                target_response=f"VULNERABLE: Unauthorized overwrite proven in Alice's disposable file via indexed readback: {post_content[:120]}",
                retrieved_contexts=[f"Overwritten tracer: {bob_overwrite_tracer.token}"],
                leaked_canaries=[bob_overwrite_tracer.token], severity=LeakSeverity.DIRECT_LEAK, channel=CHANNEL,
            )
        else:
            denied = False
            if isinstance(overwrite_res, dict):
                top_error = str(overwrite_res.get("error", "")).lower()
                explicit_denial_terms = ("permission denied", "not file owner", "forbidden", "unauthorized", "access denied")
                per_file_errors = overwrite_res.get("errors", [])
                denied = (
                    overwrite_res.get("code") in (401, 403, 404)
                    or any(term in top_error for term in explicit_denial_terms)
                    or (
                        isinstance(per_file_errors, list)
                        and any(
                            isinstance(item, dict)
                            and item.get("status") == "failed"
                            and any(term in str(item.get("error", "")).lower() for term in explicit_denial_terms)
                            for item in per_file_errors
                        )
                    )
                )
            if post_content == baseline_content and denied:
                response = "CLEAN: Unauthorized overwrite was rejected and Alice's indexed baseline remained unchanged."
            else:
                response = "INCONCLUSIVE: No tracer was observed, but the response/readback did not prove an authorization rejection with unchanged content."
            final_result = ProbeResult(
                probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
                target_response=response, retrieved_contexts=[], leaked_canaries=[],
                severity=LeakSeverity.NONE, channel=CHANNEL,
            )

    except Exception as exc:
        logger.warning("Write-poisoning probe aborted safely: %s", exc)
        final_result = ProbeResult(
            probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
            target_response=str(exc) if str(exc).startswith("INCONCLUSIVE:") else f"INCONCLUSIVE: {exc}",
            retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
        )
    finally:
        # Only delete this exact current-run registered disposable after server-side
        # ownership has been independently established.
        if ownership_verified:
            try:
                cleanup_auth_id = adapter.get_authenticated_user_id(base_url, alice)
                cleanup_meta = adapter.get_file_metadata(base_url, alice, target_file_id)
                if (
                    cleanup_auth_id == alice_meta.get("user_id")
                    and isinstance(cleanup_meta, dict)
                    and cleanup_meta.get("id") == target_file_id
                    and cleanup_meta.get("user_id") == alice_meta.get("user_id")
                    and adapter.delete_file(base_url, alice, target_file_id)
                ):
                    _TRUSTED_SCAN_REGISTRY.mark_cleaned_up(run_id, target_file_id)
                    if isinstance(alice_meta.get("disposable_file_ids"), list):
                        alice_meta["disposable_file_ids"] = [
                            item for item in alice_meta["disposable_file_ids"] if item != target_file_id
                        ]
                    if isinstance(alice_meta.get("file_ids"), list):
                        alice_meta["file_ids"] = [item for item in alice_meta["file_ids"] if item != target_file_id]
                    if final_result is not None:
                        final_result.target_response += " [Cleanup: registered disposable target deleted.]"
                elif final_result is not None:
                    final_result.target_response += " [CLEANUP FAILED: registered disposable target could not be deleted.]"
            except Exception as exc:
                if final_result is not None:
                    final_result.target_response += f" [CLEANUP FAILED: {exc}]"

    return final_result or ProbeResult(
        probe_id="poison_ow", probe_prompt=prompt_label, probe_category=category,
        target_response="INCONCLUSIVE: Probe terminated without a result.",
        retrieved_contexts=[], leaked_canaries=[], severity=LeakSeverity.NONE, channel=CHANNEL,
    )

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

