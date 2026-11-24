"""
Neutral knowledge base and file membership resolution module.

Authoritatively resolves the unique knowledge base containing a target file ID
by inspecting server-side candidate knowledge bases and verifying file membership.
Shared across CVE probes (e.g. CVE-2026-28788) and generic scenario probes (e.g. write_poisoning).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import TargetAdapter, UserSession

logger = logging.getLogger("firedamp.probes.knowledge_membership")


def resolve_file_knowledge_base(
    adapter: Any,
    base_url: str,
    session: UserSession,
    target_file_id: str,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Authoritatively resolves the unique knowledge base containing target_file_id.

    Inspects the file membership of accessible knowledge bases to identify the KB
    containing the exact target file ID.

    Rules:
    1. Obtains complete authorized candidate set from adapter.get_accessible_knowledge_bases().
       If enumeration fails or returns None, fails closed with INCONCLUSIVE.
    2. Never select knowledge_ids[0] merely because it exists.
    3. Never select a KB based only on its position in a list.
    4. Distinguishes verified empty KB ([]) from lookup failure / unverified (None).
    5. Truth Table:
       - Target in exactly 1 KB, all candidates fully checked -> Select that KB: (kb_id, None)
       - Target in multiple KBs -> INCONCLUSIVE (ambiguous): (None, reason)
       - Target in 1 KB, another candidate lookup failed (None) -> INCONCLUSIVE (incomplete verification): (None, reason)
       - No target matches, all KBs fully checked -> INCONCLUSIVE (no membership): (None, reason)
       - No target matches, at least 1 KB lookup failed (None) -> INCONCLUSIVE (incomplete verification): (None, reason)
    6. Does not use unverified session metadata to bypass adapter checks or establish file membership.
    7. Does not issue an overwrite request when resolution fails.
    """
    if not target_file_id or not isinstance(target_file_id, str) or not target_file_id.strip():
        return None, "Invalid or missing target_file_id"

    clean_file_id = target_file_id.strip()

    # 1. Authoritatively enumerate candidate knowledge bases
    if not hasattr(adapter, "get_accessible_knowledge_bases"):
        return (
            None,
            "Adapter does not support accessible knowledge base enumeration (get_accessible_knowledge_bases)",
        )

    try:
        candidate_kbs_raw = adapter.get_accessible_knowledge_bases(base_url, session)
    except Exception as exc:
        logger.debug(f"Error enumerating accessible knowledge bases: {exc}")
        return None, f"Incomplete candidate knowledge base enumeration: {exc}"

    if candidate_kbs_raw is None:
        return None, "Incomplete candidate knowledge base enumeration: adapter returned None"

    if not isinstance(candidate_kbs_raw, (list, tuple)):
        return None, f"Malformed candidate knowledge base list returned by adapter: {type(candidate_kbs_raw)}"

    candidate_kbs: List[str] = []
    seen_candidate_ids: set[str] = set()
    for candidate in candidate_kbs_raw:
        if not isinstance(candidate, str) or not candidate.strip():
            return None, "Malformed candidate knowledge base list: every candidate ID must be a non-empty string"
        clean_candidate = candidate.strip()
        if clean_candidate in seen_candidate_ids:
            return None, f"Malformed candidate knowledge base list: duplicate candidate ID '{clean_candidate}'"
        seen_candidate_ids.add(clean_candidate)
        candidate_kbs.append(clean_candidate)

    if not candidate_kbs:
        return (
            None,
            f"Target file '{clean_file_id}' does not belong to any verified knowledge base (0 accessible knowledge bases found)",
        )

    # 2. Check file membership for each candidate KB
    matching_kbs: List[str] = []
    failed_lookups: List[str] = []

    for kb_id in candidate_kbs:
        if not hasattr(adapter, "get_knowledge_base_files"):
            failed_lookups.append(kb_id)
            continue

        try:
            res = adapter.get_knowledge_base_files(base_url, session, kb_id)
        except Exception as exc:
            logger.debug(f"Error querying knowledge base files for {kb_id}: {exc}")
            res = None

        if res is None or not isinstance(res, list):
            failed_lookups.append(kb_id)
            continue

        verified_files: List[str] = []
        seen_file_ids: set[str] = set()
        malformed_membership = False
        for file_id in res:
            if not isinstance(file_id, str) or not file_id.strip():
                malformed_membership = True
                break
            clean_id = file_id.strip()
            if clean_id in seen_file_ids:
                malformed_membership = True
                break
            seen_file_ids.add(clean_id)
            verified_files.append(clean_id)
        if malformed_membership:
            failed_lookups.append(kb_id)
            continue
        if clean_file_id in verified_files:
            matching_kbs.append(kb_id)

    # 3. Apply Truth Table
    if failed_lookups:
        return (
            None,
            f"Incomplete verification: failed to verify file membership for knowledge base(s) {failed_lookups}",
        )

    if len(matching_kbs) > 1:
        return (
            None,
            f"Ambiguous knowledge base membership: target file '{clean_file_id}' belongs to multiple knowledge bases ({matching_kbs})",
        )

    if len(matching_kbs) == 1:
        return matching_kbs[0], None

    return (
        None,
        f"Target file '{clean_file_id}' does not belong to any verified knowledge base ({candidate_kbs})",
    )
