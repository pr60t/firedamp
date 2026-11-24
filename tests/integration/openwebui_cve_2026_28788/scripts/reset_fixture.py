#!/usr/bin/env python3
"""Restore the disposable CVE-2026-28788 fixture without overstating cleanup.

The reset verifies the lab target, identities, ownership, complete KB membership,
and original indexed-content hash before and after restoration. The pinned public
retrieval endpoint is nearest-neighbor/top-k, not an exhaustive vector-store
inspection, so this script deliberately reports vector cleanup as UNVERIFIED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from lab_safety import fetch_complete_file_ids, validate_setup_file, verify_setup_target


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return {"status_code": response.status, "data": parsed, "error": None}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return {"status_code": exc.code, "data": parsed, "error": str(exc)}
    except Exception as exc:
        return {"status_code": 0, "data": None, "error": str(exc)}


def _require_http_200(response: Dict[str, Any], operation: str) -> Any:
    if not isinstance(response, dict) or response.get("status_code") != 200 or response.get("error"):
        status = response.get("status_code", "invalid") if isinstance(response, dict) else "invalid"
        raise RuntimeError(f"{operation} failed (HTTP/status {status}); reset aborted")
    return response.get("data")


def _extract_content(response: Dict[str, Any], operation: str) -> str:
    data = _require_http_200(response, operation)
    if isinstance(data, dict):
        content = data.get("content")
    else:
        content = data
    if not isinstance(content, str):
        raise RuntimeError(f"{operation} did not return a string content value")
    return content


def _check_positive_vector_marker(query_response: Dict[str, Any], file_id: str) -> str:
    """A positive exact-file marker is evidence of failure; absence is not proof."""
    if not isinstance(query_response, dict) or query_response.get("status_code") != 200 or query_response.get("error"):
        return "QUERY_FAILED_NOT_EXHAUSTIVE"
    data = query_response.get("data")
    if not isinstance(data, dict):
        return "MALFORMED_QUERY_NOT_EXHAUSTIVE"
    documents = data.get("documents")
    metadatas = data.get("metadatas")
    if not isinstance(documents, list) or not isinstance(metadatas, list):
        return "QUERY_RESPONSE_MISSING_DOCUMENT_METADATA_NOT_EXHAUSTIVE"
    docs = documents[0] if documents and isinstance(documents[0], list) else []
    metas = metadatas[0] if metadatas and isinstance(metadatas[0], list) else []
    for index, metadata in enumerate(metas):
        if not isinstance(metadata, dict) or metadata.get("file_id") != file_id:
            continue
        text = docs[index] if index < len(docs) else ""
        if isinstance(text, str) and ("EXPLOIT_TRACER" in text or "CONFIRMED" in text):
            raise RuntimeError(
                f"Vector cleanup failure: the top-k diagnostic still returned an attacker marker for target file {file_id}"
            )
    return "NO_MARKER_IN_TOP_K_NOT_EXHAUSTIVE"


def reset_fixture(
    setup_file_path: str,
    fixtures_dir: Optional[Path] = None,
    *,
    allow_non_loopback: bool = False,
) -> Dict[str, Any]:
    setup_data = validate_setup_file(setup_file_path, allow_non_loopback=allow_non_loopback)
    # Verify target version, both authenticated users, victim ownership, Bob's intended
    # read access, exact fixture filename, complete KB membership, and indexed content
    # before performing any reset mutation. Baseline mismatch is allowed here because
    # restoring a modified baseline is the purpose of this command.
    preflight = verify_setup_target(
        setup_data,
        http_request,
        allow_non_loopback=allow_non_loopback,
        require_baseline=False,
    )

    base_url = setup_data["base_url"].rstrip("/")
    file_id = setup_data["disposable_file"]["id"]
    alice_token = setup_data["alice"]["token"]
    alice_user_id = setup_data["alice"]["user_id"]
    kb_id = setup_data["knowledge_base"]["id"]
    expected_hash = setup_data["disposable_file"]["original_content_sha256"]
    alice_headers = {
        "Authorization": f"Bearer {alice_token}",
        "Content-Type": "application/json",
    }

    if fixtures_dir is None:
        fixtures_dir = Path(__file__).resolve().parent.parent / "fixtures"
    original_file_path = fixtures_dir / "alice_original.txt"
    if not original_file_path.is_file():
        raise FileNotFoundError(f"Original fixture file not found: {original_file_path}")

    original_content = original_file_path.read_text(encoding="utf-8")
    original_hash = hashlib.sha256(original_content.encode("utf-8")).hexdigest()
    if original_hash != expected_hash:
        raise ValueError(
            f"Fixture mismatch: setup baseline {expected_hash} does not match alice_original.txt ({original_hash})"
        )

    expected_length = setup_data["disposable_file"].get("original_content_length")
    if expected_length is not None and len(original_content) != expected_length:
        raise ValueError("Fixture length does not match setup-file baseline")

    print(f"Resetting verified disposable fixture at {base_url} (File ID: {file_id})...")

    # Capture the complete pre-reset membership set; any pagination failure aborts
    # before vector removal, relinking, or content mutation.
    before_file_ids = fetch_complete_file_ids(base_url, kb_id, alice_headers, http_request)
    if file_id not in before_file_ids:
        raise RuntimeError("Target disposable file is not currently linked to its declared KB; reset aborted")
    other_file_ids = set(before_file_ids) - {file_id}
    print(f"  ✓ Complete pre-reset KB membership verified ({len(before_file_ids)} files).")

    # Use the documented targeted removal operation. A failed/ambiguous response is
    # not treated as successful cleanup and aborts before restoration proceeds.
    print(f"  Step 1: Request targeted vector removal for file {file_id}...")
    remove_response = http_request(
        f"{base_url}/api/v1/knowledge/{kb_id}/file/remove?delete_file=false",
        method="POST",
        headers=alice_headers,
        data=json.dumps({"file_id": file_id}).encode("utf-8"),
    )
    _require_http_200(remove_response, "Targeted vector removal request")

    add_response = http_request(
        f"{base_url}/api/v1/knowledge/{kb_id}/file/add",
        method="POST",
        headers=alice_headers,
        data=json.dumps({"file_id": file_id}).encode("utf-8"),
    )
    _require_http_200(add_response, "Target file relink")

    print(f"  Step 2: Restore indexed file content for {file_id}...")
    update_response = http_request(
        f"{base_url}/api/v1/files/{file_id}/data/content/update",
        method="POST",
        headers=alice_headers,
        data=json.dumps({"content": original_content}).encode("utf-8"),
    )
    _require_http_200(update_response, "Owner content restoration")

    readback_content = _extract_content(
        http_request(
            f"{base_url}/api/v1/files/{file_id}/data/content",
            method="GET",
            headers=alice_headers,
        ),
        "Post-reset indexed content readback",
    )
    restored_hash = hashlib.sha256(readback_content.encode("utf-8")).hexdigest()
    if restored_hash != original_hash:
        raise RuntimeError(
            f"Restoration integrity check failed: readback hash {restored_hash} != original {original_hash}"
        )
    if len(readback_content) != len(original_content):
        raise RuntimeError("Restoration length check failed")

    metadata = _require_http_200(
        http_request(
            f"{base_url}/api/v1/files/{file_id}",
            method="GET",
            headers=alice_headers,
        ),
        "Post-reset file ownership verification",
    )
    if not isinstance(metadata, dict) or metadata.get("id") != file_id or metadata.get("user_id") != alice_user_id:
        raise RuntimeError("Ownership mismatch after reset")

    after_file_ids = fetch_complete_file_ids(base_url, kb_id, alice_headers, http_request)
    after_set = set(after_file_ids)
    if file_id not in after_set:
        raise RuntimeError("Target file is missing from the KB after reset")
    missing_other = other_file_ids - after_set
    if missing_other:
        raise RuntimeError(f"Preservation failure: non-target KB files disappeared: {sorted(missing_other)}")

    # A nearest-neighbor top-k query is retained only as a positive diagnostic. It
    # cannot prove absence of all vectors, so verified_vector_cleanup stays False.
    query_response = http_request(
        f"{base_url}/api/v1/retrieval/query/collection",
        method="POST",
        headers=alice_headers,
        data=json.dumps({
            "collection_names": [kb_id],
            "query": "EXPLOIT_TRACER_CVE_2026_28788 CONFIRMED ATTACKER",
            "k": 10,
        }).encode("utf-8"),
    )
    positive_query_observation = _check_positive_vector_marker(query_response, file_id)

    return {
        "status": "RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED",
        "file_id": file_id,
        "kb_id": kb_id,
        "target_version": preflight["version"],
        "owner_user_id": metadata["user_id"],
        "content_length": len(readback_content),
        "sha256": restored_hash,
        "verified_owner": True,
        "verified_hash": True,
        "verified_kb_membership": True,
        "preserved_other_file_count": len(other_file_ids),
        "vector_removal_request_accepted": True,
        "vector_cleanup_verification": positive_query_observation,
        "verified_vector_cleanup": False,
        "vector_cleanup_note": (
            "The pinned public retrieval query is nearest-neighbor/top-k and cannot exhaustively prove vector absence. "
            "The targeted removal request was accepted, but exhaustive vector cleanup remains unverified."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset CVE-2026-28788 disposable Alice fixture")
    parser.add_argument("--setup-file", required=True, help="Validated setup JSON from setup_lab.py")
    parser.add_argument(
        "--allow-non-loopback", action="store_true",
        help="DANGEROUS: explicitly permit a non-loopback lab target",
    )
    args = parser.parse_args()

    if args.allow_non_loopback:
        print("WARNING: NON-LOOPBACK DESTRUCTIVE FIXTURE RESET ENABLED", file=sys.stderr)

    try:
        result = reset_fixture(args.setup_file, allow_non_loopback=args.allow_non_loopback)
        print(json.dumps(result, indent=2))
        print("WARNING: content and KB membership restored; vector absence is NOT exhaustively verified.", file=sys.stderr)
        # Non-zero is intentional so automation cannot mistake the partial verification
        # contract for a fully restored pristine vector fixture.
        sys.exit(2)
    except Exception as exc:
        print(f"✗ Reset failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
