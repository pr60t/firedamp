"""Safety checks shared by the CVE-2026-28788 lab scripts.

The default lab boundary is strictly loopback-only and restricted to the
pinned version/port pairs from compose.yaml. Non-loopback use requires an
explicit CLI opt-in on every script invocation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

LAB_NAME = "firedamp-cve-2026-28788"
LAB_SCHEMA_VERSION = 1
LOCAL_TARGETS = {13085: "0.8.5", 13086: "0.8.6"}
SUPPORTED_VERSIONS = {"0.8.5", "0.8.6"}
PAGE_SIZE = 30
MAX_PAGES = 100


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_target_url(
    base_url: str,
    *,
    allow_non_loopback: bool = False,
    expected_version: Optional[str] = None,
) -> str:
    """Validate URL scope and return the expected Open WebUI version."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("Target URL is required")
    parsed = urlsplit(base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Target URL must not contain userinfo, query parameters, or fragments")
    if parsed.path not in ("", "/"):
        raise ValueError("Target URL must be an origin only; paths are not allowed")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid target URL port: {exc}") from exc

    local = _is_loopback(parsed.hostname)
    if not local and not allow_non_loopback:
        raise ValueError(
            "Non-loopback target refused. Use --allow-non-loopback explicitly only for an authorized isolated test target."
        )

    if local:
        if port not in LOCAL_TARGETS:
            raise ValueError("Loopback lab targets must use port 13085 (Open WebUI 0.8.5) or 13086 (0.8.6)")
        port_version = LOCAL_TARGETS[port]
        if expected_version and expected_version != port_version:
            raise ValueError(
                f"Setup metadata version {expected_version} does not match loopback port {port} ({port_version})"
            )
        return port_version

    if not allow_non_loopback:
        raise ValueError("Non-loopback target requires explicit opt-in")
    if expected_version not in SUPPORTED_VERSIONS:
        raise ValueError("Non-loopback targets require an explicit expected version of 0.8.5 or 0.8.6")
    return expected_version


def verify_target_version(
    base_url: str,
    request_fn: Callable[..., Dict[str, Any]],
    *,
    allow_non_loopback: bool = False,
    expected_version: Optional[str] = None,
) -> str:
    expected = validate_target_url(
        base_url,
        allow_non_loopback=allow_non_loopback,
        expected_version=expected_version,
    )
    response = request_fn(f"{base_url.rstrip('/')}/api/version", method="GET")
    data = response.get("data") if isinstance(response, dict) else None
    if response.get("status_code") != 200 or not isinstance(data, dict):
        raise RuntimeError("Unable to verify target /api/version; refusing lab operation")
    actual = data.get("version")
    if actual != expected:
        raise RuntimeError(f"Target version mismatch: expected {expected}, received {actual!r}")
    return expected


def _require_success(response: Dict[str, Any], description: str) -> Any:
    if not isinstance(response, dict) or response.get("status_code") != 200 or response.get("error"):
        code = response.get("status_code") if isinstance(response, dict) else "invalid"
        raise RuntimeError(f"{description} failed (HTTP/status {code})")
    return response.get("data")


def fetch_complete_file_ids(
    base_url: str,
    kb_id: str,
    headers: Dict[str, str],
    request_fn: Callable[..., Dict[str, Any]],
) -> List[str]:
    """Fetch all KB file IDs, rejecting incomplete, malformed, or duplicate pages."""
    if not isinstance(kb_id, str) or not kb_id.strip():
        raise ValueError("A non-empty knowledge-base ID is required")
    collected: List[str] = []
    seen: set[str] = set()
    total: Optional[int] = None
    for page in range(1, MAX_PAGES + 1):
        response = request_fn(
            f"{base_url.rstrip('/')}/api/v1/knowledge/{kb_id.strip()}/files?page={page}",
            method="GET",
            headers=headers,
        )
        data = _require_success(response, f"Knowledge-base membership page {page}")
        if not isinstance(data, dict):
            raise RuntimeError(f"Malformed knowledge-base membership page {page}")
        raw_total = data.get("total")
        items = data.get("items")
        if isinstance(raw_total, bool) or not isinstance(raw_total, int) or raw_total < 0:
            raise RuntimeError(f"Invalid membership total on page {page}")
        if not isinstance(items, list):
            raise RuntimeError(f"Invalid membership items on page {page}")
        if total is None:
            total = raw_total
            if total > PAGE_SIZE * MAX_PAGES:
                raise RuntimeError("Knowledge-base membership exceeds bounded pagination capacity")
            if total == 0:
                if items:
                    raise RuntimeError("Membership reports total=0 with non-empty items")
                return []
        elif raw_total != total:
            raise RuntimeError("Knowledge-base membership total changed during pagination")

        if not items and len(collected) < total:
            raise RuntimeError(f"Knowledge-base membership page {page} was empty before all records were retrieved")
        for item in items:
            if not isinstance(item, dict):
                raise RuntimeError(f"Malformed membership item on page {page}")
            file_id = item.get("id")
            if not file_id:
                nested = item.get("file")
                file_id = nested.get("id") if isinstance(nested, dict) else item.get("file_id")
            if not isinstance(file_id, str) or not file_id.strip():
                raise RuntimeError(f"Missing or invalid file ID on membership page {page}")
            file_id = file_id.strip()
            if file_id in seen:
                raise RuntimeError(f"Duplicate file ID returned during membership pagination: {file_id}")
            seen.add(file_id)
            collected.append(file_id)

        if len(collected) == total:
            return collected
        if len(collected) > total:
            raise RuntimeError("Knowledge-base membership returned more items than total")
    raise RuntimeError("Knowledge-base membership exceeded maximum page count")


def validate_setup_file(
    setup_path: str | Path,
    *,
    allow_non_loopback: bool = False,
) -> Dict[str, Any]:
    """Load a restrictive-mode setup file and validate its lab identity envelope."""
    path = Path(setup_path)
    if not path.is_file():
        raise FileNotFoundError(f"Setup file not found: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(f"Setup file must not be group/world accessible (current mode {mode:04o})")
    try:
        setup = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("Setup file is not valid JSON") from exc
    if not isinstance(setup, dict):
        raise ValueError("Setup file root must be a JSON object")
    identity = setup.get("lab_identity")
    if not isinstance(identity, dict) or identity.get("name") != LAB_NAME or identity.get("schema_version") != LAB_SCHEMA_VERSION:
        raise ValueError("Setup file lacks the required Firedamp CVE lab identity marker; regenerate it with setup_lab.py")
    expected = identity.get("expected_version")
    if expected not in SUPPORTED_VERSIONS:
        raise ValueError("Setup file has an unsupported or missing expected target version")
    base_url = setup.get("base_url")
    validate_target_url(base_url, allow_non_loopback=allow_non_loopback, expected_version=expected)

    alice = setup.get("alice")
    bob = setup.get("bob")
    kb = setup.get("knowledge_base")
    disposable = setup.get("disposable_file")
    if not all(isinstance(value, dict) for value in (alice, bob, kb, disposable)):
        raise ValueError("Setup file is missing Alice, Bob, knowledge_base, or disposable_file metadata")
    required = [
        alice.get("token"), alice.get("user_id"), bob.get("token"), bob.get("user_id"),
        kb.get("id"), disposable.get("id"), disposable.get("filename"),
        disposable.get("original_content_sha256"),
    ]
    if any(not isinstance(value, str) or not value.strip() for value in required):
        raise ValueError("Setup file contains missing or invalid identity/resource fields")
    if alice["user_id"] == bob["user_id"] or alice["token"] == bob["token"]:
        raise ValueError("Alice and Bob must have distinct server identities and credentials")
    if disposable["filename"] != "alice_disposable.txt":
        raise ValueError("Target file is not the expected Firedamp disposable fixture")
    digest = disposable["original_content_sha256"]
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
        raise ValueError("Setup file contains an invalid baseline SHA-256")
    return setup


def verify_setup_target(
    setup: Dict[str, Any],
    request_fn: Callable[..., Dict[str, Any]],
    *,
    allow_non_loopback: bool = False,
    require_baseline: bool = True,
) -> Dict[str, Any]:
    """Independently verify version, authenticated identities, owner, file and KB membership."""
    base_url = setup["base_url"].rstrip("/")
    expected_version = setup["lab_identity"]["expected_version"]
    actual_version = verify_target_version(
        base_url, request_fn, allow_non_loopback=allow_non_loopback, expected_version=expected_version
    )
    alice = setup["alice"]
    bob = setup["bob"]
    kb = setup["knowledge_base"]
    disposable = setup["disposable_file"]
    alice_headers = {"Authorization": f"Bearer {alice['token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['token']}"}

    for name, identity, headers in (("Alice", alice, alice_headers), ("Bob", bob, bob_headers)):
        auth_data = _require_success(
            request_fn(f"{base_url}/api/v1/auths/", method="GET", headers=headers),
            f"{name} session identity verification",
        )
        if not isinstance(auth_data, dict) or auth_data.get("id") != identity["user_id"] or auth_data.get("role") != "user":
            raise RuntimeError(f"{name} server identity/role does not match the setup file")

    kb_metadata = _require_success(
        request_fn(f"{base_url}/api/v1/knowledge/{kb['id']}", method="GET", headers=alice_headers),
        "Alice target knowledge-base ownership verification",
    )
    if not isinstance(kb_metadata, dict) or kb_metadata.get("id") != kb["id"] or kb_metadata.get("user_id") != alice["user_id"]:
        raise RuntimeError("Declared lab knowledge base is not authoritatively owned by Alice")

    file_id = disposable["id"]
    metadata = _require_success(
        request_fn(f"{base_url}/api/v1/files/{file_id}", method="GET", headers=alice_headers),
        "Alice target file metadata verification",
    )
    if not isinstance(metadata, dict) or metadata.get("id") != file_id or metadata.get("user_id") != alice["user_id"]:
        raise RuntimeError("Target file ID/owner does not match the Alice-owned disposable fixture")
    if metadata.get("filename") != disposable["filename"]:
        raise RuntimeError("Target file filename does not match the expected disposable fixture")

    # Confirm Bob has the intended read path but do not attempt a write to test ACLs.
    bob_file_metadata = _require_success(
        request_fn(f"{base_url}/api/v1/files/{file_id}", method="GET", headers=bob_headers),
        "Bob read-only target metadata access",
    )
    if not isinstance(bob_file_metadata, dict) or bob_file_metadata.get("id") != file_id:
        raise RuntimeError("Bob cannot verify read access to the shared disposable file")

    file_ids = fetch_complete_file_ids(base_url, kb["id"], alice_headers, request_fn)
    if file_id not in file_ids:
        raise RuntimeError("Disposable target file is not linked to the declared knowledge base")

    content_response = request_fn(
        f"{base_url}/api/v1/files/{file_id}/data/content", method="GET", headers=alice_headers
    )
    content_data = _require_success(content_response, "Alice indexed content readback")
    content = content_data.get("content") if isinstance(content_data, dict) else content_data
    if not isinstance(content, str):
        raise RuntimeError("Alice indexed content readback did not contain a string content field")
    actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if require_baseline and actual_hash != disposable["original_content_sha256"]:
        raise RuntimeError("Disposable target content does not match the setup baseline; refusing probe")
    expected_length = disposable.get("original_content_length")
    if require_baseline and expected_length is not None and len(content) != expected_length:
        raise RuntimeError("Disposable target content length does not match the setup baseline")

    return {
        "version": actual_version,
        "file_id": file_id,
        "kb_id": kb["id"],
        "alice_user_id": alice["user_id"],
        "bob_user_id": bob["user_id"],
        "file_ids_in_kb": file_ids,
        "content_sha256": actual_hash,
        "baseline_verified": actual_hash == disposable["original_content_sha256"],
    }
