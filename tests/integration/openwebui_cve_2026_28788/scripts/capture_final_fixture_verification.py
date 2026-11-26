#!/usr/bin/env python3
"""Capture independent live read-only verification for both CVE-2026-28788 lab targets.

Uses validate_setup_file() and verify_setup_target(..., require_baseline=True)
to independently verify Open WebUI v0.8.5 and v0.8.6 target versions, identities,
ownership, KB membership, and original indexed-content baseline integrity without
sending any destructive requests or claiming exhaustive vector cleanup.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lab_safety import validate_setup_file, verify_setup_target

EXPECTED_LOOPBACK_URLS = {
    "0.8.5": "http://127.0.0.1:13085",
    "0.8.6": "http://127.0.0.1:13086",
}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject all HTTP redirects to prevent Bearer token forwarding across origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP redirect refused by read-only verification client ({code} -> {newurl})",
            headers,
            fp,
        )


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    if not isinstance(method, str) or method.strip().upper() != "GET":
        raise ValueError(
            f"Refusing non-GET request ({method!r}) in read-only fixture verification script"
        )
    if data is not None:
        raise ValueError(
            "Refusing HTTP GET request with a request body in read-only fixture verification script"
        )
    req = urllib.request.Request(url, data=None, method="GET")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as response:
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


def _secure_open_write_0600(target_path: Path | str, *, create_dirs: bool = True) -> int:
    """
    Open/create a file with 0600 permissions using directory-descriptor traversal with
    O_DIRECTORY and O_NOFOLLOW, creating the final file relative to the verified directory
    descriptor to prevent TOCTOU symlink races and directory traversal attacks.
    """
    abs_path = os.path.abspath(os.fspath(target_path))
    parts: list[str] = []
    head = abs_path
    while True:
        head, tail = os.path.split(head)
        if tail:
            parts.append(tail)
        else:
            break
    parts.reverse()
    dir_parts = parts[:-1]
    filename = parts[-1]

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    current_fd = os.open("/", dir_flags)
    try:
        for comp in dir_parts:
            try:
                next_fd = os.open(comp, dir_flags, dir_fd=current_fd)
            except FileNotFoundError:
                if create_dirs:
                    os.mkdir(comp, mode=0o700, dir_fd=current_fd)
                    next_fd = os.open(comp, dir_flags, dir_fd=current_fd)
                else:
                    raise
            except OSError as err:
                raise ValueError(
                    f"Refusing to write through symlinked parent directory component: {comp} ({err})"
                ) from err
            os.close(current_fd)
            current_fd = next_fd

        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            file_fd = os.open(filename, file_flags, 0o600, dir_fd=current_fd)
        except OSError as err:
            raise ValueError(
                f"Refusing to write to pre-existing symlink output path: {filename} ({err})"
            ) from err
        try:
            os.fchmod(file_fd, 0o600)
        except Exception:
            os.close(file_fd)
            raise
        return file_fd
    finally:
        os.close(current_fd)


def _write_secure_json(data: Dict[str, Any], output_path: str | Path) -> None:
    out_path = Path(os.path.abspath(os.fspath(output_path)))
    if out_path.is_symlink():
        raise ValueError(f"Refusing to write to pre-existing symlink output path: {out_path}")
    for parent in out_path.parents:
        if parent.is_symlink():
            raise ValueError(f"Refusing to write through symlinked parent directory component: {parent}")
    fd = _secure_open_write_0600(out_path, create_dirs=True)
    serialized = json.dumps(data, indent=2) + "\n"
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(serialized)


def _verify_single_target(
    setup_path: str | Path,
    expected_version: str,
    *,
    allow_non_loopback: bool = False,
) -> Dict[str, Any]:
    setup = validate_setup_file(setup_path, allow_non_loopback=allow_non_loopback)
    declared_version = setup["lab_identity"]["expected_version"]
    if declared_version != expected_version:
        raise ValueError(
            f"Setup file {setup_path} expected_version is {declared_version!r}, expected {expected_version!r}"
        )

    normalized_url = setup["base_url"].rstrip("/")
    expected_loopback = EXPECTED_LOOPBACK_URLS[expected_version]
    if not allow_non_loopback and normalized_url != expected_loopback:
        raise ValueError(
            f"Setup file {setup_path} target_url must be '{expected_loopback}' for Open WebUI {expected_version}, "
            f"got {normalized_url!r}"
        )

    disposable = setup["disposable_file"]
    declared_length = disposable.get("original_content_length")
    if type(declared_length) is not int or declared_length <= 0:
        raise ValueError(
            f"Setup file {setup_path} is missing a valid positive integer disposable_file.original_content_length"
        )

    verified = verify_setup_target(
        setup,
        http_request,
        allow_non_loopback=allow_non_loopback,
        require_baseline=True,
    )

    if verified.get("version") != expected_version:
        raise RuntimeError(
            f"Verified version {verified.get('version')!r} did not match expected {expected_version!r}"
        )
    if verified.get("baseline_verified") is not True:
        raise RuntimeError(f"Baseline verification failed for target Open WebUI {expected_version}")
    if verified.get("content_sha256") != disposable["original_content_sha256"]:
        raise RuntimeError(
            f"Verified readback SHA-256 did not match setup baseline for Open WebUI {expected_version}"
        )

    actual_content_length = verified.get("content_length")
    if type(actual_content_length) is not int or actual_content_length <= 0:
        raise RuntimeError(
            f"Verified readback content_length is missing or invalid for Open WebUI {expected_version}: {actual_content_length!r}"
        )
    if actual_content_length != declared_length:
        raise RuntimeError(
            f"Actual readback content length ({actual_content_length}) does not match setup "
            f"original_content_length ({declared_length}) for Open WebUI {expected_version}"
        )

    file_ids_in_kb = verified.get("file_ids_in_kb")
    if not isinstance(file_ids_in_kb, list) or verified.get("file_id") not in file_ids_in_kb:
        raise RuntimeError(
            f"Target disposable file is not a verified member of Alice's KB on {expected_version}"
        )

    # Record only non-secret verification facts without tokens, passwords, or private UUIDs.
    # Note: identities_and_read_metadata_verified records metadata access only (GET /api/v1/files/{file_id});
    # it does not test or claim permission to read file content, and write permissions are not tested.
    return {
        "expected_version": expected_version,
        "verified_version": verified["version"],
        "target_url": normalized_url,
        "baseline_verified": True,
        "original_sha256": verified["content_sha256"],
        "content_length": actual_content_length,
        "target_in_alice_kb": True,
        "kb_file_count": len(file_ids_in_kb),
        "identities_and_read_metadata_verified": True,
    }


def capture_final_fixture_verification(
    setup_v085_path: str | Path,
    setup_v086_path: str | Path,
    output_path: Optional[str | Path] = None,
    *,
    allow_non_loopback: bool = False,
) -> Dict[str, Any]:
    """Verify both pinned Open WebUI targets read-only and optionally write 0600 JSON output."""
    v085_result = _verify_single_target(
        setup_v085_path, "0.8.5", allow_non_loopback=allow_non_loopback
    )
    v086_result = _verify_single_target(
        setup_v086_path, "0.8.6", allow_non_loopback=allow_non_loopback
    )

    if v085_result["original_sha256"] != v086_result["original_sha256"]:
        raise RuntimeError(
            "Baseline SHA-256 mismatch between v0.8.5 and v0.8.6 final fixture verifications"
        )
    if v085_result["content_length"] != v086_result["content_length"]:
        raise RuntimeError(
            "Baseline content length mismatch between v0.8.5 and v0.8.6 final fixture verifications"
        )

    report: Dict[str, Any] = {
        "verification_mode": "live_read_only_verification",
        "live_execution": True,
        "read_only": True,
        "verified_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vector_cleanup_verified": False,
        "vector_cleanup_note": (
            "Independent read-only fixture verification checks server version, user identities, "
            "ownership, complete KB membership, and indexed content baseline only; exhaustive "
            "vector cleanup is not claimed or verified by this check."
        ),
        "targets": {
            "v0.8.5": v085_result,
            "v0.8.6": v086_result,
        },
    }

    if output_path is not None:
        _write_secure_json(report, output_path)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture independent live read-only verification for Open WebUI v0.8.5 and v0.8.6 lab targets"
    )
    parser.add_argument(
        "--setup-v085",
        required=True,
        help="Path to protected setup JSON for Open WebUI v0.8.5",
    )
    parser.add_argument(
        "--setup-v086",
        required=True,
        help="Path to protected setup JSON for Open WebUI v0.8.6",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON path (written with restrictive 0600 permissions)",
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Explicitly permit non-loopback authorized lab targets",
    )
    args = parser.parse_args()

    try:
        report = capture_final_fixture_verification(
            args.setup_v085,
            args.setup_v086,
            args.output,
            allow_non_loopback=args.allow_non_loopback,
        )
        print(json.dumps(report, indent=2))
        print(f"✓ Live read-only fixture verification captured at: {args.output} (mode: 0600)")
    except Exception as exc:
        print(f"✗ Final fixture verification failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
