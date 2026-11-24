#!/usr/bin/env python3
"""
Firedamp CVE-2026-28788 Probe Execution Script.
Executes Firedamp's actual CVE-2026-28788 behavioral regression probe
against a live target Open WebUI instance using OpenWebUIAdapter.
"""

import argparse
import json
import logging
import os
import sys
import uuid
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict

# Ensure repository root is on sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
LAB_DIR = SCRIPT_DIR.parent
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from adapters.base import UserSession
from adapters.openwebui import OpenWebUIAdapter
from core.engine import LeakSeverity, ProbingEngine
from probes.cves import cve_2026_28788
from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY
from lab_safety import validate_setup_file, verify_setup_target


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("firedamp.lab.probe")


def _http_request_adapter(url: str, method: str = "GET", headers=None, data=None, timeout: int = 15):
    """Adapt the lab safety helper's call signature to urllib.request."""
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute Firedamp CVE-2026-28788 probe")
    parser.add_argument("--setup-file", required=True, help="Path to setup JSON from setup_lab.py")
    parser.add_argument("--output", default=None, help="Path to output probe result JSON")
    parser.add_argument(
        "--allow-non-loopback", action="store_true",
        help="DANGEROUS: explicitly permit a non-loopback lab target",
    )
    args = parser.parse_args()

    try:
        setup_data = validate_setup_file(args.setup_file, allow_non_loopback=args.allow_non_loopback)
        preflight = verify_setup_target(
            setup_data,
            request_fn=_http_request_adapter,
            allow_non_loopback=args.allow_non_loopback,
            require_baseline=True,
        )
    except Exception as exc:
        logger.error("Lab preflight failed; no disposable registration or probe request was made: %s", exc)
        sys.exit(2)

    base_url = setup_data["base_url"]
    alice_token = setup_data["alice"]["token"]
    alice_user_id = setup_data["alice"]["user_id"]
    bob_token = setup_data["bob"]["token"]
    bob_user_id = setup_data["bob"]["user_id"]
    kb_id = setup_data["knowledge_base"]["id"]
    file_id = setup_data["disposable_file"]["id"]

    run_id = f"firedamp-lab-run-{uuid.uuid4().hex[:12]}"
    logger.info(f"Initialized scan run ID: {run_id}")

    # Register only after live URL/version, user identities, server-side owner,
    # KB membership, Bob read access, and pristine baseline were independently verified.
    _TRUSTED_SCAN_REGISTRY.register(
        run_id=run_id,
        resource_id=file_id,
        owner="alice",
        metadata={
            "source": "validated-cve-lab-setup",
            "expected_version": preflight["version"],
            "baseline_sha256": preflight["content_sha256"],
        },
    )
    logger.info(f"Registered disposable resource {file_id} in scan registry.")

    # Configure Personas
    alice = UserSession(
        username="alice",
        role="owner",
        token=alice_token,
        headers={"Authorization": f"Bearer {alice_token}"},
        metadata={
            "user_id": alice_user_id,
            "run_id": run_id,
            "disposable_file_ids": [file_id],
            "ordinary_file_ids": [],
            "knowledge_ids": [kb_id],
        },
    )

    bob = UserSession(
        username="bob",
        role="attacker",
        token=bob_token,
        headers={"Authorization": f"Bearer {bob_token}"},
        metadata={
            "user_id": bob_user_id,
            "run_id": run_id,
            "knowledge_ids": [kb_id],
        },
    )

    engine = ProbingEngine(run_id=run_id)

    adapter = OpenWebUIAdapter()

    logger.info(f"Executing CVE-2026-28788 probe against {base_url}...")
    result = cve_2026_28788.run(
        adapter=adapter,
        base_url=base_url,
        alice=alice,
        bob=bob,
        planted_canaries=[],
        engine=engine,
        dry_run=False,
    )

    probe_output = {
        "cve_id": cve_2026_28788.CVE_ID,
        "run_id": run_id,
        "target_url": base_url,
        "target_file_id": file_id,
        "severity": result.severity.value if hasattr(result.severity, "value") else str(result.severity),
        "target_response": result.target_response,
        "leaked_canaries": [str(c) for c in result.leaked_canaries],
        "is_vulnerable": result.severity in (LeakSeverity.DIRECT_LEAK, LeakSeverity.CRITICAL),
        "is_clean": result.severity == LeakSeverity.NONE and "CLEAN" in result.target_response,
        "is_inconclusive": "INCONCLUSIVE" in result.target_response or (result.severity == LeakSeverity.NONE and "CLEAN" not in result.target_response),
    }

    logger.info(f"Probe Result:")
    logger.info(f"  Severity: {probe_output['severity']}")
    logger.info(f"  Response: {probe_output['target_response']}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(probe_output, indent=2), encoding="utf-8")
        logger.info(f"Probe report saved to {out_path}")


if __name__ == "__main__":
    main()
