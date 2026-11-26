#!/usr/bin/env python3
"""
Unit tests for CVE-2026-28788 Evidence Sanitization and Bundling Pipeline.
"""

import copy
import hashlib
import io
import json
import os
import random
import stat
import string
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch, MagicMock

from tests.integration.openwebui_cve_2026_28788.scripts import (
    capture_final_fixture_verification,
    collect_evidence,
)
from tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence import (
    REQUIRED_RAW_FILES,
    PINNED_IMAGE_DIGESTS,
    FIXTURE_BASELINE,
    sanitize_firedamp_report,
    sanitize_reproduce_report,
    sanitize_reset_report,
    sanitize_final_verification_report,
    validate_raw_reports,
    generate_bundle_readme,
    sanitize_evidence_bundle,
    sha256_file,
)


class TestEvidenceSanitizer(unittest.TestCase):
    """Test suite for evidence sanitization, redaction, and bundle generation."""

    def setUp(self):
        self.mock_firedamp_v085 = {
            "cve_id": "CVE-2026-28788",
            "run_id": "firedamp-lab-run-9ab2a196268b",
            "target_url": "http://127.0.0.1:13085",
            "target_file_id": "ffffffff-0000-0000-0000-000000000085",
            "severity": "direct_leak",
            "target_response": "COMPROMISED: Overwrite mutation proven in victim indexed content via authorized readback path: POISONED TRACER: CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F",
            "leaked_canaries": [
                "CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F"
            ],
            "is_vulnerable": True,
            "is_clean": False,
            "is_inconclusive": False,
        }

        self.mock_firedamp_v086 = {
            "cve_id": "CVE-2026-28788",
            "run_id": "firedamp-lab-run-3010ffba0e20",
            "target_url": "http://127.0.0.1:13086",
            "target_file_id": "ffffffff-0000-0000-0000-000000000086",
            "severity": "none",
            "target_response": "CLEAN: Server returned per-file authorization rejection (Permission denied: not file owner), attacker authentication verified, and original indexed content remains intact.",
            "leaked_canaries": [],
            "is_vulnerable": False,
            "is_clean": True,
            "is_inconclusive": False,
        }

        self.mock_reproduce_v085 = {
            "verdict": "VULNERABLE_CONFIRMED",
            "reason": "Attacker Bob successfully overwritten Alice's indexed file content in shared KB without file ownership.",
            "target_url": "http://127.0.0.1:13085",
            "disposable_file_id": "ffffffff-0000-0000-0000-000000000085",
            "kb_id": "cccccccc-0000-0000-0000-000000000085",
            "alice_user_id": "aaaaaaaa-0000-0000-0000-000000000085",
            "bob_user_id": "bbbbbbbb-0000-0000-0000-000000000085",
            "tracer_marker": "POISONED TRACER: FIREDAMP-CVE-2026-28788-OVERWRITE-CONFIRMED-ATTACKER-MARKER\nUNAUTHORIZED INJECTION BY BOB\nTIMESTAMP: 2026-11-22T10:00:00Z",
            "tracer_found_in_readback": True,
            "http_status": 200,
            "batch_response": {
                "results": [
                    {
                        "file_id": "ffffffff-0000-0000-0000-000000000085",
                        "status": "completed",
                        "error": None,
                    }
                ],
                "errors": [],
            },
            "baseline_sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
            "post_readback_sha256": "dc53bc65a0b06571578f0b6dcc6d92a989a5706ccc5c74d3eb1422d1caf6d232",
        }

        self.mock_reproduce_v086 = {
            "verdict": "PATCHED_CONFIRMED",
            "reason": "Open WebUI enforced file ownership check on batch processing and rejected unauthorized modification.",
            "target_url": "http://127.0.0.1:13086",
            "disposable_file_id": "ffffffff-0000-0000-0000-000000000086",
            "kb_id": "cccccccc-0000-0000-0000-000000000086",
            "alice_user_id": "aaaaaaaa-0000-0000-0000-000000000086",
            "bob_user_id": "bbbbbbbb-0000-0000-0000-000000000086",
            "tracer_marker": "POISONED TRACER: FIREDAMP-CVE-2026-28788-OVERWRITE-CONFIRMED-ATTACKER-MARKER\nUNAUTHORIZED INJECTION BY BOB\nTIMESTAMP: 2026-11-22T10:00:00Z",
            "tracer_found_in_readback": False,
            "http_status": 200,
            "batch_response": {
                "results": [],
                "errors": [
                    {
                        "file_id": "ffffffff-0000-0000-0000-000000000086",
                        "status": "failed",
                        "error": "Permission denied: not file owner",
                    }
                ],
            },
            "baseline_sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
            "post_readback_sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
        }

        self.mock_reset_v085 = {
            "status": "RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED",
            "file_id": "ffffffff-0000-0000-0000-000000000085",
            "kb_id": "cccccccc-0000-0000-0000-000000000085",
            "owner_user_id": "aaaaaaaa-0000-0000-0000-000000000085",
            "target_version": "0.8.5",
            "content_length": 302,
            "sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
            "verified_owner": True,
            "verified_hash": True,
            "verified_kb_membership": True,
            "preserved_other_file_count": 0,
            "vector_removal_request_accepted": True,
            "vector_cleanup_verification": "NO_MARKER_IN_TOP_K_NOT_EXHAUSTIVE",
            "verified_vector_cleanup": False,
        }

        self.mock_final_verification = {
            "verification_mode": "live_read_only_verification",
            "live_execution": True,
            "read_only": True,
            "verified_at_utc": "2026-11-25T04:00:00Z",
            "vector_cleanup_verified": False,
            "vector_cleanup_note": (
                "Independent read-only fixture verification checks server version, user identities, "
                "ownership, complete KB membership, and indexed content baseline only; exhaustive "
                "vector cleanup is not claimed or verified by this check."
            ),
            "targets": {
                "v0.8.5": {
                    "expected_version": "0.8.5",
                    "verified_version": "0.8.5",
                    "target_url": "http://127.0.0.1:13085",
                    "baseline_verified": True,
                    "original_sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
                    "content_length": 302,
                    "target_in_alice_kb": True,
                    "kb_file_count": 1,
                    "identities_and_read_metadata_verified": True,
                },
                "v0.8.6": {
                    "expected_version": "0.8.6",
                    "verified_version": "0.8.6",
                    "target_url": "http://127.0.0.1:13086",
                    "baseline_verified": True,
                    "original_sha256": "b8fe905c936d2f95065012f079a6637825559561b03a52967cf7de42136bf2de",
                    "content_length": 302,
                    "target_in_alice_kb": True,
                    "kb_file_count": 1,
                    "identities_and_read_metadata_verified": True,
                },
            },
        }

    def _write_raw_bundle(
        self,
        raw_dir: Path,
        *,
        firedamp_v085=None,
        firedamp_v086=None,
        reproduce_v085=None,
        reproduce_v086=None,
        reset_v085=None,
        final_verification=None,
    ) -> None:
        files = {
            "firedamp-v085.json": firedamp_v085 or self.mock_firedamp_v085,
            "firedamp-v086.json": firedamp_v086 or self.mock_firedamp_v086,
            "reproduce-v085.json": reproduce_v085 or self.mock_reproduce_v085,
            "reproduce-v086.json": reproduce_v086 or self.mock_reproduce_v086,
            "reset-v085.json": reset_v085 or self.mock_reset_v085,
            "final-fixture-verification.json": final_verification or self.mock_final_verification,
        }
        for fname, payload in files.items():
            (raw_dir / fname).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_sanitize_firedamp_report(self):
        """Sanitizer replaces UUID with TARGET_FILE and normalizes run ID."""
        sanitized = sanitize_firedamp_report(self.mock_firedamp_v085, "v085")
        self.assertEqual(sanitized["target_file_id"], "TARGET_FILE")
        self.assertEqual(sanitized["run_id"], "firedamp-lab-run-v085")
        self.assertEqual(sanitized["severity"], "direct_leak")
        self.assertTrue(sanitized["is_vulnerable"])
        self.assertNotIn("5e116d97", json.dumps(sanitized))

    def test_sanitize_reproduce_report(self):
        """Sanitizer replaces user, KB, and file UUIDs with consistent role-based placeholders."""
        sanitized = sanitize_reproduce_report(self.mock_reproduce_v085, "v085")
        self.assertEqual(sanitized["disposable_file_id"], "TARGET_FILE")
        self.assertEqual(sanitized["kb_id"], "TARGET_KNOWLEDGE_BASE")
        self.assertEqual(sanitized["alice_user_id"], "VICTIM_USER")
        self.assertEqual(sanitized["bob_user_id"], "ATTACKER_USER")
        self.assertEqual(sanitized["batch_response"]["results"][0]["file_id"], "TARGET_FILE")
        self.assertEqual(sanitized["verdict"], "VULNERABLE_CONFIRMED")
        self.assertEqual(sanitized["baseline_sha256"], FIXTURE_BASELINE["sha256"])
        self.assertNotIn("5e116d97", json.dumps(sanitized))
        self.assertNotIn("4d8347e3", json.dumps(sanitized))
        self.assertNotIn("c24265b6", json.dumps(sanitized))

    def test_sanitize_evidence_bundle_full_pipeline(self):
        """Full pipeline ingests mock raw reports, creates sanitized outputs and manifest."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            self._write_raw_bundle(raw_dir)

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIsInstance(manifest, dict)
            self.assertEqual(manifest["cve_id"], "CVE-2026-28788")

            expected_files = [
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
                "sanitized-reset-v085.json",
                "sanitized-final-fixture-verification.json",
                "README.md",
                "manifest.json",
            ]
            for ef in expected_files:
                fpath = out_dir / ef
                self.assertTrue(fpath.exists(), f"Missing expected output file: {ef}")
                if ef.endswith(".json"):
                    data = json.loads(fpath.read_text())
                    self.assertIsInstance(data, dict)

            # Ensure raw files were not modified
            for fname in REQUIRED_RAW_FILES:
                self.assertEqual(sha256_file(raw_dir / fname), manifest["raw_evidence_files"][fname]["sha256"])

    def test_sanitized_outputs_enforce_0600_and_readme_documents_live_raw_dir(self):
        """Sanitized outputs receive 0600 permissions, preserve dir/raw/unrelated modes, keep valid hashes, and document live-raw."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp, tempfile.TemporaryDirectory() as unrelated_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            os.chmod(out_dir, 0o700)
            unrelated_file = Path(unrelated_tmp) / "unrelated_existing.txt"
            unrelated_file.write_text("unrelated pre-existing file\n", encoding="utf-8")
            os.chmod(unrelated_file, 0o644)
            self._write_raw_bundle(raw_dir)
            for fname in REQUIRED_RAW_FILES:
                os.chmod(raw_dir / fname, 0o640)

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            # Directory, raw file, and unrelated pre-existing file permissions remain preserved
            self.assertEqual(stat.S_IMODE(out_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(unrelated_file.stat().st_mode), 0o644)
            for fname in REQUIRED_RAW_FILES:
                self.assertEqual(stat.S_IMODE((raw_dir / fname).stat().st_mode), 0o640)

            expected_outputs = [
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
                "sanitized-reset-v085.json",
                "sanitized-final-fixture-verification.json",
                "README.md",
                "manifest.json",
            ]
            for out_name in expected_outputs:
                out_path = out_dir / out_name
                self.assertTrue(out_path.exists(), f"Missing output: {out_name}")
                self.assertEqual(
                    stat.S_IMODE(out_path.stat().st_mode),
                    0o600,
                    f"Expected mode 0600 for {out_name}, got {stat.S_IMODE(out_path.stat().st_mode):04o}",
                )

            # Manifest hashes still match every sanitized output
            for out_name, meta in manifest["sanitized_output_files"].items():
                self.assertEqual(meta["sha256"], sha256_file(out_dir / out_name))

            # Generated README documents the live-raw input path and sanitized output path
            readme_text = (out_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("--raw-dir ~/firedamp-evidence/cve-2026-28788/live-raw \\", readme_text)
            self.assertIn("--output-dir ~/firedamp-evidence/cve-2026-28788/sanitized", readme_text)
            self.assertNotIn("--raw-dir ~/firedamp-evidence/cve-2026-28788 \\", readme_text)

    def test_acceptance_of_genuine_dynamic_reports(self):
        """Dynamic reports with arbitrary content hashes (not fixed historical hashes) are ingested securely."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            self._write_raw_bundle(raw_dir)

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertEqual(manifest["cve_id"], "CVE-2026-28788")
            for fname in REQUIRED_RAW_FILES:
                self.assertIn(fname, manifest["raw_evidence_files"])
                self.assertEqual(manifest["raw_evidence_files"][fname]["sha256"], sha256_file(raw_dir / fname))

    def test_differential_validation_vulnerable_vs_patched(self):
        """Differential validation passes when v085 is vulnerable and v086 is patched."""
        validate_raw_reports(
            self.mock_firedamp_v085,
            self.mock_firedamp_v086,
            self.mock_reproduce_v085,
            self.mock_reproduce_v086,
            self.mock_reset_v085,
            self.mock_final_verification,
        )

    def test_rejection_of_missing_files(self):
        """Sanitizer raises FileNotFoundError when required raw reports are missing."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            (raw_dir / "firedamp-v085.json").write_text(json.dumps(self.mock_firedamp_v085, indent=2))
            with self.assertRaises(FileNotFoundError):
                sanitize_evidence_bundle(raw_dir, out_dir)

    def test_rejection_of_malformed_json(self):
        """Sanitizer raises ValueError when a raw report contains invalid JSON."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            self._write_raw_bundle(raw_dir)
            (raw_dir / "firedamp-v085.json").write_text("{malformed json")
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

    def test_rejection_of_contradictory_verdicts(self):
        """Rejects raw inputs where both targets claim vulnerable or both claim clean."""
        bad_firedamp_v086 = copy.deepcopy(self.mock_firedamp_v086)
        bad_firedamp_v086["is_vulnerable"] = True
        bad_firedamp_v086["is_clean"] = False
        with self.assertRaises(ValueError):
            validate_raw_reports(
                self.mock_firedamp_v085,
                bad_firedamp_v086,
                self.mock_reproduce_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )

        bad_reproduce_v085 = copy.deepcopy(self.mock_reproduce_v085)
        bad_reproduce_v085["verdict"] = "PATCHED_CONFIRMED"
        with self.assertRaises(ValueError):
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_reproduce_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )

    def test_rejection_of_wrong_target_urls(self):
        """Rejects reports pointing to swapped or unexpected URLs."""
        bad_v085 = copy.deepcopy(self.mock_firedamp_v085)
        bad_v085["target_url"] = "http://127.0.0.1:13086"
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                bad_v085,
                self.mock_firedamp_v086,
                self.mock_reproduce_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("target_url", str(ctx.exception))

    def test_rejection_of_incorrect_content_hashes_or_baseline_mismatch(self):
        """Rejects reports where baseline hash is incorrect or v085 post-readback didn't mutate."""
        bad_reproduce_v085 = copy.deepcopy(self.mock_reproduce_v085)
        bad_reproduce_v085["baseline_sha256"] = "0" * 64
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_reproduce_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("baseline_sha256", str(ctx.exception))

        no_mutation_v085 = copy.deepcopy(self.mock_reproduce_v085)
        no_mutation_v085["post_readback_sha256"] = FIXTURE_BASELINE["sha256"]
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                no_mutation_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("post_readback_sha256", str(ctx.exception))

    def test_rejection_of_non_boolean_flags(self):
        """Strict type checking rejects non-boolean integer or string values in boolean flags."""
        bad_v085 = copy.deepcopy(self.mock_firedamp_v085)
        bad_v085["is_vulnerable"] = 1  # Truthy integer, not bool
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                bad_v085,
                self.mock_firedamp_v086,
                self.mock_reproduce_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("is_vulnerable must be True", str(ctx.exception))

        bad_rep_v085 = copy.deepcopy(self.mock_reproduce_v085)
        bad_rep_v085["tracer_found_in_readback"] = "True"  # String, not bool
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_rep_v085,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("tracer_found_in_readback must be True", str(ctx.exception))

    def test_rejection_of_non_integer_http_status(self):
        """Strict type checking rejects non-integer status codes."""
        bad_rep = copy.deepcopy(self.mock_reproduce_v085)
        bad_rep["http_status"] = "200"  # String instead of int
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_rep,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("http_status must be integer 200", str(ctx.exception))

    def test_rejection_of_invalid_sha256(self):
        """Strict hash validator rejects malformed, non-hex, or truncated SHA-256 digests."""
        bad_rep = copy.deepcopy(self.mock_reproduce_v085)
        bad_rep["post_readback_sha256"] = "not-a-valid-hex-hash"
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_rep,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("post_readback_sha256 must be valid SHA-256", str(ctx.exception))

    def test_rejection_of_malformed_batch_response_v085(self):
        """Malformed batch response on vulnerable target fails closed."""
        bad_rep = copy.deepcopy(self.mock_reproduce_v085)
        bad_rep["batch_response"] = {"results": []}  # Empty results list
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_rep,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("batch_response.results must be a non-empty list", str(ctx.exception))

        bad_rep_item = copy.deepcopy(self.mock_reproduce_v085)
        bad_rep_item["batch_response"]["results"] = [{"file_id": "TARGET_FILE", "status": "failed"}]
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_rep_item,
                self.mock_reproduce_v086,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("status='completed'", str(ctx.exception))

    def test_rejection_of_malformed_batch_response_v086(self):
        """Malformed batch response on patched target fails closed."""
        bad_rep = copy.deepcopy(self.mock_reproduce_v086)
        bad_rep["batch_response"] = {"errors": []}  # Empty errors list
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                self.mock_reproduce_v085,
                bad_rep,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("batch_response.errors must be a non-empty list", str(ctx.exception))

        bad_rep_err = copy.deepcopy(self.mock_reproduce_v086)
        bad_rep_err["batch_response"]["errors"] = [{"file_id": "TARGET_FILE", "status": "failed", "error": "Internal Error"}]
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                self.mock_reproduce_v085,
                bad_rep_err,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("per-file ownership rejection", str(ctx.exception))

    def test_manifest_records_actual_calculated_raw_hashes(self):
        """Manifest contains calculated raw hashes, provenance notes, and image digests."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            self._write_raw_bundle(raw_dir)

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("provenance_notes", manifest)
            self.assertIn("Collector-computed hashes", manifest["provenance_notes"])
            self.assertEqual(manifest["target_images"], PINNED_IMAGE_DIGESTS)
            self.assertEqual(manifest["fixture_baseline"], FIXTURE_BASELINE)
            v085_reset = manifest["fixture_reset_verification"]["v0.8.5"]
            self.assertEqual(v085_reset["reset_status"], "RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED")
            self.assertEqual(v085_reset["preserved_other_file_count"], 0)
            self.assertTrue(v085_reset["verified_owner"])
            self.assertTrue(v085_reset["verified_hash"])
            self.assertTrue(v085_reset["verified_kb_membership"])
            self.assertTrue(v085_reset["vector_removal_request_accepted"])
            self.assertEqual(v085_reset["vector_cleanup_verification"], "NO_MARKER_IN_TOP_K_NOT_EXHAUSTIVE")
            self.assertFalse(v085_reset["verified_vector_cleanup"])
            self.assertTrue(v085_reset["schema_validated"])
            self.assertFalse(v085_reset["cryptographic_origin_authenticated"])

            v086_reset = manifest["fixture_reset_verification"]["v0.8.6"]
            self.assertEqual(v086_reset["reset_status"], "NOT_NEEDED")
            self.assertTrue(v086_reset["schema_validated"])
            self.assertFalse(v086_reset["cryptographic_origin_authenticated"])

            for fname in REQUIRED_RAW_FILES:
                self.assertEqual(manifest["raw_evidence_files"][fname]["sha256"], sha256_file(raw_dir / fname))
                self.assertTrue(manifest["raw_evidence_files"][fname]["verified"])
            for out_fname in [
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
                "sanitized-reset-v085.json",
                "sanitized-final-fixture-verification.json",
                "README.md",
            ]:
                self.assertEqual(
                    manifest["sanitized_output_files"][out_fname]["sha256"],
                    sha256_file(out_dir / out_fname),
                )

    def test_raw_files_remain_byte_for_byte_unchanged(self):
        """Sanitizer verifies byte-for-byte immutability of raw files before and after processing."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            self._write_raw_bundle(raw_dir)

            hashes_before = {
                f: sha256_file(raw_dir / f)
                for f in REQUIRED_RAW_FILES
            }
            sanitize_evidence_bundle(raw_dir, out_dir)
            hashes_after = {
                f: sha256_file(raw_dir / f)
                for f in REQUIRED_RAW_FILES
            }
            self.assertEqual(hashes_before, hashes_after)

    def test_generated_readme_reflects_actual_supplied_canaries_and_hashes(self):
        """Generated README reflects actual supplied canaries, hashes, and setup CLI flags."""
        custom_firedamp = copy.deepcopy(self.mock_firedamp_v085)
        custom_canary = "CANARY-FRDP-11112222-3333-4444-5555-666677778888-ABCD"
        custom_firedamp["leaked_canaries"] = [custom_canary]
        custom_reproduce = copy.deepcopy(self.mock_reproduce_v085)
        custom_reproduce["post_readback_sha256"] = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

        readme = generate_bundle_readme(
            custom_firedamp,
            self.mock_firedamp_v086,
            custom_reproduce,
            self.mock_reproduce_v086,
            self.mock_reset_v085,
            self.mock_final_verification,
        )
        self.assertIn(custom_canary, readme)
        self.assertIn("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", readme)
        self.assertIn("--url http://127.0.0.1:13085 --target-name v085 --output /tmp/setup-v085.json", readme)
        self.assertIn("--url http://127.0.0.1:13086 --target-name v086 --output /tmp/setup-v086.json", readme)
        self.assertNotIn("--target v085", readme)

    def test_sanitized_files_contain_no_credentials_or_internal_uuids(self):
        """Sanitized outputs contain role-based placeholders and no private user/file UUIDs."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            noisy_reset = copy.deepcopy(self.mock_reset_v085)
            noisy_reset["vector_cleanup_note"] = (
                "File ffffffff-0000-0000-0000-000000000085 in KB cccccccc-0000-0000-0000-000000000085 "
                "owned by aaaaaaaa-0000-0000-0000-000000000085 checked."
            )
            noisy_final = copy.deepcopy(self.mock_final_verification)
            noisy_final["targets"]["v0.8.5"]["token"] = "secret-bearer-token-should-drop"
            noisy_final["targets"]["v0.8.5"]["file_id"] = "ffffffff-0000-0000-0000-000000000085"
            self._write_raw_bundle(raw_dir, reset_v085=noisy_reset, final_verification=noisy_final)

            sanitize_evidence_bundle(raw_dir, out_dir)
            for fname in [
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
                "sanitized-reset-v085.json",
                "sanitized-final-fixture-verification.json",
            ]:
                content = (out_dir / fname).read_text(encoding="utf-8")
                self.assertNotIn("ffffffff-0000-0000-0000-000000000085", content)
                self.assertNotIn("cccccccc-0000-0000-0000-000000000085", content)
                self.assertNotIn("aaaaaaaa-0000-0000-0000-000000000085", content)
                self.assertNotIn("bbbbbbbb-0000-0000-0000-000000000085", content)
                self.assertNotIn("ffffffff-0000-0000-0000-000000000086", content)
                self.assertNotIn("secret-bearer-token-should-drop", content)

    def test_rejection_of_missing_reset_and_final_verification_reports(self):
        """Sanitizer fails closed with FileNotFoundError if reset-v085 or final-fixture-verification is missing."""
        for missing in ("reset-v085.json", "final-fixture-verification.json"):
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
                    raw_dir = Path(raw_tmp)
                    out_dir = Path(out_tmp)
                    self._write_raw_bundle(raw_dir)
                    (raw_dir / missing).unlink()
                    with self.assertRaises(FileNotFoundError):
                        sanitize_evidence_bundle(raw_dir, out_dir)

    def test_rejection_of_malformed_reset_or_final_verification_json(self):
        """Sanitizer fails closed with ValueError on malformed JSON in reset or final verification reports."""
        for malformed in ("reset-v085.json", "final-fixture-verification.json"):
            with self.subTest(malformed=malformed):
                with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
                    raw_dir = Path(raw_tmp)
                    out_dir = Path(out_tmp)
                    self._write_raw_bundle(raw_dir)
                    (raw_dir / malformed).write_text("{not valid json", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        sanitize_evidence_bundle(raw_dir, out_dir)

    def test_rejection_of_invalid_reset_artifact_conditions(self):
        """Validate fail-closed checks for reset-v085 boolean types, false flags, version, hash, count, and vector claim."""
        cases = [
            ("non_bool_verified_owner", {"verified_owner": 1}),
            ("non_bool_verified_hash", {"verified_hash": "True"}),
            ("non_bool_verified_kb_membership", {"verified_kb_membership": 1}),
            ("non_bool_vector_removal_accepted", {"vector_removal_request_accepted": "true"}),
            ("non_bool_verified_vector_cleanup", {"verified_vector_cleanup": 0}),
            ("false_verified_owner", {"verified_owner": False}),
            ("false_verified_hash", {"verified_hash": False}),
            ("false_verified_kb_membership", {"verified_kb_membership": False}),
            ("false_vector_removal_accepted", {"vector_removal_request_accepted": False}),
            ("wrong_target_version", {"target_version": "0.8.6"}),
            ("wrong_reset_status", {"status": "SUCCESS"}),
            ("wrong_sha256", {"sha256": "0" * 64}),
            ("wrong_content_length", {"content_length": 301}),
            ("negative_preserved_count", {"preserved_other_file_count": -1}),
            ("bool_preserved_count", {"preserved_other_file_count": True}),
            ("incorrect_vector_diagnostic", {"vector_cleanup_verification": "ALL_VECTORS_PURGED"}),
            ("claimed_verified_vector_cleanup", {"verified_vector_cleanup": True}),
        ]
        for label, patch_fields in cases:
            with self.subTest(case=label):
                bad_reset = copy.deepcopy(self.mock_reset_v085)
                bad_reset.update(patch_fields)
                with self.assertRaises(ValueError):
                    validate_raw_reports(
                        self.mock_firedamp_v085,
                        self.mock_firedamp_v086,
                        self.mock_reproduce_v085,
                        self.mock_reproduce_v086,
                        bad_reset,
                        self.mock_final_verification,
                    )

    def test_rejection_of_invalid_final_verification_conditions(self):
        """Validate fail-closed checks for final-fixture-verification version, baseline, mode, and vector claims."""
        with self.subTest(case="claimed_vector_cleanup_verified"):
            bad = copy.deepcopy(self.mock_final_verification)
            bad["vector_cleanup_verified"] = True
            with self.assertRaises(ValueError):
                validate_raw_reports(
                    self.mock_firedamp_v085, self.mock_firedamp_v086,
                    self.mock_reproduce_v085, self.mock_reproduce_v086,
                    self.mock_reset_v085, bad,
                )

        with self.subTest(case="non_bool_read_only"):
            bad = copy.deepcopy(self.mock_final_verification)
            bad["read_only"] = 1
            with self.assertRaises(ValueError):
                validate_raw_reports(
                    self.mock_firedamp_v085, self.mock_firedamp_v086,
                    self.mock_reproduce_v085, self.mock_reproduce_v086,
                    self.mock_reset_v085, bad,
                )

        target_cases = [
            ("wrong_verified_version", "v0.8.5", {"verified_version": "0.8.6"}),
            ("wrong_expected_version", "v0.8.6", {"expected_version": "0.8.5"}),
            ("wrong_url", "v0.8.5", {"target_url": "http://127.0.0.1:13086"}),
            ("false_baseline_verified", "v0.8.5", {"baseline_verified": False}),
            ("non_bool_baseline_verified", "v0.8.6", {"baseline_verified": 1}),
            ("wrong_sha256", "v0.8.6", {"original_sha256": "a" * 64}),
            ("wrong_content_length", "v0.8.5", {"content_length": 123}),
            ("false_target_in_alice_kb", "v0.8.5", {"target_in_alice_kb": False}),
            ("false_identities_verified", "v0.8.6", {"identities_and_read_metadata_verified": False}),
            ("zero_kb_file_count", "v0.8.6", {"kb_file_count": 0}),
            ("bool_kb_file_count", "v0.8.5", {"kb_file_count": True}),
            ("mismatched_v085_kb_file_count", "v0.8.5", {"kb_file_count": 3}),
        ]
        for label, target_key, patch_fields in target_cases:
            with self.subTest(case=label):
                bad = copy.deepcopy(self.mock_final_verification)
                bad["targets"][target_key].update(patch_fields)
                with self.assertRaises(ValueError):
                    validate_raw_reports(
                        self.mock_firedamp_v085, self.mock_firedamp_v086,
                        self.mock_reproduce_v085, self.mock_reproduce_v086,
                        self.mock_reset_v085, bad,
                    )

    def test_readme_and_manifest_reflect_zero_and_two_preserved_files_truthfully(self):
        """README and manifest accurately reflect 0 or 2 preserved neighboring files and never overstate cleanup."""
        with tempfile.TemporaryDirectory() as raw0_tmp, tempfile.TemporaryDirectory() as out0_tmp:
            self._write_raw_bundle(Path(raw0_tmp))
            manifest0 = sanitize_evidence_bundle(Path(raw0_tmp), Path(out0_tmp))
            readme0 = (Path(out0_tmp) / "README.md").read_text(encoding="utf-8")

            self.assertEqual(manifest0["fixture_reset_verification"]["v0.8.5"]["preserved_other_file_count"], 0)
            self.assertIn("0 other files were present in the disposable knowledge base", readme0)
            self.assertIn("no neighboring files were present to preserve", readme0)
            self.assertNotIn("0 other files were preserved", readme0)
            self.assertNotIn("2 other KB files preserved", readme0)
            self.assertIn("not exhaustive proof of vector absence", readme0)
            self.assertIn("exhaustive vector cleanup remains unverified", readme0)
            self.assertNotIn("Purged overwritten vector embeddings", readme0)
            self.assertNotIn("Verified 0 tracer vectors remained", readme0)
            self.assertNotIn("all-MiniLM-L6-v2", readme0)

        reset_two = copy.deepcopy(self.mock_reset_v085)
        reset_two["preserved_other_file_count"] = 2
        final_two = copy.deepcopy(self.mock_final_verification)
        final_two["targets"]["v0.8.5"]["kb_file_count"] = 3
        with tempfile.TemporaryDirectory() as raw2_tmp, tempfile.TemporaryDirectory() as out2_tmp:
            self._write_raw_bundle(Path(raw2_tmp), reset_v085=reset_two, final_verification=final_two)
            manifest2 = sanitize_evidence_bundle(Path(raw2_tmp), Path(out2_tmp))
            readme2 = (Path(out2_tmp) / "README.md").read_text(encoding="utf-8")

            self.assertEqual(manifest2["fixture_reset_verification"]["v0.8.5"]["preserved_other_file_count"], 2)
            self.assertIn("Reset reported `preserved_other_file_count=2` and final KB membership count matched (3 total files in KB)", readme2)
            self.assertIn("not separately hashed or recorded", readme2)
            self.assertNotIn("verified preserved", readme2)
            self.assertNotIn("0 other files were present", readme2)
            self.assertIn("not exhaustive proof of vector absence", readme2)

    def test_capture_final_fixture_verification_script(self):
        """Read-only verification capture records non-secret facts, sets 0600 mode, and fails closed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            s085 = tmp / "setup-v085.json"
            s086 = tmp / "setup-v086.json"
            out_path = tmp / "final-fixture-verification.json"

            setup_085_data = {
                "base_url": "http://127.0.0.1:13085",
                "lab_identity": {"name": "firedamp-cve-2026-28788", "schema_version": 1, "expected_version": "0.8.5"},
                "alice": {"token": "secret-alice-085", "user_id": "aaaaaaaa-0000-0000-0000-000000000085"},
                "bob": {"token": "secret-bob-085", "user_id": "bbbbbbbb-0000-0000-0000-000000000085"},
                "knowledge_base": {"id": "cccccccc-0000-0000-0000-000000000085"},
                "disposable_file": {
                    "id": "ffffffff-0000-0000-0000-000000000085",
                    "filename": "alice_disposable.txt",
                    "original_content_length": 302,
                    "original_content_sha256": FIXTURE_BASELINE["sha256"],
                },
            }
            setup_086_data = {
                "base_url": "http://127.0.0.1:13086",
                "lab_identity": {"name": "firedamp-cve-2026-28788", "schema_version": 1, "expected_version": "0.8.6"},
                "alice": {"token": "secret-alice-086", "user_id": "aaaaaaaa-0000-0000-0000-000000000086"},
                "bob": {"token": "secret-bob-086", "user_id": "bbbbbbbb-0000-0000-0000-000000000086"},
                "knowledge_base": {"id": "cccccccc-0000-0000-0000-000000000086"},
                "disposable_file": {
                    "id": "ffffffff-0000-0000-0000-000000000086",
                    "filename": "alice_disposable.txt",
                    "original_content_length": 302,
                    "original_content_sha256": FIXTURE_BASELINE["sha256"],
                },
            }
            for p, d in ((s085, setup_085_data), (s086, setup_086_data)):
                p.write_text(json.dumps(d), encoding="utf-8")
                os.chmod(p, 0o600)

            def fake_verify(setup, request_fn, **kwargs):
                self.assertTrue(kwargs.get("require_baseline"))
                return {
                    "version": setup["lab_identity"]["expected_version"],
                    "file_id": setup["disposable_file"]["id"],
                    "kb_id": setup["knowledge_base"]["id"],
                    "alice_user_id": setup["alice"]["user_id"],
                    "bob_user_id": setup["bob"]["user_id"],
                    "file_ids_in_kb": [setup["disposable_file"]["id"]],
                    "content_sha256": setup["disposable_file"]["original_content_sha256"],
                    "content_length": setup["disposable_file"]["original_content_length"],
                    "baseline_verified": True,
                }

            with patch.object(capture_final_fixture_verification, "verify_setup_target", side_effect=fake_verify):
                report = capture_final_fixture_verification.capture_final_fixture_verification(
                    s085, s086, out_path
                )

            self.assertEqual(stat.S_IMODE(out_path.stat().st_mode), 0o600)
            self.assertEqual(report["verification_mode"], "live_read_only_verification")
            self.assertTrue(report["read_only"])
            self.assertFalse(report["vector_cleanup_verified"])
            self.assertEqual(report["targets"]["v0.8.5"]["content_length"], 302)
            self.assertEqual(report["targets"]["v0.8.6"]["content_length"], 302)

            serialized = out_path.read_text(encoding="utf-8")
            self.assertNotIn("secret-alice", serialized)
            self.assertNotIn("secret-bob", serialized)
            self.assertNotIn("ffffffff-0000-0000-0000-000000000085", serialized)
            self.assertNotIn("aaaaaaaa-0000-0000-0000-000000000085", serialized)
            self.assertNotIn("cccccccc-0000-0000-0000-000000000085", serialized)

            # Non-GET HTTP methods must be rejected
            for bad_method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(bad_method=bad_method):
                    with self.assertRaises(ValueError):
                        capture_final_fixture_verification.http_request(
                            "http://127.0.0.1:13085/api/version", method=bad_method
                        )

            # GET requests supplying a body must also be rejected
            for body in (b"{}", b"", "payload", ""):
                with self.subTest(body=body):
                    with self.assertRaises(ValueError):
                        capture_final_fixture_verification.http_request(
                            "http://127.0.0.1:13085/api/version", method="GET", data=body
                        )

            # Setup metadata length disagreeing with actual readback length must fail closed
            def mismatched_length_verify(setup, request_fn, **kwargs):
                res = fake_verify(setup, request_fn, **kwargs)
                res["content_length"] = 999
                return res

            with patch.object(capture_final_fixture_verification, "verify_setup_target", side_effect=mismatched_length_verify):
                with self.assertRaises(RuntimeError) as len_ctx:
                    capture_final_fixture_verification.capture_final_fixture_verification(s085, s086, out_path)
                self.assertIn("does not match setup original_content_length", str(len_ctx.exception))

            # Missing actual content_length from readback result must fail closed
            def missing_length_verify(setup, request_fn, **kwargs):
                res = fake_verify(setup, request_fn, **kwargs)
                res.pop("content_length", None)
                return res

            with patch.object(capture_final_fixture_verification, "verify_setup_target", side_effect=missing_length_verify):
                with self.assertRaises(RuntimeError) as miss_ctx:
                    capture_final_fixture_verification.capture_final_fixture_verification(s085, s086, out_path)
                self.assertIn("content_length", str(miss_ctx.exception))

            # Non-pinned loopback URL (e.g. localhost alias or swapped port) must fail closed
            bad_url_085 = copy.deepcopy(setup_085_data)
            bad_url_085["base_url"] = "http://localhost:13085"
            bad_url_path = tmp / "bad-url-085.json"
            bad_url_path.write_text(json.dumps(bad_url_085), encoding="utf-8")
            os.chmod(bad_url_path, 0o600)
            with patch.object(capture_final_fixture_verification, "verify_setup_target", side_effect=fake_verify):
                with self.assertRaises(ValueError) as url_ctx:
                    capture_final_fixture_verification.capture_final_fixture_verification(bad_url_path, s086, out_path)
                self.assertIn("http://127.0.0.1:13085", str(url_ctx.exception))

            # Fail closed on failed baseline verification
            with patch.object(
                capture_final_fixture_verification,
                "verify_setup_target",
                side_effect=RuntimeError("Baseline mismatch"),
            ):
                with self.assertRaises(RuntimeError):
                    capture_final_fixture_verification.capture_final_fixture_verification(s085, s086, out_path)

    def test_rejection_of_setup_files_in_raw_dir(self):
        """Sanitizer refuses raw directories containing credential-bearing setup JSON files."""
        for forbidden in ("setup-v085.json", "setup-v086.json"):
            with self.subTest(forbidden=forbidden):
                with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
                    raw_dir = Path(raw_tmp)
                    self._write_raw_bundle(raw_dir)
                    (raw_dir / forbidden).write_text("{\"alice\": {\"token\": \"secret\"}}", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        sanitize_evidence_bundle(raw_dir, Path(out_tmp))

    def test_http_client_rejects_redirects_without_forwarding_authorization_header(self):
        """Read-only verification HTTP client refuses redirects so Bearer tokens cannot leak to a second server."""
        received_second_server: list[dict] = []

        class SecondServerHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                received_second_server.append(
                    {"path": self.path, "auth": self.headers.get("Authorization")}
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, format, *args):
                pass

        second_server = ThreadingHTTPServer(("127.0.0.1", 0), SecondServerHandler)
        second_port = second_server.server_address[1]

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{second_port}/capture-token")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        first_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        first_port = first_server.server_address[1]

        t1 = threading.Thread(target=first_server.serve_forever, daemon=True)
        t2 = threading.Thread(target=second_server.serve_forever, daemon=True)
        t1.start()
        t2.start()
        try:
            resp = capture_final_fixture_verification.http_request(
                f"http://127.0.0.1:{first_port}/api/v1/auths/",
                method="GET",
                headers={"Authorization": "Bearer super-secret-bearer-token"},
            )
            self.assertEqual(resp["status_code"], 302)
            self.assertIsNotNone(resp["error"])
            self.assertEqual(received_second_server, [])
        finally:
            first_server.shutdown()
            second_server.shutdown()
            first_server.server_close()
            second_server.server_close()

    def test_write_secure_json_refuses_symlink_and_preserves_target(self):
        """_write_secure_json refuses pre-existing output symlink and leaves target file unchanged."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            target_file = tmp / "victim_target.txt"
            target_file.write_text("DO_NOT_OVERWRITE_TARGET", encoding="utf-8")
            symlink_out = tmp / "final-fixture-verification.json"
            os.symlink(target_file, symlink_out)

            with self.assertRaises(ValueError):
                capture_final_fixture_verification._write_secure_json(
                    {"verification_mode": "live_read_only_verification"}, symlink_out
                )
            self.assertEqual(target_file.read_text(encoding="utf-8"), "DO_NOT_OVERWRITE_TARGET")

    def test_free_text_fields_scrub_credentials_while_preserving_canaries(self):
        """Token-like values, cookies, passwords, and stray UUIDs in free-text fields are scrubbed; canaries remain."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                "COMPROMISED: CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F "
                "Authorization: Bearer tok_leak_12345 Cookie: session=abcsecretpassword "
                "password=AdminPass123! uuid=12345678-1234-1234-1234-1234567890ab"
            )
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = "Overwritten using Bearer reason_tok_99999 and password=SecretReason!"
            rep_085["tracer_marker"] = (
                "POISONED TRACER: CANARY-FRDP-11111111-2222-3333-4444-555555555555-ABCD "
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signaturepart123"
            )
            rep_085["batch_response"]["results"][0]["error"] = "Set-Cookie: sid=badcookievalue"
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                "Permission denied: not file owner (token=err_secret_token_88888)"
            )
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = "Note with Bearer reset_tok_77777 and sk-abcdef1234567890"
            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = "Note with password=fv_pass_66666 and uuid=99999999-8888-7777-6666-555555555555"

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv,
            )
            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("Bearer tokens", manifest["sanitization_method"])
            self.assertIn("Cookie headers", manifest["sanitization_method"])

            combined = "\n".join(
                (out_dir / f).read_text(encoding="utf-8")
                for f in (
                    "sanitized-v085.json",
                    "sanitized-reproduce-v085.json",
                    "sanitized-reproduce-v086.json",
                    "sanitized-reset-v085.json",
                    "sanitized-final-fixture-verification.json",
                )
            )
            for secret in (
                "tok_leak_12345",
                "abcsecretpassword",
                "AdminPass123!",
                "12345678-1234-1234-1234-1234567890ab",
                "reason_tok_99999",
                "SecretReason!",
                "eyJhbGciOiJIUzI1NiJ9",
                "badcookievalue",
                "err_secret_token_88888",
                "reset_tok_77777",
                "sk-abcdef1234567890",
                "fv_pass_66666",
                "99999999-8888-7777-6666-555555555555",
            ):
                self.assertNotIn(secret, combined)

            # Legitimate canary tokens are preserved intact
            s_v085 = json.loads((out_dir / "sanitized-v085.json").read_text(encoding="utf-8"))
            self.assertIn("CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F", s_v085["target_response"])
            s_rep_v085 = json.loads((out_dir / "sanitized-reproduce-v085.json").read_text(encoding="utf-8"))
            self.assertIn("CANARY-FRDP-11111111-2222-3333-4444-555555555555-ABCD", s_rep_v085["tracer_marker"])

    def test_sanitized_final_verification_does_not_synthesize_absent_pseudonym_fields(self):
        """Sanitized final-fixture-verification omits target_file_id/kb_id/user_id keys not present in source."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            self._write_raw_bundle(raw_dir)
            sanitize_evidence_bundle(raw_dir, out_dir)
            sanitized_fv = json.loads(
                (out_dir / "sanitized-final-fixture-verification.json").read_text(encoding="utf-8")
            )
            for key in ("v0.8.5", "v0.8.6"):
                t = sanitized_fv["targets"][key]
                self.assertNotIn("target_file_id", t)
                self.assertNotIn("kb_id", t)
                self.assertNotIn("alice_user_id", t)
                self.assertNotIn("bob_user_id", t)
                self.assertTrue(t["identities_and_read_metadata_verified"])

    def test_readme_sanitizes_patched_batch_error_and_malformed_leaked_canaries(self):
        """README uses sanitized/escaped text and redacts malformed canary strings across all outputs."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            valid_canary = "CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F"
            fd_085["leaked_canaries"] = [
                valid_canary,
                "Bearer canary_secret_tok password=CanaryPass123! | [evil](http://x)",
            ]
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            raw_err = (
                "Permission denied: not file owner Bearer err_bearer_999 "
                "password=ErrPass123! | [link](http://evil)"
            )
            rep_086["batch_response"]["errors"][0]["error"] = raw_err

            self._write_raw_bundle(raw_dir, firedamp_v085=fd_085, reproduce_v086=rep_086)
            sanitize_evidence_bundle(raw_dir, out_dir)

            all_outputs = {
                p.name: p.read_text(encoding="utf-8")
                for p in out_dir.iterdir()
                if p.is_file()
            }
            for fname, content in all_outputs.items():
                self.assertNotIn("canary_secret_tok", content, f"Secret leaked in {fname}")
                self.assertNotIn("CanaryPass123!", content, f"Password leaked in {fname}")
                self.assertNotIn("err_bearer_999", content, f"Bearer token leaked in {fname}")
                self.assertNotIn("ErrPass123!", content, f"Password leaked in {fname}")

            readme_text = all_outputs["README.md"]
            self.assertIn(valid_canary, readme_text)
            self.assertIn("\\[REDACTED\\_MALFORMED\\_CANARY\\]", readme_text)
            self.assertNotIn(raw_err, readme_text)
            self.assertIn("Bearer \\[REDACTED\\_TOKEN\\]", readme_text)
            self.assertIn("password=\\[REDACTED\\_SECRET\\]", readme_text)
            self.assertIn("\\| \\[link\\]\\(http://evil\\)", readme_text)

            sanitized_v085 = json.loads(all_outputs["sanitized-v085.json"])
            self.assertEqual(sanitized_v085["leaked_canaries"], [valid_canary, "[REDACTED_MALFORMED_CANARY]"])

    def test_unexpected_non_string_free_text_types_fail_closed(self):
        """Nested dicts/lists/ints in retained free-text fields fail closed instead of forwarding."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            # Nested dict containing token in reason and tracer_marker
            rep_bad_reason = copy.deepcopy(self.mock_reproduce_v085)
            rep_bad_reason["reason"] = {"leaked": "Bearer secret_in_dict"}
            self._write_raw_bundle(raw_dir, reproduce_v085=rep_bad_reason)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

            rep_bad_tracer = copy.deepcopy(self.mock_reproduce_v085)
            rep_bad_tracer["tracer_marker"] = {"token": "nested_secret_tok"}
            self._write_raw_bundle(raw_dir, reproduce_v085=rep_bad_tracer)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

            # Non-string in target_response, batch result/error, and vector_cleanup_note
            fd_bad_resp = copy.deepcopy(self.mock_firedamp_v085)
            fd_bad_resp["target_response"] = ["list", "not", "str"]
            self._write_raw_bundle(raw_dir, firedamp_v085=fd_bad_resp)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

            rep_bad_res_err = copy.deepcopy(self.mock_reproduce_v085)
            rep_bad_res_err["batch_response"]["results"][0]["error"] = {"secret": 123}
            self._write_raw_bundle(raw_dir, reproduce_v085=rep_bad_res_err)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

            rep_bad_err = copy.deepcopy(self.mock_reproduce_v086)
            rep_bad_err["batch_response"]["errors"][0]["error"] = 403
            self._write_raw_bundle(raw_dir, reproduce_v086=rep_bad_err)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

            rst_bad_note = copy.deepcopy(self.mock_reset_v085)
            rst_bad_note["vector_cleanup_note"] = ["unexpected"]
            self._write_raw_bundle(raw_dir, reset_v085=rst_bad_note)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

            fv_bad_note = copy.deepcopy(self.mock_final_verification)
            fv_bad_note["vector_cleanup_note"] = {"note": "bad"}
            self._write_raw_bundle(raw_dir, final_verification=fv_bad_note)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, out_dir)

    def test_rejection_of_non_failed_batch_error_status(self):
        """batch_response.errors[].status must strictly equal 'failed'."""
        bad_rep = copy.deepcopy(self.mock_reproduce_v086)
        bad_rep["batch_response"]["errors"][0]["status"] = "arbitrary_status"
        with self.assertRaises(ValueError) as ctx:
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                self.mock_reproduce_v085,
                bad_rep,
                self.mock_reset_v085,
                self.mock_final_verification,
            )
        self.assertIn("status must be 'failed'", str(ctx.exception))

    def test_verified_at_utc_normalized_or_omitted_when_invalid(self):
        """verified_at_utc is normalized to UTC ISO-8601 when valid and omitted when invalid/non-UTC."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            fv_valid = copy.deepcopy(self.mock_final_verification)
            fv_valid["verified_at_utc"] = "2026-11-25T04:00:00+00:00"
            self._write_raw_bundle(raw_dir, final_verification=fv_valid)
            sanitize_evidence_bundle(raw_dir, out_dir)
            s_valid = json.loads((out_dir / "sanitized-final-fixture-verification.json").read_text(encoding="utf-8"))
            self.assertEqual(s_valid["verified_at_utc"], "2026-11-25T04:00:00Z")

            for idx, bad_ts in enumerate(("arbitrary-not-a-date", "2026-11-25T04:00:00+05:45", "2026-11-25T04:00:00")):
                with self.subTest(bad_ts=bad_ts):
                    sub_out_dir = out_dir / f"bad_ts_{idx}"
                    fv_bad = copy.deepcopy(self.mock_final_verification)
                    fv_bad["verified_at_utc"] = bad_ts
                    self._write_raw_bundle(raw_dir, final_verification=fv_bad)
                    sanitize_evidence_bundle(raw_dir, sub_out_dir)
                    s_bad = json.loads(
                        (sub_out_dir / "sanitized-final-fixture-verification.json").read_text(encoding="utf-8")
                    )
                    self.assertNotIn("verified_at_utc", s_bad)

    def test_free_text_scrubs_url_userinfo_json_secrets_and_malformed_canary_suffixes(self):
        """URL userinfo, JSON-style secrets, and malformed CANARY-FRDP suffixes are scrubbed across all outputs."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            valid_canary = "CANARY-FRDP-11112222-3333-4444-5555-666677778888-ABCD"
            malformed_canary_with_suffix = (
                "CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F-SECRET_TRAILING_SUFFIX"
            )

            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary} {malformed_canary_with_suffix} "
                'http://alice:UrlPass123@127.0.0.1:13085/cb {"password":"json-secret-pass"}'
            )
            fd_085["leaked_canaries"] = [valid_canary]

            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = '{"cookie":"session=json-cookie-secret"} http://bob:BobUrlPass@127.0.0.1:13085/'
            rep_085["tracer_marker"] = (
                f"{valid_canary} {malformed_canary_with_suffix} "
                '{"authorization":"Basic json-basic-secret"} {"api_key":"json-api-secret"}'
            )

            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                'Permission denied: not file owner {"password":"err-json-pass"} '
                f"http://ops:OpsPass@127.0.0.1:13086/ {malformed_canary_with_suffix}"
            )

            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = (
                'Note {"api_key":"fv-json-api-secret"} {"cookie":"session=fv-json-cookie"} '
                "http://admin:AdminUrlPass@127.0.0.1:13085/"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                final_verification=fv,
            )
            sanitize_evidence_bundle(raw_dir, out_dir)

            outputs = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir() if p.is_file()}
            for secret in (
                "UrlPass123",
                "json-secret-pass",
                "json-cookie-secret",
                "BobUrlPass",
                "json-basic-secret",
                "json-api-secret",
                "err-json-pass",
                "OpsPass",
                "fv-json-api-secret",
                "fv-json-cookie",
                "AdminUrlPass",
                "SECRET_TRAILING_SUFFIX",
            ):
                for fname, content in outputs.items():
                    self.assertNotIn(secret, content, f"Secret '{secret}' leaked in {fname}")

            s_v085 = json.loads(outputs["sanitized-v085.json"])
            self.assertIn(valid_canary, s_v085["target_response"])
            self.assertIn("[REDACTED_MALFORMED_CANARY]", s_v085["target_response"])

    def test_collector_refuses_symlinks_for_output_dir_and_all_output_files(self):
        """Collector refuses symlink output_dir and pre-existing output symlinks without altering targets."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as target_tmp:
            raw_dir = Path(raw_tmp)
            self._write_raw_bundle(raw_dir)

            # 1. Symlinked output directory
            real_dir = Path(target_tmp) / "real_out"
            real_dir.mkdir()
            symlink_dir = Path(target_tmp) / "symlink_out"
            os.symlink(real_dir, symlink_dir)
            with self.assertRaises(ValueError):
                sanitize_evidence_bundle(raw_dir, symlink_dir)
            self.assertEqual(list(real_dir.iterdir()), [])

            # 2. Pre-existing symlink for each collector output file
            for fname in (
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
                "sanitized-reset-v085.json",
                "sanitized-final-fixture-verification.json",
                "README.md",
                "manifest.json",
            ):
                with self.subTest(symlink_output=fname):
                    with tempfile.TemporaryDirectory() as out_tmp:
                        out_dir = Path(out_tmp)
                        victim = Path(target_tmp) / f"victim_{fname}.txt"
                        victim.write_text("BYTE_FOR_BYTE_UNCHANGED", encoding="utf-8")
                        os.symlink(victim, out_dir / fname)
                        with self.assertRaises(ValueError):
                            sanitize_evidence_bundle(raw_dir, out_dir)
                        self.assertEqual(victim.read_text(encoding="utf-8"), "BYTE_FOR_BYTE_UNCHANGED")

    def test_readme_adversarial_markdown_error_escaping(self):
        """Adversarial Markdown characters in batch error cannot inject table cells, links, or headings."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                "Permission denied: not file owner `break` | extra_col | "
                "[click](http://evil.example) <script>alert(1)</script>\n# Injected Heading"
            )
            self._write_raw_bundle(raw_dir, reproduce_v086=rep_086)
            sanitize_evidence_bundle(raw_dir, out_dir)

            readme_text = (out_dir / "README.md").read_text(encoding="utf-8")
            self.assertNotIn("\n# Injected Heading", readme_text)
            self.assertNotIn("<script>", readme_text)
            self.assertNotIn("[click](http://evil.example)", readme_text)
            self.assertIn("\\`break\\`", readme_text)
            self.assertIn("\\| extra\\_col \\|", readme_text)
            self.assertIn("\\<script\\>alert\\(1\\)\\</script\\>", readme_text)

            batch_rows = [line for line in readme_text.splitlines() if "1. Direct Exploit — Batch Payload" in line]
            self.assertEqual(len(batch_rows), 1)
            # Strip escaped pipes `\|` before counting table column separators `|`
            unescaped_pipes = batch_rows[0].replace("\\|", "").count("|")
            self.assertEqual(unescaped_pipes, 4)

    def test_extended_secret_patterns_scrub_credentials_across_all_fields_and_formats(self):
        """Extended secret key patterns scrub client_secret, secret_key, private_key, aws_secret_access_key,
        access-token, and refresh-token (both underscore and hyphen variants, case-insensitively) across
        JSON, single-quoted, and unquoted formats in target_response, reason, tracer_marker, batch errors,
        and vector_cleanup_note, asserting none appear in any sanitized output, README, or manifest."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            valid_canary = "CANARY-FRDP-11112222-3333-4444-5555-666677778888-ABCD"
            secret_values = [
                "super-client-secret-json-111",
                "super-client-secret-unquoted-222",
                "super-secret-key-json-333",
                "super-secret-key-unquoted-444",
                "super-priv-key-single-quoted-555",
                "super-priv-key-unquoted-666",
                "super-aws-secret-unquoted-777",
                "super-aws-secret-json-888",
                "super-access-token-unquoted-999",
                "super-access-token-json-000",
                "super-refresh-token-single-quoted-aaa",
                "super-refresh-token-unquoted-bbb",
            ]

            # 1. target_response (firedamp_v085): JSON client_secret and unquoted client-secret
            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary} "
                '{"CLIENT_SECRET": "super-client-secret-json-111"} '
                'client-secret="super-client-secret-unquoted-222"'
            )
            fd_085["leaked_canaries"] = [valid_canary]

            # 2. reason (reproduce_v085): JSON secret_key and unquoted secret-key
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = (
                'Exploited via {"secret_key": "super-secret-key-json-333"} '
                'and Secret-Key: super-secret-key-unquoted-444'
            )

            # 3. tracer_marker (reproduce_v085): single-quoted private_key and unquoted private-key
            rep_085["tracer_marker"] = (
                f"{valid_canary} "
                "{'private_key': 'super-priv-key-single-quoted-555'} "
                'private-key=super-priv-key-unquoted-666'
            )

            # 4. batch error text (reproduce_v086): unquoted aws_secret_access_key and JSON aws-secret-access-key
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                "Permission denied: not file owner "
                "AWS_SECRET_ACCESS_KEY=super-aws-secret-unquoted-777 "
                '{"aws-secret-access-key": "super-aws-secret-json-888"}'
            )

            # 5. vector_cleanup_note (reset_v085): unquoted access-token and JSON access_token
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = (
                'Reset diagnostic with access-token="super-access-token-unquoted-999" '
                'and {"access_token": "super-access-token-json-000"}'
            )

            # 6. vector_cleanup_note (final_verification): single-quoted refresh-token and unquoted refresh_token
            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = (
                "Final verification note: {'REFRESH-TOKEN': 'super-refresh-token-single-quoted-aaa'} "
                "refresh_token: super-refresh-token-unquoted-bbb"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv,
            )
            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            outputs = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir() if p.is_file()}
            # Verify manifest.json and README.md are present among outputs
            self.assertIn("manifest.json", outputs)
            self.assertIn("README.md", outputs)

            # Assert none of the secret values appear in any generated sanitized JSON, README, or manifest
            for secret in secret_values:
                for fname, content in outputs.items():
                    self.assertNotIn(secret, content, f"Secret value '{secret}' leaked into {fname}")

            # Verify legitimate canary was preserved
            s_v085 = json.loads(outputs["sanitized-v085.json"])
            self.assertIn(valid_canary, s_v085["target_response"])
            s_rep_085 = json.loads(outputs["sanitized-reproduce-v085.json"])
            self.assertIn(valid_canary, s_rep_085["tracer_marker"])

    def test_nested_structured_and_pem_secret_values_are_redacted_across_all_fields(self):
        """Structured JSON objects, arrays, and multiline PEM private key material associated with
        sensitive keys are completely redacted across target_response, reason, tracer_marker,
        batch errors, reset vector_cleanup_note, and final verification vector_cleanup_note,
        with none appearing in any sanitized output JSON, README, or manifest."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            valid_canary_tr = "CANARY-FRDP-aaaaaaaa-1111-2222-3333-444455556666-ABCD"
            valid_canary_tm = "CANARY-FRDP-bbbbbbbb-1111-2222-3333-444455556666-DCBA"

            nested_secrets = [
                "NESTED-SECRET-TR",
                "PRIVATE-MATERIAL-REASON",
                "NESTED-AWS-SECRET-TM",
                "NESTED-SECRET-BATCH",
                "PRIVATE-MATERIAL-RESET",
                "NESTED-AWS-SECRET-FV",
                "STANDALONE-PEM-BODY",
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----END PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
            ]

            # 1. target_response: nested object {"client_secret": {"value": "NESTED-SECRET-TR"}}
            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary_tr} "
                'Error details: {"client_secret": {"value": "NESTED-SECRET-TR"}}'
            )
            fd_085["leaked_canaries"] = [valid_canary_tr]

            # 2. reason: object with PEM {"private_key": {"pem": "-----BEGIN PRIVATE KEY-----\nPRIVATE-MATERIAL-REASON"}}
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = (
                'Exploited with key: {"private_key": {"pem": "-----BEGIN PRIVATE KEY-----\\nPRIVATE-MATERIAL-REASON"}} '
                'and standalone PEM: -----BEGIN RSA PRIVATE KEY-----\nSTANDALONE-PEM-BODY\n-----END RSA PRIVATE KEY-----'
            )

            # 3. tracer_marker: array {"aws_secret_access_key": ["NESTED-AWS-SECRET-TM"]}
            rep_085["tracer_marker"] = (
                f"{valid_canary_tm} "
                'Tracer config: {"aws_secret_access_key": ["NESTED-AWS-SECRET-TM"]}'
            )

            # 4. batch error text: nested object in error
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                'Permission denied: not file owner {"client_secret": {"value": "NESTED-SECRET-BATCH"}}'
            )

            # 5. reset vector_cleanup_note: nested PEM object
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = (
                'Reset vector cleanup diagnostics: {"private_key": {"pem": "-----BEGIN PRIVATE KEY-----\\nPRIVATE-MATERIAL-RESET"}}'
            )

            # 6. final verification vector_cleanup_note: nested array
            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = (
                'Final verification diagnostic: {"aws_secret_access_key": ["NESTED-AWS-SECRET-FV"]}'
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv,
            )
            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            outputs = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir() if p.is_file()}
            self.assertIn("manifest.json", outputs)
            self.assertIn("README.md", outputs)

            # Assert none of the nested secret values or PEM material appear anywhere in outputs
            for sec in nested_secrets:
                for fname, content in outputs.items():
                    self.assertNotIn(sec, content, f"Secret / PEM material '{sec}' leaked into {fname}")

            # Verify legitimate canaries were preserved
            s_v085 = json.loads(outputs["sanitized-v085.json"])
            self.assertIn(valid_canary_tr, s_v085["target_response"])
            s_rep_085 = json.loads(outputs["sanitized-reproduce-v085.json"])
            self.assertIn(valid_canary_tm, s_rep_085["tracer_marker"])

    def test_unbounded_or_malformed_structured_secrets_fail_closed(self):
        """Malformed or unclosed structured values (unclosed braces, brackets, quotes) fail closed."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            # 1. Unclosed JSON object after sensitive key
            bad_obj_rep = copy.deepcopy(self.mock_reproduce_v085)
            bad_obj_rep["reason"] = 'Exploited: {"client_secret": {"value": "NESTED-SECRET"'
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_obj_rep)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unbounded structured secret value", str(ctx.exception))

            # 2. Unclosed JSON array after sensitive key
            bad_arr_rep = copy.deepcopy(self.mock_reproduce_v085)
            bad_arr_rep["reason"] = 'Exploited: {"aws_secret_access_key": ["NESTED-AWS-SECRET"'
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_arr_rep)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unbounded structured secret value", str(ctx.exception))

            # 3. Unclosed quoted string after sensitive key
            bad_str_rep = copy.deepcopy(self.mock_reproduce_v085)
            bad_str_rep["reason"] = 'Exploited: {"private_key": "unclosed pem string'
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_str_rep)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unbounded quoted secret value", str(ctx.exception))

    def test_multiline_yaml_block_scalars_and_sequences_are_redacted_across_all_fields(self):
        """Multiline YAML literal (|, |-, |+), folded (>, >-, >+), and sequence values after
        sensitive keys are completely redacted across target_response, reason, tracer_marker,
        batch errors, reset vector_cleanup_note, and final verification vector_cleanup_note,
        with no sentinels or continuation lines appearing in any generated sanitized output,
        README, or manifest."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            valid_canary_tr = "CANARY-FRDP-aaaaaaaa-1111-2222-3333-444455556666-ABCD"
            valid_canary_tm = "CANARY-FRDP-bbbbbbbb-1111-2222-3333-444455556666-DCBA"

            sentinels = [
                "SENTINEL-YAML-LITERAL-1",
                "SENTINEL-YAML-LITERAL-2",
                "SENTINEL-YAML-CHOMP-LITERAL-1",
                "SENTINEL-YAML-CHOMP-LITERAL-2",
                "SENTINEL-YAML-FOLDED-1",
                "SENTINEL-YAML-FOLDED-2",
                "SENTINEL-YAML-CHOMP-FOLDED-1",
                "SENTINEL-YAML-CHOMP-FOLDED-2",
                "SENTINEL-YAML-SEQ-1",
                "SENTINEL-YAML-SEQ-2",
                "SENTINEL-YAML-PLUS-LITERAL-1",
                "SENTINEL-YAML-PLUS-LITERAL-2",
                "SENTINEL-YAML-ANCHOR-1",
                "SENTINEL-YAML-ANCHOR-2",
                "SENTINEL-YAML-TAG-1",
                "SENTINEL-YAML-TAG-2",
                "SENTINEL-YAML-COMMENT-BEFORE-1",
                "SENTINEL-YAML-COMMENT-BEFORE-2",
                "SENTINEL-YAML-INLINE-COMMENT-1",
                "SENTINEL-YAML-INLINE-COMMENT-2",
                "SENTINEL-YAML-INDENT-CHOMP-1",
                "SENTINEL-YAML-INDENT-CHOMP-2",
                "SENTINEL-YAML-FOLDED-CHOMP-1",
                "SENTINEL-YAML-FOLDED-CHOMP-2",
            ]

            # 1. target_response: chomped literal scalar (|-) and anchored block scalar (&vault |)
            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary_tr}\n"
                "client_secret: |-\n"
                "  SENTINEL-YAML-CHOMP-LITERAL-1\n"
                "  SENTINEL-YAML-CHOMP-LITERAL-2\n"
                "private_key: &vault |\n"
                "  SENTINEL-YAML-ANCHOR-1\n"
                "  SENTINEL-YAML-ANCHOR-2\n"
                "adjacent_prop_1: preserved\n"
                "diagnostic_flag: true"
            )
            fd_085["leaked_canaries"] = [valid_canary_tr]

            # 2. reason: literal block scalar (|), tagged block scalar (!!str |), and indent/chomp (|2-)
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = (
                "Exploited via YAML config:\n"
                "private_key: |\n"
                "  SENTINEL-YAML-LITERAL-1\n"
                "  SENTINEL-YAML-LITERAL-2\n"
                "client_secret: !!str |\n"
                "  SENTINEL-YAML-TAG-1\n"
                "  SENTINEL-YAML-TAG-2\n"
                "aws_secret_access_key: &vault !!str |2-\n"
                "  SENTINEL-YAML-INDENT-CHOMP-1\n"
                "  SENTINEL-YAML-INDENT-CHOMP-2\n"
                "adjacent_prop_2: preserved\n"
                "status_code: 200"
            )

            # 3. tracer_marker: folded block scalar (>) and chomped/folded indicator (> -2)
            rep_085["tracer_marker"] = (
                f"{valid_canary_tm}\n"
                "aws_secret_access_key: >\n"
                "  SENTINEL-YAML-FOLDED-1\n"
                "  SENTINEL-YAML-FOLDED-2\n"
                "secret_key: !tag &vault >-2\n"
                "  SENTINEL-YAML-FOLDED-CHOMP-1\n"
                "  SENTINEL-YAML-FOLDED-CHOMP-2\n"
                "adjacent_prop_3: preserved\n"
                "region: us-east-1"
            )

            # 4. batch error text: chomped folded scalar (>-) and comment before sequence
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                "Permission denied: not file owner\n"
                "secret_key: >-\n"
                "  SENTINEL-YAML-CHOMP-FOLDED-1\n"
                "  SENTINEL-YAML-CHOMP-FOLDED-2\n"
                "private_key:\n"
                "# comment before sequence\n"
                "  - SENTINEL-YAML-COMMENT-BEFORE-1\n"
                "  - SENTINEL-YAML-COMMENT-BEFORE-2\n"
                "adjacent_prop_4: preserved"
            )

            # 5. reset vector_cleanup_note: indented sequence and inline comment before sequence
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = (
                "Reset diagnostic config:\n"
                "private_key:\n"
                "  - SENTINEL-YAML-SEQ-1\n"
                "  - SENTINEL-YAML-SEQ-2\n"
                "client_secret: # inline comment before sequence\n"
                "  - SENTINEL-YAML-INLINE-COMMENT-1\n"
                "  - SENTINEL-YAML-INLINE-COMMENT-2\n"
                "adjacent_prop_5: preserved\n"
                "cleanup_verified: false"
            )

            # 6. final verification vector_cleanup_note: plus literal scalar (|+)
            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = (
                "FV diagnostic config:\n"
                "client_secret: |+\n"
                "  SENTINEL-YAML-PLUS-LITERAL-1\n"
                "  SENTINEL-YAML-PLUS-LITERAL-2\n"
                "adjacent_prop_6: preserved"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv,
            )
            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            outputs = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir() if p.is_file()}
            self.assertIn("manifest.json", outputs)
            self.assertIn("README.md", outputs)

            # Assert no sentinel appears in any generated output JSON, README.md, or manifest.json
            for sen in sentinels:
                for fname, content in outputs.items():
                    self.assertNotIn(sen, content, f"YAML sentinel '{sen}' leaked into {fname}")

            # Verify legitimate canaries were preserved
            s_v085 = json.loads(outputs["sanitized-v085.json"])
            self.assertIn(valid_canary_tr, s_v085["target_response"])
            s_rep_085 = json.loads(outputs["sanitized-reproduce-v085.json"])
            self.assertIn(valid_canary_tm, s_rep_085["tracer_marker"])

            # Verify adjacent keys and values are preserved
            self.assertIn("adjacent_prop_1", s_v085["target_response"])
            self.assertIn("preserved", s_v085["target_response"])
            self.assertIn("adjacent_prop_2", s_rep_085["reason"])
            self.assertIn("adjacent_prop_3", s_rep_085["tracer_marker"])
            s_rep_086 = json.loads(outputs["sanitized-reproduce-v086.json"])
            self.assertIn("adjacent_prop_4", s_rep_086["batch_response"]["errors"][0]["error"])
            s_rst = json.loads(outputs["sanitized-reset-v085.json"])
            self.assertIn("adjacent_prop_5", s_rst["vector_cleanup_note"])
            s_fv = json.loads(outputs["sanitized-final-fixture-verification.json"])
            self.assertIn("adjacent_prop_6", s_fv["vector_cleanup_note"])

    def test_unbounded_or_malformed_multiline_yaml_secrets_fail_closed(self):
        """Malformed YAML block scalar indicators or unterminated quotes in sequences fail closed."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            # 1. Illegal content on YAML block indicator line
            bad_yaml_ind = copy.deepcopy(self.mock_reproduce_v085)
            bad_yaml_ind["reason"] = "Exploited:\nprivate_key: | ILLEGAL-TRAILING-TEXT\n  SECRET-MATERIAL"
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_yaml_ind)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("Malformed or unbounded YAML block scalar", str(ctx.exception))

            # 2. Illegal content on chomped / indented YAML block indicator line
            bad_yaml_chomp = copy.deepcopy(self.mock_reproduce_v085)
            bad_yaml_chomp["reason"] = "Exploited:\nprivate_key: &vault |2- ILLEGAL\n  SECRET-MATERIAL"
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_yaml_chomp)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("Malformed or unbounded YAML block scalar", str(ctx.exception))

            # 3. Unterminated quote inside indented YAML sequence
            bad_seq_rep = copy.deepcopy(self.mock_reproduce_v085)
            bad_seq_rep["reason"] = 'Exploited:\nprivate_key:\n  - "UNCLOSED-SECRET-ITEM\n  - VALID-ITEM'
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_seq_rep)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unterminated quote in indented block", str(ctx.exception))

    def test_parent_directory_symlink_rejection(self):
        """Writing through a symlinked parent directory component fails closed with ValueError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_dir = Path(tmp_dir)
            real_target_dir = base_dir / "real_dir"
            real_target_dir.mkdir()
            symlinked_parent = base_dir / "symlink_dir"
            symlinked_parent.symlink_to(real_target_dir)

            # 1. collect_evidence._write_secure_output fails when parent is a symlink
            output_in_symlinked_dir = symlinked_parent / "output.txt"
            with self.assertRaises(ValueError) as ctx:
                collect_evidence._write_secure_output(output_in_symlinked_dir, "content")
            self.assertIn("symlinked parent directory component", str(ctx.exception))

            # 2. capture_final_fixture_verification._write_secure_json fails when parent is a symlink
            json_in_symlinked_dir = symlinked_parent / "output.json"
            with self.assertRaises(ValueError) as ctx:
                capture_final_fixture_verification._write_secure_json({"k": "v"}, json_in_symlinked_dir)
            self.assertIn("symlinked parent directory component", str(ctx.exception))

            # 3. sanitize_evidence_bundle fails when output_dir has a symlinked parent component
            with tempfile.TemporaryDirectory() as raw_dir:
                self._write_raw_bundle(Path(raw_dir))
                with self.assertRaises(ValueError) as ctx:
                    sanitize_evidence_bundle(Path(raw_dir), symlinked_parent / "bundle_out")
                self.assertIn("symlinked parent directory component", str(ctx.exception))

    def test_multiline_yaml_plain_scalar_continuations_are_redacted_across_all_fields(self):
        """Plain scalar multiline continuations, multiword same-line scalars, commas/semicolons,
        inline comments, differing indentation, blank/comment lines, and single-line scalars are
        completely redacted across all free-text fields, while adjacent sibling keys, inline/trailing
        comments, and synthetic canaries are preserved."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            valid_canary_tr = "CANARY-FRDP-cccccccc-1111-2222-3333-444455556666-ABCD"
            valid_canary_tm = "CANARY-FRDP-dddddddd-1111-2222-3333-444455556666-DCBA"

            sentinels = [
                "SENTINEL-MW-A",
                "SENTINEL-MW-B",
                "SENTINEL-MW-C",
                "SENTINEL-COMMA-FIRST",
                "SENTINEL-SEMI-FIRST",
                "SENTINEL-COMMA-CONT-1",
                "SENTINEL-COMMA-CONT-2",
                "SENTINEL-MW-FIRST-1",
                "SENTINEL-MW-FIRST-2",
                "SENTINEL-MW-CONT-1",
                "SENTINEL-MW-CONT-2",
                "SENTINEL-TRAILING-COMM-1",
                "SENTINEL-TRAILING-COMM-2",
                "SENTINEL-INLINE-COMM-1",
                "SENTINEL-INLINE-COMM-2",
                "SENTINEL-QUOTED-KEY-1",
                "SENTINEL-QUOTED-KEY-2",
                "SENTINEL-QUOTED-KEY-CONT",
            ]

            # 1. target_response: multiword same-line plain scalar
            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary_tr}\n"
                "private_key: SENTINEL-MW-A SENTINEL-MW-B SENTINEL-MW-C\n"
                "adjacent_prop_plain_1: preserved_scalar_val_1\n"
                "diagnostic_flag: true"
            )
            fd_085["leaked_canaries"] = [valid_canary_tr]

            # 2. reason: same-line scalar containing commas and semicolons with indented continuations
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = (
                "Exploited via plain YAML scalar with commas and semicolons:\n"
                "client_secret: SENTINEL-COMMA-FIRST, SENTINEL-SEMI-FIRST; extra words,\n"
                "  SENTINEL-COMMA-CONT-1, more text;\n"
                "    SENTINEL-COMMA-CONT-2\n"
                "adjacent_prop_plain_2: preserved_scalar_val_2\n"
                "status_code: 200"
            )

            # 3. tracer_marker: multiword first-line value followed by indented continuation lines
            rep_085["tracer_marker"] = (
                f"{valid_canary_tm}\n"
                "aws_secret_access_key: SENTINEL-MW-FIRST-1 SENTINEL-MW-FIRST-2\n"
                "  SENTINEL-MW-CONT-1\n"
                "\n"
                "# intervening comment inside continuation\n"
                "    SENTINEL-MW-CONT-2\n"
                "\n"
                "adjacent_prop_plain_3: preserved_scalar_val_3\n"
                "region: us-east-1"
            )

            # 4. batch error text: multiline plain scalar followed by comment line preceding sibling key
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                "Permission denied: not file owner\n"
                "secret_key: SENTINEL-TRAILING-COMM-1\n"
                "  SENTINEL-TRAILING-COMM-2\n"
                "# comment describing adjacent\n"
                "adjacent_prop_plain_4: preserved_scalar_val_4"
            )

            # 5. reset vector_cleanup_note: inline comments following multiword values
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = (
                "Reset diagnostic config:\n"
                "access_token: SENTINEL-INLINE-COMM-1 SENTINEL-INLINE-COMM-2 # inline comment for token\n"
                "adjacent_prop_plain_5: preserved_scalar_val_5\n"
                "cleanup_verified: false"
            )

            # 6. final verification vector_cleanup_note: quoted key with multiword first line and continuations
            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = (
                "FV diagnostic config:\n"
                '"refresh_token": SENTINEL-QUOTED-KEY-1, SENTINEL-QUOTED-KEY-2\n'
                "  SENTINEL-QUOTED-KEY-CONT\n"
                "adjacent_prop_plain_6: preserved_scalar_val_6"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv,
            )
            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            outputs = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir() if p.is_file()}
            self.assertIn("manifest.json", outputs)
            self.assertIn("README.md", outputs)

            # Assert no sentinel appears in any generated output JSON, README.md, or manifest.json
            for sen in sentinels:
                for fname, content in outputs.items():
                    self.assertNotIn(sen, content, f"Plain scalar sentinel '{sen}' leaked into {fname}")

            # Verify legitimate canaries were preserved
            s_v085 = json.loads(outputs["sanitized-v085.json"])
            self.assertIn(valid_canary_tr, s_v085["target_response"])
            s_rep_085 = json.loads(outputs["sanitized-reproduce-v085.json"])
            self.assertIn(valid_canary_tm, s_rep_085["tracer_marker"])

            # Verify adjacent keys and values are preserved
            self.assertIn("adjacent_prop_plain_1", s_v085["target_response"])
            self.assertIn("preserved_scalar_val_1", s_v085["target_response"])
            self.assertIn("adjacent_prop_plain_2", s_rep_085["reason"])
            self.assertIn("preserved_scalar_val_2", s_rep_085["reason"])
            self.assertIn("adjacent_prop_plain_3", s_rep_085["tracer_marker"])
            self.assertIn("preserved_scalar_val_3", s_rep_085["tracer_marker"])
            s_rep_086 = json.loads(outputs["sanitized-reproduce-v086.json"])
            self.assertIn("adjacent_prop_plain_4", s_rep_086["batch_response"]["errors"][0]["error"])
            self.assertIn("preserved_scalar_val_4", s_rep_086["batch_response"]["errors"][0]["error"])
            self.assertIn("# comment describing adjacent", s_rep_086["batch_response"]["errors"][0]["error"])
            s_rst = json.loads(outputs["sanitized-reset-v085.json"])
            self.assertIn("adjacent_prop_plain_5", s_rst["vector_cleanup_note"])
            self.assertIn("preserved_scalar_val_5", s_rst["vector_cleanup_note"])
            self.assertIn("# inline comment for token", s_rst["vector_cleanup_note"])
            s_fv = json.loads(outputs["sanitized-final-fixture-verification.json"])
            self.assertIn("adjacent_prop_plain_6", s_fv["vector_cleanup_note"])
            self.assertIn("preserved_scalar_val_6", s_fv["vector_cleanup_note"])

    def test_unbounded_or_malformed_plain_scalar_continuations_fail_closed(self):
        """Malformed plain scalar continuations (unclosed quotes or unbalanced structures) fail closed."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            # 1. Unterminated quote inside plain scalar continuation
            bad_quote = copy.deepcopy(self.mock_reproduce_v085)
            bad_quote["reason"] = (
                "Exploited:\n"
                "private_key: FIRST-SECRET\n"
                '  "UNCLOSED-QUOTE-IN-CONTINUATION\n'
                "  MORE-SECRET\n"
                "adjacent_prop: preserved"
            )
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_quote)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unterminated quote in continuation block", str(ctx.exception))

            # 2. Unterminated structure inside plain scalar continuation
            bad_struct = copy.deepcopy(self.mock_reproduce_v085)
            bad_struct["reason"] = (
                "Exploited:\n"
                "private_key: FIRST-SECRET\n"
                '  {"unclosed": "structure"\n'
                "adjacent_prop: preserved"
            )
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_struct)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unterminated structure in continuation block", str(ctx.exception))

            # 3. Unbalanced structure inside plain scalar continuation line
            bad_unbal = copy.deepcopy(self.mock_reproduce_v085)
            bad_unbal["reason"] = (
                "Exploited:\n"
                "private_key: FIRST-SECRET\n"
                "  } mismatched\n"
                "adjacent_prop: preserved"
            )
            self._write_raw_bundle(raw_dir, reproduce_v085=bad_unbal)
            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("unbalanced structure in continuation line", str(ctx.exception))

    def test_same_line_multiword_plain_scalar_and_inline_comments_sanitization(self):
        """Verify unit behavior for multiword same-line scalars, commas, semicolons, inline comments,
        and fragment URLs across unquoted and quoted secret keys."""
        from tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence import _sanitize_free_text

        # 1. Multiword same-line plain scalar
        text1 = "private_key: FIRST SECRET_VAL MATERIAL\nadjacent_prop: preserved"
        scrubbed1 = _sanitize_free_text(text1)
        self.assertNotIn("FIRST", scrubbed1)
        self.assertNotIn("SECRET_VAL", scrubbed1)
        self.assertNotIn("MATERIAL", scrubbed1)
        self.assertIn("adjacent_prop: preserved", scrubbed1)
        self.assertIn("private_key=[REDACTED_SECRET]", scrubbed1)

        # 2. Comma and semicolon in plain scalar with continuation
        text2 = (
            "client_secret: FIRST-SECRET, with commas;\n"
            "  SECOND-SECRET, more items\n"
            "adjacent_prop: preserved"
        )
        scrubbed2 = _sanitize_free_text(text2)
        self.assertNotIn("FIRST-SECRET", scrubbed2)
        self.assertNotIn("SECOND-SECRET", scrubbed2)
        self.assertIn("adjacent_prop: preserved", scrubbed2)
        self.assertIn("client_secret=[REDACTED_SECRET]", scrubbed2)

        # 3. Inline comment on same line preserved while multiword value is redacted
        text3 = "access_token: MY MULTIWORD TOKEN # this is an inline comment\nadjacent: preserved"
        scrubbed3 = _sanitize_free_text(text3)
        self.assertNotIn("MY", scrubbed3)
        self.assertNotIn("MULTIWORD", scrubbed3)
        self.assertNotIn("TOKEN", scrubbed3)
        self.assertIn("# this is an inline comment", scrubbed3)
        self.assertIn("adjacent: preserved", scrubbed3)

        # 4. URL fragment (# without preceding whitespace) is treated as scalar, not comment
        text4 = "private_key: https://example.com/api#fragment\nadjacent: preserved"
        scrubbed4 = _sanitize_free_text(text4)
        self.assertNotIn("fragment", scrubbed4)
        self.assertIn("adjacent: preserved", scrubbed4)

        # 5. Table pipe with sep == '=' does not swallow table delimiter
        text5 = "password=ErrPass123! | [link](http://evil)"
        scrubbed5 = _sanitize_free_text(text5)
        self.assertNotIn("ErrPass123!", scrubbed5)
        self.assertIn("| [link](http://evil)", scrubbed5)

        # 6. Colon-space inside ambiguous sensitive value is completely redacted without leaving suffix
        text6 = "private_key: FIRST SECRET: SECOND_SECRET\nadjacent_prop: preserved"
        scrubbed6 = _sanitize_free_text(text6)
        self.assertNotIn("FIRST", scrubbed6)
        self.assertNotIn("SECOND_SECRET", scrubbed6)
        self.assertNotIn(": SECOND_SECRET", scrubbed6)
        self.assertIn("adjacent_prop: preserved", scrubbed6)
        self.assertIn("private_key=[REDACTED_SECRET]", scrubbed6)

        # 7. Colon-space after multiword secret is completely redacted
        text7 = "private_key: FIRST MULTIWORD SECRET: STILL_SECRET\nadjacent_prop: preserved"
        scrubbed7 = _sanitize_free_text(text7)
        self.assertNotIn("MULTIWORD", scrubbed7)
        self.assertNotIn("STILL_SECRET", scrubbed7)
        self.assertNotIn(": STILL_SECRET", scrubbed7)
        self.assertIn("adjacent_prop: preserved", scrubbed7)

        # 8. Comma-delimited sibling fields, including following sensitive key
        text8 = "api_key: SECRET1_CANARY, client_secret: SECRET2_CANARY, adjacent: preserved"
        scrubbed8 = _sanitize_free_text(text8)
        self.assertNotIn("SECRET1_CANARY", scrubbed8)
        self.assertNotIn("SECRET2_CANARY", scrubbed8)
        self.assertIn("adjacent: preserved", scrubbed8)
        self.assertIn("api_key=[REDACTED_SECRET]", scrubbed8)
        self.assertIn("client_secret=[REDACTED_SECRET]", scrubbed8)

        # 9. Multiword phrase-style password= value
        text9 = "password=correct horse battery staple\nadjacent: preserved"
        scrubbed9 = _sanitize_free_text(text9)
        self.assertNotIn("correct", scrubbed9)
        self.assertNotIn("horse", scrubbed9)
        self.assertNotIn("battery", scrubbed9)
        self.assertNotIn("staple", scrubbed9)
        self.assertIn("adjacent: preserved", scrubbed9)
        self.assertIn("password=[REDACTED_SECRET]", scrubbed9)

        # 10. Multiword phrase-style token= with Markdown table pipe
        text10 = "| token=phrase style secret token value | [link](http://example.com) |"
        scrubbed10 = _sanitize_free_text(text10)
        self.assertNotIn("phrase", scrubbed10)
        self.assertNotIn("secret", scrubbed10)
        self.assertNotIn("token value", scrubbed10)
        self.assertIn("| [link](http://example.com) |", scrubbed10)

    def test_output_directory_containing_unexpected_files_refused(self):
        """sanitize_evidence_bundle refuses non-empty output directories containing unexpected
        entries without modifying or deleting them."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            self._write_raw_bundle(raw_dir)

            sensitive_preexisting = out_dir / "stale_credentials.json"
            content = '{"secret_token": "MUST_NOT_BE_TOUCHED_OR_DELETED"}\n'
            sensitive_preexisting.write_text(content, encoding="utf-8")
            stat_before = sensitive_preexisting.stat()

            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("non-empty output directory", str(ctx.exception))
            self.assertIn("stale_credentials.json", str(ctx.exception))

            # Verify the pre-existing file was not modified or deleted
            self.assertTrue(sensitive_preexisting.exists())
            self.assertEqual(sensitive_preexisting.read_text(encoding="utf-8"), content)
            self.assertEqual(sensitive_preexisting.stat().st_mtime, stat_before.st_mtime)

    def test_colon_space_boundary_and_multiword_key_value_redaction_e2e(self):
        """End-to-end evidence bundle sanitization verifies that ambiguous colon-space boundaries,
        multiword key=value secrets, comma-delimited siblings, and Markdown table pipes are
        correctly handled without leaking sentinels into any generated artifact."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            valid_canary_tr = "CANARY-FRDP-eeeeeeee-1111-2222-3333-444455556666-BEEF"
            valid_canary_tm = "CANARY-FRDP-ffffffff-1111-2222-3333-444455556666-FEED"

            sentinels = [
                "SENTINEL-COLON-AMBIG-1",
                "SENTINEL-COLON-AMBIG-2",
                "SENTINEL-MW-KEY-1",
                "SENTINEL-MW-KEY-2",
                "SENTINEL-MW-SUFFIX",
                "SENTINEL-COMMA-SIB-1",
                "SENTINEL-COMMA-SIB-2",
                "SENTINEL-MW-PASS-1",
                "SENTINEL-MW-PASS-2",
                "SENTINEL-MW-TOK-1",
                "SENTINEL-MW-TOK-2",
                "SENTINEL-TABLE-PASS-1",
                "SENTINEL-TABLE-PASS-2",
            ]

            # 1. target_response: colon-space inside ambiguous sensitive value
            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary_tr}\n"
                "private_key: SENTINEL-COLON-AMBIG-1: SENTINEL-COLON-AMBIG-2\n"
                "adjacent_prop_plain_1: preserved_scalar_val_1\n"
                "diagnostic_flag: true"
            )
            fd_085["leaked_canaries"] = [valid_canary_tr]

            # 2. reason: colon-space after multiword secret
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = (
                "Exploited via colon-space suffix:\n"
                "client_secret: SENTINEL-MW-KEY-1 SENTINEL-MW-KEY-2: SENTINEL-MW-SUFFIX\n"
                "adjacent_prop_plain_2: preserved_scalar_val_2\n"
                "status_code: 200"
            )

            # 3. tracer_marker: comma-delimited sibling fields, including a following sensitive key
            rep_085["tracer_marker"] = (
                f"{valid_canary_tm}\n"
                "api_key: SENTINEL-COMMA-SIB-1, client_secret: SENTINEL-COMMA-SIB-2, adjacent_prop_plain_3: preserved_scalar_val_3\n"
                "region: us-east-1"
            )

            # 4. batch error text: multiword phrase-style password= value
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                "Permission denied: not file owner\n"
                "password=correct horse battery staple SENTINEL-MW-PASS-1 SENTINEL-MW-PASS-2\n"
                "adjacent_prop_plain_4: preserved_scalar_val_4"
            )

            # 5. reset vector_cleanup_note: multiword phrase-style token= value
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = (
                "Reset diagnostic config:\n"
                "token=phrase style secret token value SENTINEL-MW-TOK-1 SENTINEL-MW-TOK-2\n"
                "adjacent_prop_plain_5: preserved_scalar_val_5\n"
                "cleanup_verified: false"
            )

            # 6. final verification vector_cleanup_note: Markdown table pipe with phrase password
            fv = copy.deepcopy(self.mock_final_verification)
            fv["vector_cleanup_note"] = (
                "FV diagnostic config:\n"
                "| password=SENTINEL-TABLE-PASS-1 SENTINEL-TABLE-PASS-2 | [link](http://example.com/login) |\n"
                "adjacent_prop_plain_6: preserved_scalar_val_6"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv,
            )
            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            outputs = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir() if p.is_file()}
            self.assertIn("manifest.json", outputs)
            self.assertIn("README.md", outputs)

            # Assert no sentinel appears in any generated output JSON, README.md, or manifest.json
            for sen in sentinels:
                for fname, content in outputs.items():
                    self.assertNotIn(sen, content, f"Sentinel '{sen}' leaked into {fname}")

            # Verify legitimate canaries were preserved
            s_v085 = json.loads(outputs["sanitized-v085.json"])
            self.assertIn(valid_canary_tr, s_v085["target_response"])
            s_rep_085 = json.loads(outputs["sanitized-reproduce-v085.json"])
            self.assertIn(valid_canary_tm, s_rep_085["tracer_marker"])

            # Verify adjacent keys and values are preserved
            self.assertIn("adjacent_prop_plain_1", s_v085["target_response"])
            self.assertIn("preserved_scalar_val_1", s_v085["target_response"])
            self.assertIn("adjacent_prop_plain_2", s_rep_085["reason"])
            self.assertIn("preserved_scalar_val_2", s_rep_085["reason"])
            self.assertIn("adjacent_prop_plain_3", s_rep_085["tracer_marker"])
            self.assertIn("preserved_scalar_val_3", s_rep_085["tracer_marker"])
            s_rep_086 = json.loads(outputs["sanitized-reproduce-v086.json"])
            self.assertIn("adjacent_prop_plain_4", s_rep_086["batch_response"]["errors"][0]["error"])
            self.assertIn("preserved_scalar_val_4", s_rep_086["batch_response"]["errors"][0]["error"])
            s_rst = json.loads(outputs["sanitized-reset-v085.json"])
            self.assertIn("adjacent_prop_plain_5", s_rst["vector_cleanup_note"])
            self.assertIn("preserved_scalar_val_5", s_rst["vector_cleanup_note"])
            s_fv = json.loads(outputs["sanitized-final-fixture-verification.json"])
            self.assertIn("adjacent_prop_plain_6", s_fv["vector_cleanup_note"])
            self.assertIn("preserved_scalar_val_6", s_fv["vector_cleanup_note"])
            self.assertIn("| [link](http://example.com/login) |", s_fv["vector_cleanup_note"])

    def test_comprehensive_adversarial_corpus_end_to_end(self):
        """
        Comprehensive adversarial test corpus across all delimiter, whitespace, quote,
        nesting, multiline, CRLF, and Unicode permutations in end-to-end bundle sanitization.
        Asserts that classified secret sentinels never survive across ANY generated artifact.
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)

            valid_canary = "CANARY-FRDP-68259e44-b5db-4403-b42f-275ca9cac5c4-2D2F"
            sentinels = [
                "ADV_SECRET_COLON_EQUALS_1",
                "ADV_SECRET_SEMICOLON_2",
                "ADV_SECRET_AMP_PIPE_3",
                "ADV_SECRET_BRACKETS_4",
                "ADV_SECRET_HASH_COMMENT_5",
                "ADV_SECRET_TABS_CRLF_6",
                "ADV_SECRET_ESCAPED_QUOTES_7",
                "ADV_SECRET_UNICODE_8_\U0001F525",
                "ADV_SECRET_MULTI_ON_LINE_9A",
                "ADV_SECRET_MULTI_ON_LINE_9B",
                "ADV_SECRET_MIXED_FORMAT_10",
                "ADV_SECRET_CLOUD_KEY_11",
                "ADV_SECRET_UNCLOSED_PEM_12",
                "ADV_SECRET_STRUCTURAL_JSON_13",
            ]

            # 1. target_response in firedamp-v085: mixed-format, brackets, and escaped quotes
            fd_085 = copy.deepcopy(self.mock_firedamp_v085)
            fd_085["target_response"] = (
                f"COMPROMISED: {valid_canary} "
                f'{{"client_secret": {{"nested_arr": ["{sentinels[3]}", 123]}}}}, '
                f'"passphrase" = "{sentinels[6]}\\"quoted\\"", other_flag=active\r\n'
                f"Diagnostic notice: secret_key={sentinels[10]}"
            )

            # 2. reason in reproduce-v085: CRLF, tabs, and colons/semicolons
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = (
                f"Observed mutation;\t\r\n"
                f"client_secret={sentinels[0]}, other_prop: preserved_1;\t"
                f"api_key: {sentinels[1]}; next_param=preserved_2\r\n"
                f"\t\"secret_key\":\t\t\"{sentinels[5]}\"\r\n"
            )

            # 3. tracer_marker in reproduce-v085: pipes, ampersands, multiple on one line
            rep_085["tracer_marker"] = (
                f"TRACER-{valid_canary} "
                f"password={sentinels[2]} &user=alice | [link](http://lab.local) | "
                f"token={sentinels[8]}, secret={sentinels[9]}"
            )

            # 4. batch error in reproduce-v086: multiline YAML block, comments, Unicode
            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                f"Permission denied: not file owner\n"
                f"private_key: &vault |\n"
                f"  {sentinels[4]}\n"
                f"# intervening comment line\n"
                f"  more_secret_material\n"
                f"password={sentinels[7]}, system_status=verified_日本語\n"
            )

            # 5. vector_cleanup_note in reset-v085: Cloud AWS keys and unclosed PEM
            rst_085 = copy.deepcopy(self.mock_reset_v085)
            rst_085["vector_cleanup_note"] = (
                f"Targeted cleanup diagnostic: "
                f"aws_access_key_id=AKIAIOSFODNN7EXAMPLE "
                f"aws_secret_access_key={sentinels[11]} "
                f"private_key: -----BEGIN PRIVATE KEY-----\n{sentinels[12]}\n"
                f"public_summary: preserved_cleanup_note"
            )

            # 6. vector_cleanup_note in final-verification: structural JSON
            fv_report = copy.deepcopy(self.mock_final_verification)
            fv_report["vector_cleanup_note"] = json.dumps({
                "note": "Read-only verification baseline check",
                "client_secret": {"deep": sentinels[13]},
                "verified": True,
            })

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=fd_085,
                reproduce_v085=rep_085,
                reproduce_v086=rep_086,
                reset_v085=rst_085,
                final_verification=fv_report,
            )

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIsInstance(manifest, dict)

            # Read all generated files
            outputs = {}
            for path in out_dir.iterdir():
                if path.is_file():
                    outputs[path.name] = path.read_text(encoding="utf-8")

            # Check that NONE of the secret sentinels survive anywhere in the bundle
            for sentinel in sentinels:
                clean_sentinel = sentinel.split("\U0001F525")[0]
                for fname, content in outputs.items():
                    self.assertNotIn(
                        clean_sentinel,
                        content,
                        f"Secret sentinel {clean_sentinel!r} leaked in {fname}",
                    )

            # Verify legitimate evidence is preserved
            self.assertIn(valid_canary, outputs["sanitized-v085.json"])
            self.assertIn(valid_canary, outputs["sanitized-reproduce-v085.json"])
            self.assertIn("preserved_1", outputs["sanitized-reproduce-v085.json"])
            self.assertIn("preserved_2", outputs["sanitized-reproduce-v085.json"])
            s_rep_086 = json.loads(outputs["sanitized-reproduce-v086.json"])
            self.assertIn("verified_日本語", s_rep_086["batch_response"]["errors"][0]["error"])
            self.assertIn("preserved_cleanup_note", outputs["sanitized-reset-v085.json"])

    def test_malformed_and_truncated_structures_fail_closed(self):
        """Malformed or unbounded secret values must fail closed rather than forwarding ambiguous data."""
        test_cases = [
            ("unclosed_quote", 'password="UNCLOSED_SECRET_VAL'),
            ("unbalanced_brackets", 'client_secret={"unbalanced": ["val"}'),
            ("unterminated_yaml_quote", 'private_key: FIRST\n  "UNTERMINATED_CONTINUATION'),
        ]
        for name, malformed_val in test_cases:
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
                    raw_dir = Path(raw_tmp)
                    out_dir = Path(out_tmp)
                    rep_085 = copy.deepcopy(self.mock_reproduce_v085)
                    rep_085["reason"] = malformed_val
                    self._write_raw_bundle(raw_dir, reproduce_v085=rep_085)
                    with self.assertRaises(ValueError):
                        sanitize_evidence_bundle(raw_dir, out_dir)

    def test_atomic_staging_prevents_partial_writes_on_failure(self):
        """When an integrity or processing error occurs, staging prevents partial writes to destination."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "sanitized_target"

            self._write_raw_bundle(raw_dir)

            # Inject a failure during manifest construction by altering a required raw file
            # after initial validation (simulating TOCTOU modification)
            orig_sanitize = collect_evidence.sanitize_firedamp_report

            def faulty_sanitize(*args, **kwargs):
                # Tamper with a raw file during processing to trigger anti-TOCTOU failure
                (raw_dir / "firedamp-v085.json").write_text("{\"TAMPERED\": true}", encoding="utf-8")
                return orig_sanitize(*args, **kwargs)

            with patch.object(collect_evidence, "sanitize_firedamp_report", side_effect=faulty_sanitize):
                with self.assertRaises(RuntimeError) as ctx:
                    sanitize_evidence_bundle(raw_dir, out_dir)
                self.assertIn("INTEGRITY VIOLATION", str(ctx.exception))

            # Destination must NOT exist or must be completely empty (no partial writes)
            if out_dir.exists():
                self.assertEqual(list(out_dir.iterdir()), [])

    def test_property_based_fuzz_sanitizer(self):
        """
        Property-based randomized fuzz test over combinations of sensitive keys, delimiters,
        whitespace, quotes, and synthetic canaries, asserting confidentiality and integrity invariants.
        """
        rng = random.Random(42)  # Deterministic seed for reproducible property runs
        sensitive_keys = [
            "password", "client_secret", "client-secret", "secret_key",
            "private_key", "aws_secret_access_key", "aws_access_key_id",
            "access-token", "refresh-token", "api_key", "passphrase",
        ]
        delimiters = [": ", " = ", "=", ":\t"]
        quote_styles = ["", "\"", "'"]

        for iteration in range(25):
            key = rng.choice(sensitive_keys)
            delim = rng.choice(delimiters)
            q = rng.choice(quote_styles)
            sentinel = "FUZZ_SECRET_" + "".join(rng.choices(string.ascii_uppercase + string.digits, k=12))
            valid_canary = f"CANARY-FRDP-{iteration:08x}-1234-5678-90ab-cdef12345678-abcd"

            # Formulate text with sensitive key-value, canary, and adjacent benign property
            if q:
                payload = f'{key}{delim}{q}{sentinel}{q}, adjacent_prop="safe_value", {valid_canary}'
            else:
                payload = f'{key}{delim}{sentinel}\nadjacent_prop: safe_value\ncanary: {valid_canary}\n'

            scrubbed = collect_evidence._sanitize_free_text(payload)
            self.assertIsNotNone(scrubbed)

            # Invariant 1: Sentinel MUST NOT survive in scrubbed output
            self.assertNotIn(
                sentinel,
                scrubbed,
                f"Fuzz iteration {iteration} leaked secret sentinel {sentinel!r} in payload: {payload!r}",
            )

            # Invariant 2: Valid CANARY token MUST be preserved
            self.assertIn(
                valid_canary,
                scrubbed,
                f"Fuzz iteration {iteration} lost legitimate canary {valid_canary!r} in: {scrubbed!r}",
            )

            # Invariant 3: Adjacent benign property MUST be preserved
            self.assertIn("adjacent_prop", scrubbed)
            self.assertIn("safe_value", scrubbed)

    def test_json_sensitive_key_aliases_and_normalization_recursive_e2e(self):
        """
        Finding 1 Regression:
        Credential property aliases with camelCase, PascalCase, qualifiers, and delimiters
        (dbPassword, openaiApiKey, serviceAccessToken, tokenValue, db_password_value,
        refreshTokenValue, clientSecretValue, DATABASE-PASSWORD, aws.secret.access.key)
        are redacted completely, even when nested in objects or arrays across all forwarded free-text fields,
        while preserving legitimate non-sensitive metadata keys (public_key, token_count, max_tokens, key_id,
        jwt_algorithm, sha256).
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_aliases"

            sentinels = {
                "db_pw": "SENTINEL-DB-PW-12345",
                "smtp_pw": "SENTINEL-SMTP-PW-23456",
                "openai": "sk-SENTINEL-OPENAI-KEY-34567",
                "db_secret": "SENTINEL-DB-SECRET-45678",
                "service_token": "SENTINEL-SERVICE-TOKEN-56789",
                "nested_array_pw": "SENTINEL-NESTED-ARRAY-PW-67890",
                "token_val": "SENTINEL-TOKEN-VALUE-11111",
                "db_pw_val": "SENTINEL-DB-PW-VAL-22222",
                "refresh_tok_val": "SENTINEL-REFRESH-TOK-VAL-33333",
                "client_sec_val": "SENTINEL-CLIENT-SEC-VAL-44444",
                "db_pass_upper": "SENTINEL-DATABASE-PASSWORD-55555",
                "aws_dot_key": "SENTINEL-AWS-DOT-SECRET-66666",
            }

            # Build structured JSON payload containing aliases and benign keys
            payload_v085 = json.dumps({
                "verdict": "COMPROMISED: POISONED TRACER LEAKED",
                "app_config": {
                    "dbPassword": sentinels["db_pw"],
                    "db_password_value": sentinels["db_pw_val"],
                    "tokenValue": sentinels["token_val"],
                    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpublickeydata user@example.com",
                    "metrics": {
                        "token_count": 42,
                        "max_tokens": 512,
                        "total_tokens": 1024,
                    },
                },
                "email_service": {
                    "SMTP_PASSWORD": [sentinels["smtp_pw"], sentinels["nested_array_pw"]],
                    "clientSecretValue": sentinels["client_sec_val"],
                    "key_id": "key-id-public-safe",
                },
            })

            payload_v086 = json.dumps({
                "verdict": "CLEAN: Permission denied: not file owner",
                "ai_provider": {
                    "openaiApiKey": {
                        "value": sentinels["openai"],
                        "jwt_algorithm": "RS256",
                    },
                },
                "cloud": {
                    "DATABASE-PASSWORD": sentinels["db_pass_upper"],
                    "aws.secret.access.key": sentinels["aws_dot_key"],
                    "serviceAccessToken": sentinels["service_token"],
                    "refreshTokenValue": sentinels["refresh_tok_val"],
                    "database_secret": sentinels["db_secret"],
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                },
            })

            firedamp_085 = copy.deepcopy(self.mock_firedamp_v085)
            firedamp_085["target_response"] = payload_v085
            firedamp_085["reason"] = f"Verification reason with embedded JSON: {payload_v085}"

            firedamp_086 = copy.deepcopy(self.mock_firedamp_v086)
            firedamp_086["target_response"] = payload_v086
            firedamp_086["tracer_marker"] = f"Tracer with credentials: {payload_v086}"

            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                f"Permission denied: not file owner; batch error with dbPassword={sentinels['db_pw']} and serviceAccessToken={sentinels['service_token']}"
            )

            final_verif = copy.deepcopy(self.mock_final_verification)
            final_verif["vector_cleanup_note"] = (
                f"Final note: {json.dumps({'DATABASE-PASSWORD': sentinels['db_pass_upper'], 'aws.secret.access.key': sentinels['aws_dot_key']})}"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=firedamp_085,
                firedamp_v086=firedamp_086,
                reproduce_v086=rep_086,
                final_verification=final_verif,
            )

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIsInstance(manifest, dict)

            # Assert that NO sentinel survived in ANY published file
            for p in out_dir.iterdir():
                if p.is_file():
                    content = p.read_text(encoding="utf-8")
                    for s_name, s_val in sentinels.items():
                        self.assertNotIn(
                            s_val,
                            content,
                            f"Sensitive sentinel '{s_name}' leaked in {p.name}!",
                        )

            # Assert legitimate non-sensitive keys and metadata are preserved
            sanitized_085 = json.loads((out_dir / "sanitized-v085.json").read_text(encoding="utf-8"))
            resp_085 = json.loads(sanitized_085["target_response"])
            self.assertEqual(resp_085["app_config"]["dbPassword"], "[REDACTED_SECRET]")
            self.assertEqual(resp_085["app_config"]["db_password_value"], "[REDACTED_SECRET]")
            self.assertEqual(resp_085["app_config"]["tokenValue"], "[REDACTED_SECRET]")
            self.assertIn("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpublickeydata", resp_085["app_config"]["public_key"])
            self.assertEqual(resp_085["app_config"]["metrics"]["token_count"], 42)
            self.assertEqual(resp_085["app_config"]["metrics"]["max_tokens"], 512)
            self.assertEqual(resp_085["email_service"]["SMTP_PASSWORD"], "[REDACTED_SECRET]")
            self.assertEqual(resp_085["email_service"]["clientSecretValue"], "[REDACTED_SECRET]")
            self.assertEqual(resp_085["email_service"]["key_id"], "key-id-public-safe")

            sanitized_086 = json.loads((out_dir / "sanitized-v086.json").read_text(encoding="utf-8"))
            resp_086 = json.loads(sanitized_086["target_response"])
            self.assertEqual(resp_086["ai_provider"]["openaiApiKey"], "[REDACTED_SECRET]")
            self.assertEqual(resp_086["cloud"]["DATABASE-PASSWORD"], "[REDACTED_SECRET]")
            self.assertEqual(resp_086["cloud"]["aws.secret.access.key"], "[REDACTED_SECRET]")
            self.assertEqual(resp_086["cloud"]["serviceAccessToken"], "[REDACTED_SECRET]")
            self.assertEqual(resp_086["cloud"]["refreshTokenValue"], "[REDACTED_SECRET]")
            self.assertEqual(resp_086["cloud"]["database_secret"], "[REDACTED_SECRET]")
            self.assertEqual(
                resp_086["cloud"]["sha256"],
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            )

    def test_is_sensitive_key_name_component_aware_matching(self):
        """
        Verify robust component-aware normalization and sensitivity detection
        for all target credential names across camelCase, PascalCase, separators,
        and contextual qualifiers, while strictly preserving legitimate metadata.
        """
        sensitive_cases = [
            "dbPassword",
            "openaiApiKey",
            "serviceAccessToken",
            "tokenValue",
            "db_password_value",
            "refreshTokenValue",
            "clientSecretValue",
            "DATABASE-PASSWORD",
            "aws.secret.access.key",
            "password",
            "client_secret",
            "secret_key",
            "private_key",
            "access_token",
            "refresh-token",
            "api_key",
            "smtp_password",
            "database_secret",
            "public_key_password",
            "public_key_secret",
            "public_key_access_token",
            "public_key_private_key",
            "public_keys_client_secret",
            "publicKeyPassword",
            "publicKeySecret",
            "publicKeyAccessToken",
            "publicKeyPrivateKey",
            "publicKeysClientSecret",
            "PUBLIC-KEY-PASSWORD",
            "public.key.secret",
        ]
        non_sensitive_cases = [
            "public_key",
            "public_keys",
            "public_key_id",
            "client_public_key",
            "token_count",
            "max_tokens",
            "total_tokens",
            "prompt_tokens",
            "completion_tokens",
            "key_id",
            "jwt_algorithm",
            "sha256",
            "content_length",
            "verified_hash",
        ]
        for k in sensitive_cases:
            self.assertTrue(
                collect_evidence._is_sensitive_key_name(k),
                f"Expected '{k}' to be detected as sensitive",
            )
        for k in non_sensitive_cases:
            self.assertFalse(
                collect_evidence._is_sensitive_key_name(k),
                f"Expected '{k}' to be preserved as non-sensitive metadata",
            )

    def test_metadata_precedence_credential_combinations_e2e(self):
        """
        Verify metadata-exemption precedence:
        Legitimate metadata keys (public_key, public_keys, public_key_id, token_count,
        max_tokens, key_id, jwt_algorithm, sha256) are strictly preserved, while
        credential-bearing keys combining public_key terms with credentials (public_key_password,
        public_key_secret, public_key_access_token, public_key_private_key, public_keys_client_secret,
        publicKeyPassword, publicKeySecret, publicKeyAccessToken, publicKeyPrivateKey,
        publicKeysClientSecret, PUBLIC-KEY-PASSWORD, public.key.secret) are always redacted across
        both structured JSON and free-text fields in end-to-end evidence bundles.
        """
        json_payload = {
            "public_key": "PUBLIC_MATERIAL",
            "public_keys": ["PUBLIC_A", "PUBLIC_B"],
            "public_key_id": "KEY_IDENTIFIER",
            "token_count": 42,
            "max_tokens": 4096,
            "key_id": "IDENTIFIER",
            "jwt_algorithm": "RS256",
            "sha256": "EXPECTED_HASH",
            "public_key_password": "SENTINEL_1",
            "public_key_secret": "SENTINEL_2",
            "public_key_access_token": "SENTINEL_3",
            "public_key_private_key": "SENTINEL_4",
            "public_keys_client_secret": "SENTINEL_5",
            "publicKeyPassword": "SENTINEL_6",
            "nested_credentials": {
                "publicKeySecret": {"secret_token": "SENTINEL_7"},
                "publicKeyAccessToken": ["SENTINEL_8"],
                "publicKeyPrivateKey": "SENTINEL_9",
            },
            "publicKeysClientSecret": "SENTINEL_10",
            "PUBLIC-KEY-PASSWORD": "SENTINEL_11",
            "public.key.secret": "SENTINEL_12",
        }

        # 1. Direct structured JSON verification
        sanitized_node = collect_evidence._sanitize_json_node(json_payload)

        # Assert all metadata preserved
        self.assertEqual(sanitized_node["public_key"], "PUBLIC_MATERIAL")
        self.assertEqual(sanitized_node["public_keys"], ["PUBLIC_A", "PUBLIC_B"])
        self.assertEqual(sanitized_node["public_key_id"], "KEY_IDENTIFIER")
        self.assertEqual(sanitized_node["token_count"], 42)
        self.assertEqual(sanitized_node["max_tokens"], 4096)
        self.assertEqual(sanitized_node["key_id"], "IDENTIFIER")
        self.assertEqual(sanitized_node["jwt_algorithm"], "RS256")
        self.assertEqual(sanitized_node["sha256"], "EXPECTED_HASH")

        # Assert all credential keys redacted
        self.assertEqual(sanitized_node["public_key_password"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_key_secret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_key_access_token"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_key_private_key"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_keys_client_secret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["publicKeyPassword"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["nested_credentials"]["publicKeySecret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["nested_credentials"]["publicKeyAccessToken"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["nested_credentials"]["publicKeyPrivateKey"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["publicKeysClientSecret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["PUBLIC-KEY-PASSWORD"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public.key.secret"], "[REDACTED_SECRET]")

        # 2. End-to-end evidence bundle publication test
        sentinels = {f"s_{i}": f"SENTINEL_{i}" for i in range(1, 13)}

        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_pubkey_cred"

            payload_v085 = json.dumps(json_payload)

            firedamp_085 = copy.deepcopy(self.mock_firedamp_v085)
            firedamp_085["target_response"] = f"COMPROMISED: {payload_v085}"
            firedamp_085["reason"] = f"Reason text with embedded JSON: {payload_v085}"

            firedamp_086 = copy.deepcopy(self.mock_firedamp_v086)
            firedamp_086["target_response"] = f"CLEAN: Permission denied: not file owner; {payload_v085}"
            firedamp_086["tracer_marker"] = f"Tracer with free-text publicKeyPassword={sentinels['s_6']}"

            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                f"Permission denied: not file owner; batch error with public_key_password={sentinels['s_1']}"
            )

            final_verif = copy.deepcopy(self.mock_final_verification)
            final_verif["vector_cleanup_note"] = (
                f"Final note: {json.dumps({'publicKeysClientSecret': sentinels['s_10']})}"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=firedamp_085,
                firedamp_v086=firedamp_086,
                reproduce_v086=rep_086,
                final_verification=final_verif,
            )

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIsInstance(manifest, dict)

            # Assert that NO sentinel survived in ANY published bundle file
            for p in out_dir.iterdir():
                if p.is_file():
                    content = p.read_text(encoding="utf-8")
                    for s_name, s_val in sentinels.items():
                        self.assertNotIn(
                            s_val,
                            content,
                            f"Sensitive sentinel '{s_name}' ({s_val}) leaked in published {p.name}!",
                        )

            # Assert that legitimate metadata survived in sanitized artifacts
            sanitized_085_text = (out_dir / "sanitized-v085.json").read_text(encoding="utf-8")
            self.assertIn("PUBLIC_MATERIAL", sanitized_085_text)
            self.assertIn("PUBLIC_A", sanitized_085_text)
            self.assertIn("PUBLIC_B", sanitized_085_text)
            self.assertIn("KEY_IDENTIFIER", sanitized_085_text)
            self.assertIn("RS256", sanitized_085_text)
            self.assertIn("EXPECTED_HASH", sanitized_085_text)

    def test_metadata_exemption_precedence_and_public_key_credentials_e2e(self):
        """
        Verify metadata-exemption precedence:
        Legitimate metadata keys (public_key, public_keys, public_key_id, token_count,
        max_tokens, key_id, jwt_algorithm, sha256) are strictly preserved, while
        credential-bearing keys combining public_key terms with credentials (public_key_password,
        public_key_secret, public_key_access_token, public_key_private_key, public_keys_client_secret,
        publicKeyPassword, publicKeySecret, publicKeyAccessToken, publicKeyPrivateKey,
        publicKeysClientSecret, PUBLIC-KEY-PASSWORD, public.key.secret) are always redacted across
        both structured JSON and free-text fields in end-to-end evidence bundles.
        """
        # 1. Direct structured JSON verification
        json_payload = {
            "public_key": "PUBLIC_MATERIAL",
            "public_keys": ["PUBLIC_A", "PUBLIC_B"],
            "public_key_id": "KEY_IDENTIFIER",
            "token_count": 42,
            "max_tokens": 4096,
            "key_id": "IDENTIFIER",
            "jwt_algorithm": "RS256",
            "sha256": "EXPECTED_HASH",
            "public_key_password": "SENTINEL_1",
            "public_key_secret": "SENTINEL_2",
            "public_key_access_token": "SENTINEL_3",
            "public_key_private_key": "SENTINEL_4",
            "public_keys_client_secret": "SENTINEL_5",
            "publicKeyPassword": "SENTINEL_6",
            "nested_credentials": {
                "publicKeySecret": {"secret_token": "SENTINEL_7"},
                "publicKeyAccessToken": ["SENTINEL_8"],
                "publicKeyPrivateKey": "SENTINEL_9",
            },
            "publicKeysClientSecret": "SENTINEL_10",
            "PUBLIC-KEY-PASSWORD": "SENTINEL_11",
            "public.key.secret": "SENTINEL_12",
        }

        sanitized_node = collect_evidence._sanitize_json_node(json_payload)

        # Assert all metadata preserved
        self.assertEqual(sanitized_node["public_key"], "PUBLIC_MATERIAL")
        self.assertEqual(sanitized_node["public_keys"], ["PUBLIC_A", "PUBLIC_B"])
        self.assertEqual(sanitized_node["public_key_id"], "KEY_IDENTIFIER")
        self.assertEqual(sanitized_node["token_count"], 42)
        self.assertEqual(sanitized_node["max_tokens"], 4096)
        self.assertEqual(sanitized_node["key_id"], "IDENTIFIER")
        self.assertEqual(sanitized_node["jwt_algorithm"], "RS256")
        self.assertEqual(sanitized_node["sha256"], "EXPECTED_HASH")

        # Assert all credential keys redacted
        self.assertEqual(sanitized_node["public_key_password"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_key_secret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_key_access_token"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_key_private_key"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public_keys_client_secret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["publicKeyPassword"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["nested_credentials"]["publicKeySecret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["nested_credentials"]["publicKeyAccessToken"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["nested_credentials"]["publicKeyPrivateKey"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["publicKeysClientSecret"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["PUBLIC-KEY-PASSWORD"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized_node["public.key.secret"], "[REDACTED_SECRET]")

        # 2. End-to-end evidence bundle publication test
        sentinels = {f"s_{i}": f"SENTINEL_{i}" for i in range(1, 13)}

        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_pubkey_cred"

            payload_v085 = json.dumps(json_payload)

            firedamp_085 = copy.deepcopy(self.mock_firedamp_v085)
            firedamp_085["target_response"] = f"COMPROMISED: {payload_v085}"
            firedamp_085["reason"] = f"Reason text with embedded JSON: {payload_v085}"

            firedamp_086 = copy.deepcopy(self.mock_firedamp_v086)
            firedamp_086["target_response"] = f"CLEAN: Permission denied: not file owner; {payload_v085}"
            firedamp_086["tracer_marker"] = f"Tracer with free-text publicKeyPassword={sentinels['s_6']}"

            rep_086 = copy.deepcopy(self.mock_reproduce_v086)
            rep_086["batch_response"]["errors"][0]["error"] = (
                f"Permission denied: not file owner; batch error with public_key_password={sentinels['s_1']}"
            )

            final_verif = copy.deepcopy(self.mock_final_verification)
            final_verif["vector_cleanup_note"] = (
                f"Final note: {json.dumps({'publicKeysClientSecret': sentinels['s_10']})}"
            )

            self._write_raw_bundle(
                raw_dir,
                firedamp_v085=firedamp_085,
                firedamp_v086=firedamp_086,
                reproduce_v086=rep_086,
                final_verification=final_verif,
            )

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIsInstance(manifest, dict)

            # Assert that NO sentinel survived in ANY published bundle file
            for p in out_dir.iterdir():
                if p.is_file():
                    content = p.read_text(encoding="utf-8")
                    for s_name, s_val in sentinels.items():
                        self.assertNotIn(
                            s_val,
                            content,
                            f"Sensitive sentinel '{s_name}' ({s_val}) leaked in published {p.name}!",
                        )

            # Assert that legitimate metadata survived in sanitized artifacts
            sanitized_085_text = (out_dir / "sanitized-v085.json").read_text(encoding="utf-8")
            self.assertIn("PUBLIC_MATERIAL", sanitized_085_text)
            self.assertIn("PUBLIC_A", sanitized_085_text)
            self.assertIn("PUBLIC_B", sanitized_085_text)
            self.assertIn("KEY_IDENTIFIER", sanitized_085_text)
            self.assertIn("RS256", sanitized_085_text)
            self.assertIn("EXPECTED_HASH", sanitized_085_text)

    def test_raw_file_descriptor_fstat_rejects_non_regular_file(self):
        """
        Verify raw file ingestion uses fstat() on opened descriptor and
        refuses non-regular files (e.g. directories, pipes).
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_nonreg"
            self._write_raw_bundle(raw_dir)

            tampered_file = raw_dir / "firedamp-v085.json"
            tampered_file.unlink()
            tampered_file.mkdir()

            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("Refusing non-regular raw evidence file", str(ctx.exception))
            self.assertFalse(out_dir.exists())

    def test_raw_file_descriptor_read_failure_preserves_exception_without_double_close(self):
        """
        Verify raw file read failures preserve original exception and do not raise EBADF
        from double-closing the descriptor.
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_read_fail"
            self._write_raw_bundle(raw_dir)

            orig_open = open

            def mocked_open(file, *args, **kwargs):
                f = orig_open(file, *args, **kwargs)
                if isinstance(file, int):
                    def fail_read(*_a, **_kw):
                        raise IOError("Simulated physical sector read failure")
                    f.read = fail_read
                return f

            with patch("builtins.open", side_effect=mocked_open):
                with self.assertRaises(ValueError) as ctx:
                    sanitize_evidence_bundle(raw_dir, out_dir)
                self.assertIn("Simulated physical sector read failure", str(ctx.exception))
                self.assertNotIn("Bad file descriptor", str(ctx.exception))
            self.assertFalse(out_dir.exists())

    def test_publication_sets_mode_before_replace_and_atomic_swap_is_final(self):
        """
        Verify publication sets directory permissions to 0700 on staging directory
        BEFORE calling os.replace, and os.replace is the final directory operation.
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_pub_order"
            self._write_raw_bundle(raw_dir)

            call_log = []
            orig_chmod = os.chmod
            orig_replace = os.replace

            def track_chmod(path, mode):
                call_log.append(("chmod", str(path), mode))
                return orig_chmod(path, mode)

            def track_replace(src, dst):
                call_log.append(("replace", str(src), str(dst)))
                return orig_replace(src, dst)

            with patch("os.chmod", side_effect=track_chmod), patch("os.replace", side_effect=track_replace):
                manifest = sanitize_evidence_bundle(raw_dir, out_dir)
                self.assertIsInstance(manifest, dict)

            replace_calls = [c for c in call_log if c[0] == "replace"]
            self.assertEqual(len(replace_calls), 1)
            replace_idx = call_log.index(replace_calls[0])

            chmod_after_replace = [
                c for c in call_log[replace_idx + 1:]
                if c[0] == "chmod" and str(out_dir) in c[1]
            ]
            self.assertEqual(len(chmod_after_replace), 0, "os.chmod must not be called on output directory after os.replace")

            staging_src = replace_calls[0][1]
            chmod_before_replace = [
                c for c in call_log[:replace_idx]
                if c[0] == "chmod" and c[1] == staging_src and c[2] == 0o700
            ]
            self.assertTrue(len(chmod_before_replace) >= 1, "Staging directory must be chmod 0700 before replace")

    def test_manifest_provenance_notes_wording(self):
        """
        Verify manifest provenance notes explicitly distinguish in-memory SHA-256 byte binding,
        post-execution final-state disk consistency, and external cryptographic origin authentication.
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_provenance"
            self._write_raw_bundle(raw_dir)

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            provenance = manifest.get("provenance_notes", "")
            self.assertIn("cryptographically bind the exact in-memory bytes", provenance)
            self.assertIn("post-execution disk re-reading verifies final-state hash consistency", provenance)
            self.assertIn("does not prove the absence of transient external modifications", provenance)
            self.assertIn("does not establish external cryptographic origin authentication", provenance)

    def test_json_sanitizer_exceptions_propagate_without_silent_fallback(self):
        """
        Finding 2 Regression:
        JSON decoding failure falls through to free-text fallback, but any exception raised
        during JSON recursive sanitization, validation, or redaction propagates immediately
        and aborts bundle publication.
        """
        # 1. Verify JSON decode error DOES fall back to free-text scanner
        malformed_json_str = '{"incomplete_json": "value"'
        fallback_res = collect_evidence._sanitize_free_text(malformed_json_str)
        self.assertIsNotNone(fallback_res)
        self.assertIn('"incomplete_json": "value"', fallback_res)

        # 2. Verify an exception in _sanitize_json_node propagates and is NOT caught
        valid_json_str = '{"valid_key": "some_value"}'

        with patch.object(
            collect_evidence,
            "_sanitize_json_node",
            side_effect=RuntimeError("Sanitizer AST validation failure"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                collect_evidence._sanitize_free_text(valid_json_str)
            self.assertIn("Sanitizer AST validation failure", str(ctx.exception))

        # 3. Verify that in the full pipeline, an exception in _sanitize_json_node aborts publication
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_fail"
            rep_085 = copy.deepcopy(self.mock_reproduce_v085)
            rep_085["reason"] = '{"embedded": "valid_json_payload"}'
            self._write_raw_bundle(raw_dir, reproduce_v085=rep_085)

            with patch.object(
                collect_evidence,
                "_sanitize_json_node",
                side_effect=ValueError("Injected node schema violation"),
            ):
                with self.assertRaises(ValueError) as ctx:
                    sanitize_evidence_bundle(raw_dir, out_dir)
                self.assertIn("Injected node schema violation", str(ctx.exception))

            # Destination directory must NOT be published
            self.assertFalse(out_dir.exists())

    def test_true_atomic_directory_publication_and_failure_injection(self):
        """
        Finding 3 Regression:
        Publication uses a single directory-level atomic rename.
        Pre-existing non-empty destination directories are refused without modifying them.
        Failure immediately before or during publication never leaves a partial or mixed bundle.
        """
        # 1. Refuse pre-existing destination containing existing files
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "existing_dest"
            out_dir.mkdir(parents=True)
            unrelated_file = out_dir / "unrelated_user_data.txt"
            unrelated_file.write_text("DO NOT TOUCH THIS FILE", encoding="utf-8")
            self._write_raw_bundle(raw_dir)

            with self.assertRaises(ValueError) as ctx:
                sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("Refusing non-empty output directory", str(ctx.exception))
            self.assertEqual(unrelated_file.read_text(encoding="utf-8"), "DO NOT TOUCH THIS FILE")

        # 2. Failure immediately before publication: staging directory is cleaned up, destination never created
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "pre_pub_fail"
            self._write_raw_bundle(raw_dir)

            with patch.object(
                collect_evidence,
                "generate_bundle_readme",
                side_effect=RuntimeError("Failure right before manifest and staging"),
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    sanitize_evidence_bundle(raw_dir, out_dir)
                self.assertIn("Failure right before manifest", str(ctx.exception))

            self.assertFalse(out_dir.exists())

        # 3. Failure during publication (os.replace failure): raises RuntimeError, cleans staging, leaves target intact
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "pub_swap_fail"
            self._write_raw_bundle(raw_dir)

            with patch("os.replace", side_effect=OSError("Cross-device or disk swap failure")):
                with self.assertRaises(RuntimeError) as ctx:
                    sanitize_evidence_bundle(raw_dir, out_dir)
                self.assertIn("Atomic directory publication failed", str(ctx.exception))

            self.assertFalse(out_dir.exists())

    def test_raw_evidence_hash_bound_to_exact_parsed_bytes(self):
        """
        Finding 4 Regression:
        Manifest hashes correspond to the exact in-memory bytes read and parsed.
        Post-execution raw immutability checks verify disk state was not altered during processing.
        """
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp) / "bundle_integrity"
            self._write_raw_bundle(raw_dir)

            # Compute disk SHA-256 before call
            expected_disk_hashes = {
                fname: collect_evidence.sha256_file(raw_dir / fname)
                for fname in collect_evidence.REQUIRED_RAW_FILES
            }

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)

            # Assert manifest recorded hashes match exactly what was on disk and parsed
            for fname, info in manifest["raw_evidence_files"].items():
                self.assertEqual(
                    info["sha256"],
                    expected_disk_hashes[fname],
                    f"Recorded manifest hash for {fname} does not match exact disk hash!",
                )

            # Test anti-TOCTOU: tampering with disk after initial read fails closed
            with tempfile.TemporaryDirectory() as raw_tamper_tmp, tempfile.TemporaryDirectory() as out_tamper_tmp:
                raw_t_dir = Path(raw_tamper_tmp)
                out_t_dir = Path(out_tamper_tmp) / "bundle_tamper"
                self._write_raw_bundle(raw_t_dir)

                orig_sanitizer = collect_evidence.sanitize_firedamp_report

                def tamper_and_sanitize(*args, **kwargs):
                    # Tamper with the raw file on disk after initial snapshot read
                    (raw_t_dir / "firedamp-v085.json").write_text('{"TAMPERED": true}', encoding="utf-8")
                    return orig_sanitizer(*args, **kwargs)

                with patch.object(collect_evidence, "sanitize_firedamp_report", side_effect=tamper_and_sanitize):
                    with self.assertRaises(RuntimeError) as ctx:
                        sanitize_evidence_bundle(raw_t_dir, out_t_dir)
                    self.assertIn("INTEGRITY VIOLATION", str(ctx.exception))

                self.assertFalse(out_t_dir.exists())


class TestEvidenceIntegrityCollection(unittest.TestCase):
    """Verifies evidence collection integrity, simulation isolation, and fail-closed handling."""

    def test_live_mode_without_raw_dir_fails_closed(self):
        """Live mode without --raw-dir must fail closed with exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_argv = ["collect_evidence.py", "--mode", "live", "--output-dir", tmp_dir]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as ctx:
                    collect_evidence.main()
                self.assertEqual(ctx.exception.code, 1)
                output = mock_out.getvalue()
                self.assertIn("Live mode requires validated raw reports supplied via --raw-dir", output)
                self.assertIn("Aborting fail-closed", output)

    def test_auto_mode_with_raw_dir_fails_closed(self):
        """Auto mode with --raw-dir must fail closed requiring explicit --mode live."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_argv = ["collect_evidence.py", "--mode", "auto", "--raw-dir", tmp_dir]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as ctx:
                    collect_evidence.main()
                self.assertEqual(ctx.exception.code, 1)
                output = mock_out.getvalue()
                self.assertIn("Ingesting raw evidence via --raw-dir requires explicit --mode live", output)
                self.assertIn("Aborting fail-closed", output)

    def test_offline_mode_with_raw_dir_fails_closed(self):
        """Offline mode with --raw-dir must fail closed with exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_argv = ["collect_evidence.py", "--mode", "offline", "--raw-dir", tmp_dir]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with self.assertRaises(SystemExit) as ctx:
                    collect_evidence.main()
                self.assertEqual(ctx.exception.code, 1)
                output = mock_out.getvalue()
                self.assertIn("Ingesting raw evidence via --raw-dir requires explicit --mode live", output)
                self.assertIn("Aborting fail-closed", output)

    def test_live_mode_with_raw_dir_succeeds(self):
        """Live mode with valid --raw-dir successfully ingests, validates, and sanitizes reports."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            helper = TestEvidenceSanitizer()
            helper.setUp()
            helper._write_raw_bundle(raw_dir)

            test_argv = ["collect_evidence.py", "--mode", "live", "--raw-dir", raw_tmp, "--output-dir", out_tmp]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO):
                collect_evidence.main()

            out_path = Path(out_tmp)
            self.assertTrue((out_path / "manifest.json").exists())
            self.assertTrue((out_path / "README.md").exists())
            self.assertTrue((out_path / "sanitized-reset-v085.json").exists())
            self.assertTrue((out_path / "sanitized-final-fixture-verification.json").exists())

    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.check_docker_daemon")
    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.run_offline_simulations")
    def test_auto_mode_without_raw_dir_never_checks_docker_and_generates_no_live_verdicts(
        self, mock_sim, mock_docker_check
    ):
        """Auto mode without --raw-dir must never check Docker and must not generate live verdicts."""
        mock_sim.return_value = {
            "tests_run": 5,
            "was_successful": True,
            "failures": 0,
            "errors": 0,
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_argv = ["collect_evidence.py", "--mode", "auto", "--output-dir", tmp_dir]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO):
                collect_evidence.main()

            mock_docker_check.assert_not_called()

            out_path = Path(tmp_dir)
            env_data = json.loads((out_path / "environment.json").read_text(encoding="utf-8"))
            self.assertFalse(env_data["live_execution"])
            self.assertEqual(env_data["execution_mode"], "offline_simulation")
            self.assertFalse(env_data["docker"]["daemon"]["accessible"])
            self.assertEqual(env_data["docker"]["cli_version"], "NOT_CHECKED")
            self.assertEqual(env_data["docker"]["compose_version"], "NOT_CHECKED")

            v085 = json.loads((out_path / "vulnerable-v085.json").read_text(encoding="utf-8"))
            self.assertEqual(v085["target_execution_status"], "NOT_RUN")
            self.assertEqual(v085["observed_verdict"], "NOT_RUN")
            self.assertFalse(v085["observed_exploitation"])
            self.assertFalse(v085["live_execution"])

            v086 = json.loads((out_path / "patched-v086.json").read_text(encoding="utf-8"))
            self.assertEqual(v086["target_execution_status"], "NOT_RUN")
            self.assertEqual(v086["observed_verdict"], "NOT_RUN")
            self.assertFalse(v086["live_execution"])

            evidence = json.loads((out_path / "evidence.json").read_text(encoding="utf-8"))
            self.assertFalse(evidence["live_execution"])
            self.assertEqual(evidence["target_verdicts"]["v0.8.5"]["execution_status"], "NOT_RUN")
            self.assertEqual(evidence["target_verdicts"]["v0.8.5"]["observed_verdict"], "NOT_RUN")
            self.assertEqual(evidence["target_verdicts"]["v0.8.6"]["execution_status"], "NOT_RUN")
            self.assertEqual(evidence["target_verdicts"]["v0.8.6"]["observed_verdict"], "NOT_RUN")

    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.run_offline_simulations")
    def test_offline_mode_explicitly_records_targets_not_executed(self, mock_sim):
        """Offline mode explicitly records that targets were not executed and no real exploitation observed."""
        mock_sim.return_value = {
            "tests_run": 5,
            "was_successful": True,
            "failures": 0,
            "errors": 0,
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_argv = ["collect_evidence.py", "--mode", "offline", "--output-dir", tmp_dir]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO):
                collect_evidence.main()

            out_path = Path(tmp_dir)

            for target_file in ["vulnerable-v085.json", "patched-v086.json"]:
                data = json.loads((out_path / target_file).read_text(encoding="utf-8"))
                self.assertEqual(data["target_execution_status"], "NOT_RUN")
                self.assertEqual(data["observed_verdict"], "NOT_RUN")
                self.assertFalse(data["observed_exploitation"])
                self.assertFalse(data["tracer_found_in_alice_indexed_content"])
                self.assertIsNone(data["http_status"])
                self.assertIsNone(data["post_readback_sha256"])

            for probe_file in ["firedamp-v085.json", "firedamp-v086.json"]:
                pdata = json.loads((out_path / probe_file).read_text(encoding="utf-8"))
                self.assertEqual(pdata["target_execution_status"], "NOT_RUN")
                self.assertEqual(pdata["probe_status"], "NOT_RUN")
                self.assertFalse(pdata["pre_write_gate_passed"])
                self.assertFalse(pdata["scan_registry_verified"])

            setup_alice = json.loads((out_path / "setup-alice.json").read_text(encoding="utf-8"))
            self.assertEqual(setup_alice["target_execution_status"], "NOT_RUN")
            setup_bob = json.loads((out_path / "setup-bob.json").read_text(encoding="utf-8"))
            self.assertEqual(setup_bob["target_execution_status"], "NOT_RUN")

    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.run_offline_simulations")
    def test_offline_mode_does_not_report_successful_cleanup(self, mock_sim):
        """Offline mode does not claim successful cleanup when no resources were provisioned."""
        mock_sim.return_value = {
            "tests_run": 5,
            "was_successful": True,
            "failures": 0,
            "errors": 0,
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_argv = ["collect_evidence.py", "--mode", "offline", "--output-dir", tmp_dir]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO):
                collect_evidence.main()

            out_path = Path(tmp_dir)
            cleanup_data = json.loads((out_path / "cleanup.json").read_text(encoding="utf-8"))
            self.assertEqual(cleanup_data["status"], "NOT_RUN")
            self.assertEqual(cleanup_data["actual_docker_removal"], "NOT_RUN")
            self.assertEqual(cleanup_data["docker_cleanup_status"], "NOT_RUN")
            self.assertEqual(cleanup_data["unit_test_verification"], "NOT_RUN_BY_COLLECTOR")
            self.assertEqual(cleanup_data["shell_syntax_validation"], "NOT_RUN_BY_COLLECTOR")
            self.assertNotIn("PASSED", cleanup_data["unit_test_verification"])
            self.assertNotIn("PASSED", cleanup_data["shell_syntax_validation"])
            self.assertNotIn("SUCCESS", cleanup_data["status"])

            summary_content = (out_path / "summary.md").read_text(encoding="utf-8")
            self.assertNotIn("Shell Script Syntax Validation:** `PASSED`", summary_content)
            self.assertNotIn("Fail-Closed Adapter Deletion:** `PASSED`", summary_content)
            self.assertIn("Shell Script Syntax Validation:** `NOT_RUN_BY_COLLECTOR`", summary_content)
            self.assertIn("Fail-Closed Adapter Deletion:** `NOT_RUN_BY_COLLECTOR`", summary_content)

            firedamp_v085 = json.loads((out_path / "firedamp-v085.json").read_text(encoding="utf-8"))
            self.assertIn("NOT_RUN", firedamp_v085["cleanup_status"])
            self.assertNotIn("SUCCESSFUL", firedamp_v085["cleanup_status"])


if __name__ == "__main__":
    unittest.main()
