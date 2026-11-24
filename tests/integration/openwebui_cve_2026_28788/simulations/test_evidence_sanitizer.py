#!/usr/bin/env python3
"""
Unit tests for CVE-2026-28788 Evidence Sanitization and Bundling Pipeline.
"""

import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from tests.integration.openwebui_cve_2026_28788.scripts import collect_evidence
from tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence import (
    REQUIRED_RAW_FILES,
    PINNED_IMAGE_DIGESTS,
    FIXTURE_BASELINE,
    sanitize_firedamp_report,
    sanitize_reproduce_report,
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

            (raw_dir / "firedamp-v085.json").write_text(json.dumps(self.mock_firedamp_v085, indent=2))
            (raw_dir / "firedamp-v086.json").write_text(json.dumps(self.mock_firedamp_v086, indent=2))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps(self.mock_reproduce_v085, indent=2))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps(self.mock_reproduce_v086, indent=2))

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIsInstance(manifest, dict)
            self.assertEqual(manifest["cve_id"], "CVE-2026-28788")

            expected_files = [
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
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

    def test_acceptance_of_genuine_dynamic_reports(self):
        """Dynamic reports with arbitrary content hashes (not fixed historical hashes) are ingested securely."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            (raw_dir / "firedamp-v085.json").write_text(json.dumps(self.mock_firedamp_v085, indent=2))
            (raw_dir / "firedamp-v086.json").write_text(json.dumps(self.mock_firedamp_v086, indent=2))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps(self.mock_reproduce_v085, indent=2))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps(self.mock_reproduce_v086, indent=2))

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
            (raw_dir / "firedamp-v085.json").write_text("{malformed json")
            (raw_dir / "firedamp-v086.json").write_text(json.dumps(self.mock_firedamp_v086, indent=2))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps(self.mock_reproduce_v085, indent=2))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps(self.mock_reproduce_v086, indent=2))
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
            )

        bad_reproduce_v085 = copy.deepcopy(self.mock_reproduce_v085)
        bad_reproduce_v085["verdict"] = "PATCHED_CONFIRMED"
        with self.assertRaises(ValueError):
            validate_raw_reports(
                self.mock_firedamp_v085,
                self.mock_firedamp_v086,
                bad_reproduce_v085,
                self.mock_reproduce_v086,
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
            )
        self.assertIn("per-file ownership rejection", str(ctx.exception))

    def test_manifest_records_actual_calculated_raw_hashes(self):
        """Manifest contains calculated raw hashes, provenance notes, and image digests."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            (raw_dir / "firedamp-v085.json").write_text(json.dumps(self.mock_firedamp_v085, indent=2))
            (raw_dir / "firedamp-v086.json").write_text(json.dumps(self.mock_firedamp_v086, indent=2))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps(self.mock_reproduce_v085, indent=2))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps(self.mock_reproduce_v086, indent=2))

            manifest = sanitize_evidence_bundle(raw_dir, out_dir)
            self.assertIn("provenance_notes", manifest)
            self.assertIn("Collector-computed hashes", manifest["provenance_notes"])
            self.assertEqual(manifest["target_images"], PINNED_IMAGE_DIGESTS)
            self.assertEqual(manifest["fixture_baseline"], FIXTURE_BASELINE)
            self.assertFalse(manifest["fixture_reset_verification"]["v0.8.5"]["machine_validated_artifact"])
            self.assertTrue(manifest["fixture_reset_verification"]["v0.8.6"]["machine_validated_artifact"])
            for fname in REQUIRED_RAW_FILES:
                self.assertEqual(manifest["raw_evidence_files"][fname]["sha256"], sha256_file(raw_dir / fname))
                self.assertTrue(manifest["raw_evidence_files"][fname]["verified"])

    def test_raw_files_remain_byte_for_byte_unchanged(self):
        """Sanitizer verifies byte-for-byte immutability of raw files before and after processing."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            (raw_dir / "firedamp-v085.json").write_text(json.dumps(self.mock_firedamp_v085, indent=2))
            (raw_dir / "firedamp-v086.json").write_text(json.dumps(self.mock_firedamp_v086, indent=2))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps(self.mock_reproduce_v085, indent=2))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps(self.mock_reproduce_v086, indent=2))

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
        custom_firedamp["leaked_canaries"] = ["CANARY-CUSTOM-TEST-XYZ-123"]
        custom_reproduce = copy.deepcopy(self.mock_reproduce_v085)
        custom_reproduce["post_readback_sha256"] = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

        readme = generate_bundle_readme(
            custom_firedamp,
            self.mock_firedamp_v086,
            custom_reproduce,
            self.mock_reproduce_v086,
        )
        self.assertIn("CANARY-CUSTOM-TEST-XYZ-123", readme)
        self.assertIn("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", readme)
        self.assertIn("--url http://127.0.0.1:13085 --target-name v085 --output /tmp/setup-v085.json", readme)
        self.assertIn("--url http://127.0.0.1:13086 --target-name v086 --output /tmp/setup-v086.json", readme)
        self.assertNotIn("--target v085", readme)

    def test_sanitized_files_contain_no_credentials_or_internal_uuids(self):
        """Sanitized outputs contain role-based placeholders and no private user/file UUIDs."""
        with tempfile.TemporaryDirectory() as raw_tmp, tempfile.TemporaryDirectory() as out_tmp:
            raw_dir = Path(raw_tmp)
            out_dir = Path(out_tmp)
            (raw_dir / "firedamp-v085.json").write_text(json.dumps(self.mock_firedamp_v085, indent=2))
            (raw_dir / "firedamp-v086.json").write_text(json.dumps(self.mock_firedamp_v086, indent=2))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps(self.mock_reproduce_v085, indent=2))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps(self.mock_reproduce_v086, indent=2))

            sanitize_evidence_bundle(raw_dir, out_dir)
            for fname in [
                "sanitized-v085.json",
                "sanitized-v086.json",
                "sanitized-reproduce-v085.json",
                "sanitized-reproduce-v086.json",
            ]:
                content = (out_dir / fname).read_text(encoding="utf-8")
                self.assertNotIn("ffffffff-0000-0000-0000-000000000085", content)
                self.assertNotIn("aaaaaaaa-0000-0000-0000-000000000085", content)
                self.assertNotIn("bbbbbbbb-0000-0000-0000-000000000085", content)
                self.assertNotIn("ffffffff-0000-0000-0000-000000000086", content)


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
            (raw_dir / "firedamp-v085.json").write_text(json.dumps(TestEvidenceSanitizer().mock_firedamp_v085 if hasattr(self, "mock_firedamp_v085") else {
                "cve_id": "CVE-2026-28788", "run_id": "run-1", "target_url": "http://127.0.0.1:13085",
                "target_file_id": "file-1", "severity": "direct_leak", "target_response": "COMPROMISED",
                "leaked_canaries": ["CANARY-1"], "is_vulnerable": True, "is_clean": False, "is_inconclusive": False,
            }))
            (raw_dir / "firedamp-v086.json").write_text(json.dumps({
                "cve_id": "CVE-2026-28788", "run_id": "run-2", "target_url": "http://127.0.0.1:13086",
                "target_file_id": "file-2", "severity": "none", "target_response": "CLEAN: Permission denied: not file owner",
                "leaked_canaries": [], "is_vulnerable": False, "is_clean": True, "is_inconclusive": False,
            }))
            (raw_dir / "reproduce-v085.json").write_text(json.dumps({
                "verdict": "VULNERABLE_CONFIRMED", "reason": "Overwritten", "target_url": "http://127.0.0.1:13085",
                "disposable_file_id": "file-1", "kb_id": "kb-1", "alice_user_id": "u1", "bob_user_id": "u2",
                "tracer_marker": "marker", "tracer_found_in_readback": True, "http_status": 200,
                "batch_response": {"results": [{"file_id": "file-1", "status": "completed"}], "errors": []},
                "baseline_sha256": FIXTURE_BASELINE["sha256"],
                "post_readback_sha256": "dc53bc65a0b06571578f0b6dcc6d92a989a5706ccc5c74d3eb1422d1caf6d232",
            }))
            (raw_dir / "reproduce-v086.json").write_text(json.dumps({
                "verdict": "PATCHED_CONFIRMED", "reason": "Protected", "target_url": "http://127.0.0.1:13086",
                "disposable_file_id": "file-2", "kb_id": "kb-2", "alice_user_id": "u3", "bob_user_id": "u4",
                "tracer_marker": "marker", "tracer_found_in_readback": False, "http_status": 200,
                "batch_response": {"results": [], "errors": [{"file_id": "file-2", "status": "failed", "error": "Permission denied: not file owner"}]},
                "baseline_sha256": FIXTURE_BASELINE["sha256"],
                "post_readback_sha256": FIXTURE_BASELINE["sha256"],
            }))

            test_argv = ["collect_evidence.py", "--mode", "live", "--raw-dir", raw_tmp, "--output-dir", out_tmp]
            with patch.object(sys, "argv", test_argv), patch("sys.stdout", new_callable=io.StringIO):
                collect_evidence.main()

            out_path = Path(out_tmp)
            self.assertTrue((out_path / "manifest.json").exists())
            self.assertTrue((out_path / "README.md").exists())

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
