#!/usr/bin/env python3
"""Tests for truthful, fail-closed fixture reset behavior."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

lab_scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
if str(lab_scripts_dir) not in sys.path:
    sys.path.insert(0, str(lab_scripts_dir))

import reset_fixture  # noqa: E402


class TestResetFixture(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.fixtures_dir = self.tmp / "fixtures"
        self.fixtures_dir.mkdir()
        self.sample_content = (
            "CONFIDENTIAL QUARTERLY ASSET LEDGER\n"
            "OWNER: Alice\n"
            "PROJECT: Project Firedamp Mine Safety Audit\n"
            "CANARY TOKEN: CANARY-ALICE-VAULT-99887766-ORIGINAL\n"
            "CLASSIFICATION: TOP SECRET RESTRICTED TO TENANT ALICE\n"
            "This file contains sensitive operational telemetry and canary values for tenant isolation verification.\n"
        )
        self.sample_hash = hashlib.sha256(self.sample_content.encode("utf-8")).hexdigest()
        (self.fixtures_dir / "alice_original.txt").write_text(self.sample_content, encoding="utf-8")
        self.setup_file = self.tmp / "setup-test.json"
        self.setup_data = {
            "base_url": "http://127.0.0.1:13085",
            "lab_identity": {"name": "firedamp-cve-2026-28788", "schema_version": 1, "expected_version": "0.8.5"},
            "alice": {"user_id": "alice-uid-123", "token": "mock-alice-tok"},
            "bob": {"user_id": "bob-uid-456", "token": "mock-bob-tok"},
            "knowledge_base": {"id": "kb-uuid-789", "name": "Alice Shared Knowledge"},
            "disposable_file": {
                "id": "file-uuid-456",
                "filename": "alice_disposable.txt",
                "original_content_length": len(self.sample_content),
                "original_content_sha256": self.sample_hash,
            },
        }
        self.setup_file.write_text(json.dumps(self.setup_data), encoding="utf-8")
        os.chmod(self.setup_file, 0o600)
        self.preflight = {
            "version": "0.8.5",
            "file_id": "file-uuid-456",
            "kb_id": "kb-uuid-789",
            "alice_user_id": "alice-uid-123",
            "bob_user_id": "bob-uid-456",
            "content_sha256": self.sample_hash,
            "baseline_verified": False,
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def _membership(self, ids):
        return {"status_code": 200, "data": {"items": [{"id": item} for item in ids], "total": len(ids)}, "error": None}

    def _base_success_calls(self, other_ids=None, *, query=None):
        other_ids = other_ids or []
        return [
            self._membership(list(other_ids) + ["file-uuid-456"]),  # before membership
            {"status_code": 200, "data": {"status": True}, "error": None},  # targeted remove
            {"status_code": 200, "data": {"status": True}, "error": None},  # relink
            {"status_code": 200, "data": {"content": self.sample_content}, "error": None},  # update
            {"status_code": 200, "data": {"content": self.sample_content}, "error": None},  # content readback
            {"status_code": 200, "data": {"id": "file-uuid-456", "user_id": "alice-uid-123"}, "error": None},  # metadata
            self._membership(list(other_ids) + ["file-uuid-456"]),  # after membership
            query if query is not None else {"status_code": 200, "data": {"documents": [[]], "metadatas": [[]]}, "error": None},
        ]

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_restores_content_and_membership_but_does_not_claim_vector_verification(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        mock_http.side_effect = self._base_success_calls(other_ids=["other-file-1", "other-file-2"])

        result = reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertEqual(result["status"], "RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED")
        self.assertEqual(result["sha256"], self.sample_hash)
        self.assertEqual(result["owner_user_id"], "alice-uid-123")
        self.assertEqual(result["content_length"], len(self.sample_content))
        self.assertTrue(result["verified_owner"])
        self.assertTrue(result["verified_hash"])
        self.assertTrue(result["verified_kb_membership"])
        self.assertFalse(result["verified_vector_cleanup"])
        self.assertEqual(result["preserved_other_file_count"], 2)
        mock_preflight.assert_called_once()

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_fails_closed_when_initial_membership_lookup_fails(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        mock_http.return_value = {"status_code": 503, "data": None, "error": "unavailable"}
        with self.assertRaises(RuntimeError):
            reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertEqual(mock_http.call_count, 1)

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_other_file_preservation_failure_raises(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        calls = self._base_success_calls(other_ids=["other-file-1"])
        calls[6] = self._membership(["file-uuid-456"])
        mock_http.side_effect = calls
        with self.assertRaises(RuntimeError) as ctx:
            reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertIn("Preservation failure", str(ctx.exception))

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_positive_attacker_marker_in_top_k_is_failure(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        calls = self._base_success_calls()
        calls[7] = {
            "status_code": 200,
            "data": {
                "documents": [["POISONED EXPLOIT_TRACER_CVE_2026_28788 CONFIRMED"]],
                "metadatas": [[{"file_id": "file-uuid-456"}]],
            },
            "error": None,
        }
        mock_http.side_effect = calls
        with self.assertRaises(RuntimeError) as ctx:
            reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertIn("Vector cleanup failure", str(ctx.exception))

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_query_failure_is_reported_as_unverified_not_verified(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        calls = self._base_success_calls(query={"status_code": 503, "data": None, "error": "unavailable"})
        mock_http.side_effect = calls
        result = reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertFalse(result["verified_vector_cleanup"])
        self.assertEqual(result["vector_cleanup_verification"], "QUERY_FAILED_NOT_EXHAUSTIVE")

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_hash_mismatch_fails_closed(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        calls = self._base_success_calls()
        calls[4] = {"status_code": 200, "data": {"content": "POISONED_CONTENT"}, "error": None}
        mock_http.side_effect = calls
        with self.assertRaises(RuntimeError) as ctx:
            reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertIn("Restoration integrity check failed", str(ctx.exception))

    @patch("reset_fixture.verify_setup_target")
    @patch("reset_fixture.http_request")
    def test_reset_owner_mismatch_fails_closed(self, mock_http, mock_preflight):
        mock_preflight.return_value = self.preflight
        calls = self._base_success_calls()
        calls[5] = {"status_code": 200, "data": {"id": "file-uuid-456", "user_id": "attacker-bob-uid"}, "error": None}
        mock_http.side_effect = calls
        with self.assertRaises(RuntimeError) as ctx:
            reset_fixture.reset_fixture(str(self.setup_file), fixtures_dir=self.fixtures_dir)
        self.assertIn("Ownership mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
