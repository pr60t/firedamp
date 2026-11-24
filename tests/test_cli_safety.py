"""Regression tests for scan-scoped disposable provisioning and cleanup."""

import hashlib
import unittest
from unittest.mock import MagicMock, patch

from adapters.base import UserSession
from cli import _cleanup_scan_disposables, _register_newly_seeded_disposables, run_scan_flow
from core.engine import LeakSeverity, ProbeResult
from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY


class TestCLIDisposableLifecycle(unittest.TestCase):
    def setUp(self):
        _TRUSTED_SCAN_REGISTRY.clear()
        self.run_id = "scan-unit-test-123"
        self.session = UserSession(
            username="alice",
            role="owner",
            token="alice-token",
            headers={"Authorization": "Bearer alice-token"},
            metadata={
                "user_id": "alice-user-id",
                "run_id": self.run_id,
                "file_ids": ["preexisting-file", "new-file"],
                "knowledge_ids": ["kb-1"],
                "disposable_file_ids": [],
            },
        )
        self.adapter = MagicMock()
        self.adapter.get_authenticated_user_id.return_value = "alice-user-id"
        self.adapter.get_file_metadata.return_value = {
            "id": "new-file", "user_id": "alice-user-id", "filename": "decoy.md"
        }
        self.adapter.read_file_content.return_value = "scan-created disposable baseline"
        self.adapter.get_accessible_knowledge_bases.return_value = ["kb-1"]
        self.adapter.get_knowledge_base_files.return_value = ["new-file"]
        self.adapter.delete_file.return_value = True

    def tearDown(self):
        _TRUSTED_SCAN_REGISTRY.clear()

    def test_only_new_server_verified_file_is_registered_and_kept_for_read_side_probes(self):
        before = ["preexisting-file"]
        registered = _register_newly_seeded_disposables(
            self.adapter, "http://mock", self.session, before, self.run_id
        )
        self.assertEqual(registered, ["new-file"])
        self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_registered(self.run_id, "new-file", "alice"))
        self.assertEqual(self.session.metadata["file_ids"], ["preexisting-file", "new-file"])
        self.assertEqual(self.session.metadata["disposable_file_ids"], ["new-file"])
        record = _TRUSTED_SCAN_REGISTRY.get_metadata(self.run_id, "new-file", "alice")
        self.assertEqual(
            record["baseline_sha256"],
            hashlib.sha256(b"scan-created disposable baseline").hexdigest(),
        )

    def test_wrong_server_owner_does_not_register_or_promote_file(self):
        self.adapter.get_file_metadata.return_value = {
            "id": "new-file", "user_id": "someone-else", "filename": "decoy.md"
        }
        registered = _register_newly_seeded_disposables(
            self.adapter, "http://mock", self.session, ["preexisting-file"], self.run_id
        )
        self.assertEqual(registered, [])
        self.assertFalse(_TRUSTED_SCAN_REGISTRY.is_registered(self.run_id, "new-file", "alice"))
        self.assertEqual(self.session.metadata["file_ids"], ["preexisting-file", "new-file"])
        self.assertEqual(self.session.metadata["disposable_file_ids"], [])

    def test_cleanup_rechecks_owner_before_deleting_registered_disposable(self):
        _TRUSTED_SCAN_REGISTRY.register(
            self.run_id,
            "new-file",
            "alice",
            metadata={"baseline_sha256": hashlib.sha256(b"x").hexdigest()},
        )
        self.session.metadata["disposable_file_ids"] = ["new-file"]
        _cleanup_scan_disposables(self.adapter, "http://mock", self.session, self.run_id)
        self.adapter.get_authenticated_user_id.assert_called_once_with("http://mock", self.session)
        self.adapter.get_file_metadata.assert_called_once_with("http://mock", self.session, "new-file")
        self.adapter.delete_file.assert_called_once_with("http://mock", self.session, "new-file")
        self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_cleaned_up(self.run_id, "new-file", "alice"))
        self.assertEqual(self.session.metadata["disposable_file_ids"], [])

    def test_cleanup_does_not_delete_when_owner_cannot_be_reverified(self):
        _TRUSTED_SCAN_REGISTRY.register(self.run_id, "new-file", "alice")
        self.session.metadata["disposable_file_ids"] = ["new-file"]
        self.adapter.get_file_metadata.return_value = {
            "id": "new-file", "user_id": "foreign-user"
        }
        _cleanup_scan_disposables(self.adapter, "http://mock", self.session, self.run_id)
        self.adapter.delete_file.assert_not_called()
        self.assertEqual(self.session.metadata["disposable_file_ids"], ["new-file"])
        self.assertNotIn("new-file", self.session.metadata["file_ids"])

    @patch("cli.reporter")
    @patch("probes.cves.run_cve_suite")
    def test_cli_inconclusive_cve_probe_never_logs_passed(self, mock_cve_suite, mock_reporter):
        """Verify that an inconclusive CVE probe result produces an active notice and never Passed."""
        mock_cve_suite.return_value = [
            ProbeResult(
                probe_id="p1",
                probe_prompt="Test CVE",
                probe_category="cve_regression:CVE-2026-44560",
                target_response="INCONCLUSIVE: Missing target file",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
            )
        ]
        ret = run_scan_flow(
            target="openwebui",
            suite="cve-regression",
            dry_run=True,
        )
        self.assertEqual(ret, 0)
        for call_args in mock_reporter.log_success.call_args_list:
            arg = str(call_args[0][0])
            self.assertNotIn("Passed CVE probe", arg)
        active_messages = [str(call_args[0][0]) for call_args in mock_reporter.log_active.call_args_list]
        self.assertTrue(any("Inconclusive CVE probe" in msg for msg in active_messages))

    @patch("cli.reporter")
    @patch("probes.scenarios.write_poisoning.run_write_poisoning_scenarios")
    def test_cli_inconclusive_write_poisoning_scenario_never_logs_passed(self, mock_scenarios, mock_reporter):
        """Verify that an inconclusive scenario result produces an active notice and never Passed."""
        mock_scenarios.return_value = [
            ProbeResult(
                probe_id="p2",
                probe_prompt="Test Write Poisoning",
                probe_category="write_poisoning:file_overwrite",
                target_response="INCONCLUSIVE: No matching knowledge base",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
            )
        ]
        ret = run_scan_flow(
            target="openwebui",
            scenario="write-poisoning",
            dry_run=True,
        )
        self.assertEqual(ret, 0)
        for call_args in mock_reporter.log_success.call_args_list:
            arg = str(call_args[0][0])
            self.assertNotIn("Passed scenario", arg)
        active_messages = [str(call_args[0][0]) for call_args in mock_reporter.log_active.call_args_list]
        self.assertTrue(any("Inconclusive scenario" in msg for msg in active_messages))


if __name__ == "__main__":
    unittest.main()
