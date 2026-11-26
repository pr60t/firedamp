#!/usr/bin/env python3
"""
Regression tests for post-release security hardening:
- Live credential configuration and secret redaction (Section 3)
- Adapter selection and fail-closed error handling (Section 4)
- Probe result status taxonomy: CLEAN, COMPROMISED, INCONCLUSIVE, SKIPPED (Section 5)
- HTTPS enforcement for non-loopback live targets and redirect refusal (Section 10)
"""

import io
import json
import logging
import os
import unittest
from unittest.mock import MagicMock, patch

from adapters import ADAPTER_REGISTRY, get_adapter
from adapters.openwebui import OpenWebUIAdapter
from core.engine import LeakSeverity, ProbeResult, ProbeStatus, sanitize_sensitive_text
from core.policy import FiredampPolicy
from core.reporter import FiredampReporter
from core.target import RemoteTargetManager, validate_target_url
import cli


class TestCredentialSecurity(unittest.TestCase):
    """Section 3: Credential configuration, validation before network calls, and redaction."""

    def test_no_hardcoded_passwords_in_cli_source(self):
        with open(cli.__file__, "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("AegisPassword!123", src)
        self.assertNotIn("BobPassword!456", src)

    @patch.dict(os.environ, {}, clear=True)
    @patch("cli.RemoteTargetManager")
    @patch("cli.DockerTargetManager")
    def test_missing_alice_credentials_refused_without_network_or_docker(self, mock_docker, mock_remote):
        ret = cli.run_scan_flow(target="openwebui", target_url="https://target.example.com", dry_run=False)
        self.assertEqual(ret, 1)
        mock_remote.assert_not_called()
        mock_docker.assert_not_called()

    @patch.dict(os.environ, {"FIREDAMP_ALICE_PASSWORD": "ValidAlicePassword!1"}, clear=True)
    @patch("cli.RemoteTargetManager")
    def test_missing_bob_credentials_refused_without_network(self, mock_remote):
        ret = cli.run_scan_flow(target="openwebui", target_url="https://target.example.com", dry_run=False)
        self.assertEqual(ret, 1)
        mock_remote.assert_not_called()

    @patch.dict(
        os.environ,
        {"FIREDAMP_ALICE_PASSWORD": "   ", "FIREDAMP_BOB_PASSWORD": "BobSecretValue!2"},
        clear=True,
    )
    @patch("cli.RemoteTargetManager")
    def test_empty_password_refused_before_network(self, mock_remote):
        with self.assertRaises(ValueError):
            cli.resolve_live_credentials()
        ret = cli.run_scan_flow(target="openwebui", target_url="https://target.example.com", dry_run=False)
        self.assertEqual(ret, 1)
        mock_remote.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "FIREDAMP_ALICE_USERNAME": "same_user",
            "FIREDAMP_ALICE_PASSWORD": "Pass1!Secret",
            "FIREDAMP_BOB_USERNAME": "same_user",
            "FIREDAMP_BOB_PASSWORD": "Pass2!Secret",
        },
        clear=True,
    )
    def test_identical_alice_and_bob_usernames_rejected(self):
        with self.assertRaises(ValueError):
            cli.resolve_live_credentials()

    @patch.dict(os.environ, {}, clear=True)
    def test_dry_run_works_without_live_credentials(self):
        ret = cli.run_scan_flow(target="openwebui", canaries=1, dry_run=True)
        self.assertEqual(ret, 0)

    def test_openwebui_auth_rejects_empty_credentials_before_http_call(self):
        adapter = OpenWebUIAdapter()
        with patch.object(adapter, "_json_request") as mock_req:
            with self.assertRaises(ValueError):
                adapter.authenticate_user("http://127.0.0.1:8080", "alice_owner", "")
            with self.assertRaises(ValueError):
                adapter.authenticate_user("http://127.0.0.1:8080", "", "SecretPass123!")
            mock_req.assert_not_called()

    def test_auth_failure_does_not_log_tokens_or_passwords(self):
        adapter = OpenWebUIAdapter()
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        auth_logger = logging.getLogger("firedamp.adapters.openwebui.auth")
        auth_logger.addHandler(handler)
        try:
            with patch.object(
                adapter,
                "_json_request",
                return_value={"code": 401, "error": "Invalid credentials", "token": None, "secret_blob": "DO_NOT_LOG_THIS"},
            ):
                adapter.authenticate_user("http://127.0.0.1:8080", "alice_owner", "SuperSecretPassword!99")
            logged = log_stream.getvalue()
            self.assertNotIn("SuperSecretPassword!99", logged)
            self.assertNotIn("DO_NOT_LOG_THIS", logged)
        finally:
            auth_logger.removeHandler(handler)

    def test_sanitize_sensitive_text_redacts_bearer_and_passwords(self):
        raw = "HTTP failed: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def password='MySecret!123'"
        redacted = sanitize_sensitive_text(raw, ["MySecret!123"])
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redacted)
        self.assertNotIn("MySecret!123", redacted)
        self.assertIn("[REDACTED]", redacted)


class TestAdapterSelection(unittest.TestCase):
    """Section 4: Explicit adapter selection and fail-closed error handling."""

    def test_invalid_target_name_fails_clearly_without_openwebui_fallback(self):
        with self.assertRaises(ValueError):
            get_adapter("nonexistent_rag_platform")

        with patch.dict(
            os.environ,
            {"FIREDAMP_ALICE_PASSWORD": "AlicePass!1", "FIREDAMP_BOB_PASSWORD": "BobPass!2"},
        ):
            with patch("cli.RemoteTargetManager") as mock_remote:
                ret = cli.run_scan_flow(
                    target="nonexistent_rag_platform",
                    target_url="https://target.example.com",
                    dry_run=False,
                )
                self.assertEqual(ret, 1)
                mock_remote.assert_not_called()

    def test_explicit_openwebui_selection(self):
        adapter = get_adapter("openwebui")
        self.assertIsInstance(adapter, OpenWebUIAdapter)
        self.assertEqual(adapter.target_name, "openwebui")

    @patch.dict(
        os.environ,
        {"FIREDAMP_ALICE_PASSWORD": "AlicePass!1", "FIREDAMP_BOB_PASSWORD": "BobPass!2"},
    )
    @patch("cli.get_adapter", side_effect=RuntimeError("Adapter constructor exploded"))
    def test_adapter_constructor_failure_is_surfaced(self, mock_get_adapter):
        with patch("cli.reporter.log_alert") as mock_alert:
            ret = cli.run_scan_flow(
                target="openwebui",
                target_url="https://target.example.com",
                dry_run=False,
            )
        self.assertEqual(ret, 1)
        alerts = [str(c.args[0]) for c in mock_alert.call_args_list]
        self.assertTrue(any("Adapter constructor exploded" in a for a in alerts))

    def test_missing_adapter_registration_fails(self):
        saved = ADAPTER_REGISTRY.pop("dify", None)
        try:
            with self.assertRaises(ValueError):
                get_adapter("dify")
        finally:
            if saved is not None:
                ADAPTER_REGISTRY["dify"] = saved


class TestProbeClassificationAndReporting(unittest.TestCase):
    """Section 5: Explicit CLEAN, COMPROMISED, INCONCLUSIVE, and SKIPPED semantics."""

    def test_four_probe_statuses_and_properties(self):
        clean = ProbeResult("1", "p", "cat", "Denied", [], [], LeakSeverity.NONE)
        compromised = ProbeResult("2", "p", "cat", "CANARY-1", [], ["CANARY-1"], LeakSeverity.DIRECT_LEAK)
        inconclusive = ProbeResult("3", "p", "cat", "INCONCLUSIVE: timeout", [], [], LeakSeverity.NONE, inconclusive=True)
        skipped = ProbeResult("4", "p", "cat", "SKIPPED: missing milvus", [], [], LeakSeverity.NONE, skipped=True)

        self.assertEqual(clean.status, ProbeStatus.CLEAN)
        self.assertTrue(clean.is_clean)
        self.assertFalse(clean.is_inconclusive or clean.is_skipped or clean.is_leak)

        self.assertEqual(compromised.status, ProbeStatus.COMPROMISED)
        self.assertTrue(compromised.is_leak)
        self.assertFalse(compromised.is_clean)

        self.assertEqual(inconclusive.status, ProbeStatus.INCONCLUSIVE)
        self.assertTrue(inconclusive.is_inconclusive)
        self.assertFalse(inconclusive.is_clean or inconclusive.is_skipped)

        self.assertEqual(skipped.status, ProbeStatus.SKIPPED)
        self.assertTrue(skipped.is_skipped)
        self.assertFalse(skipped.is_clean or skipped.is_inconclusive)

    def test_summary_and_reports_distinguish_skipped_and_inconclusive(self):
        rep = FiredampReporter()
        results = [
            ProbeResult("1", "p1", "c1", "Denied", [], [], LeakSeverity.NONE),
            ProbeResult("2", "p2", "c2", "INCONCLUSIVE: server error", [], [], LeakSeverity.NONE, inconclusive=True),
            ProbeResult("3", "p3", "c3", "SKIPPED: Missing precondition 'milvus_multitenancy'", [], [], LeakSeverity.NONE, skipped=True),
        ]
        summary = rep.calculate_summary("openwebui", "https://example.com", [], results)
        self.assertEqual(summary.status, "INCOMPLETE")
        self.assertEqual(summary.total_probes_dispatched, 3)
        self.assertEqual(summary.total_probes_executed, 2)
        self.assertEqual(summary.clean_probes, 1)
        self.assertEqual(summary.compromised_probes, 0)
        self.assertEqual(summary.inconclusive_probes, 1)
        self.assertEqual(summary.skipped_probes, 1)

        md = rep.render_markdown(summary)
        self.assertIn("INCOMPLETE", md)
        self.assertNotIn("AIRWAY CLEAR", md)

        sarif = rep.render_sarif(summary)
        props = sarif["runs"][0]["properties"]
        self.assertEqual(props["status"], "INCOMPLETE")
        self.assertEqual(props["skipped_probes"], 1)
        self.assertEqual(props["inconclusive_probes"], 1)

    def test_policy_require_complete_and_fail_on_inconclusive(self):
        yaml_cfg = """
name: strict_completeness
thresholds:
  fail_on_direct_leak: true
  fail_on_inconclusive: true
  require_complete_execution: true
"""
        policy = FiredampPolicy.from_yaml(yaml_cfg)
        rep = FiredampReporter()
        results = [
            ProbeResult("1", "p1", "c1", "SKIPPED: missing milvus", [], [], LeakSeverity.NONE, skipped=True),
        ]
        summary = rep.calculate_summary("openwebui", "https://example.com", [], results)
        eval_res = policy.evaluate(summary, results)
        self.assertFalse(eval_res.passed)
        self.assertTrue(any("Incomplete scan coverage" in v for v in eval_res.violations))

    @patch("probes.cves.run_cve_suite")
    def test_cli_require_complete_exits_nonzero_on_skipped_or_inconclusive(self, mock_cve_suite):
        mock_cve_suite.return_value = [
            ProbeResult("skip-1", "p", "cve_regression:CVE-2026-54019", "SKIPPED: Missing required precondition 'milvus_multitenancy'", [], [], LeakSeverity.NONE, skipped=True)
        ]
        ret_default = cli.run_scan_flow(target="openwebui", suite="cve-regression", dry_run=True, require_complete=False)
        self.assertEqual(ret_default, 0)

        ret_strict = cli.run_scan_flow(target="openwebui", suite="cve-regression", dry_run=True, require_complete=True)
        self.assertEqual(ret_strict, 1)


class TestTransportSecurity(unittest.TestCase):
    """Section 10: HTTPS enforcement for non-loopback live targets."""

    def test_non_loopback_http_refused_by_default(self):
        with self.assertRaises(ValueError):
            validate_target_url("http://remote-openwebui.example.com:8080")
        with self.assertRaises(ValueError):
            RemoteTargetManager("http://10.0.0.5:8080")

    def test_non_loopback_http_allowed_with_explicit_opt_in(self):
        cleaned = validate_target_url("http://10.0.0.5:8080/", allow_insecure_http=True)
        self.assertEqual(cleaned, "http://10.0.0.5:8080")

    def test_loopback_http_and_remote_https_allowed(self):
        self.assertEqual(validate_target_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080")
        self.assertEqual(validate_target_url("http://localhost:3000"), "http://localhost:3000")
        self.assertEqual(validate_target_url("https://rag.example.com"), "https://rag.example.com")


if __name__ == "__main__":
    unittest.main()
