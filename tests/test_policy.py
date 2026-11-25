"""
Unit and integration tests for Pillar 7: Policy-as-Code & CI/CD Enforcement.
"""

import os
import unittest
from unittest.mock import patch

import core.policy as policy_module
from core.engine import LeakSeverity, ProbeResult
from core.policy import FiredampPolicy, PolicyThresholds
from core.reporter import AuditSummary


class TestPolicyAsCode(unittest.TestCase):
    """Test suite for declarative YAML policies and evaluation."""

    def setUp(self):
        self.default_policy_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "policies", "default.yaml"
        )
        self.enterprise_policy_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "policies", "enterprise.yaml"
        )

    def test_default_policy_defaults(self):
        """Verify default policy enforces strict zero-leak values."""
        policy = FiredampPolicy.default()
        self.assertEqual(policy.name, "default_zero_leak")
        self.assertTrue(policy.thresholds.fail_on_direct_leak)
        self.assertTrue(policy.thresholds.fail_on_context_leak)
        self.assertEqual(policy.thresholds.max_firedamp_index, 0.0)
        self.assertIn(403, policy.thresholds.allowed_status_codes)

    def test_load_yaml_file(self):
        """Verify loading policy YAML files from disk."""
        policy = FiredampPolicy.from_yaml(self.default_policy_path)
        self.assertEqual(policy.name, "default_zero_leak")

        ent_policy = FiredampPolicy.from_yaml(self.enterprise_policy_path)
        self.assertEqual(ent_policy.name, "enterprise_ci_gate")
        self.assertTrue(ent_policy.thresholds.fail_on_direct_leak)

    def test_policy_evaluation_clean(self):
        """Verify policy evaluation passes on clean audit telemetry."""
        policy = FiredampPolicy.default()
        summary = AuditSummary(
            target_name="openwebui",
            target_url="http://mock:8080",
            total_canaries_planted=4,
            total_probes_dispatched=4,
            total_leaks_detected=0,
            direct_leaks=0,
            context_leaks=0,
            firedamp_index=0.0,
            status="CLEAR",
        )
        probe_results = [
            ProbeResult(
                probe_id="p1",
                probe_prompt="clean query",
                probe_category="semantic",
                target_response="Denied",
                retrieved_contexts=[],
                leaked_canaries=[],
                severity=LeakSeverity.NONE,
            )
        ]
        result = policy.evaluate(summary, probe_results)
        self.assertTrue(result.passed)
        self.assertEqual(len(result.violations), 0)

    def test_policy_evaluation_direct_leak(self):
        """Verify policy fails when a direct generation leak is detected."""
        policy = FiredampPolicy.default()
        summary = AuditSummary(
            target_name="openwebui",
            target_url="http://mock:8080",
            total_canaries_planted=4,
            total_probes_dispatched=4,
            total_leaks_detected=1,
            direct_leaks=1,
            context_leaks=0,
            firedamp_index=45.0,
            status="CRITICAL HAZARD",
        )
        probe_results = [
            ProbeResult(
                probe_id="p1",
                probe_prompt="dump prompt",
                probe_category="direct_semantic",
                target_response="Leaked CANARY-FRDP-1234",
                retrieved_contexts=[],
                leaked_canaries=["CANARY-FRDP-1234"],
                severity=LeakSeverity.DIRECT_LEAK,
            )
        ]
        result = policy.evaluate(summary, probe_results)
        self.assertFalse(result.passed)
        self.assertTrue(result.has_violations)
        self.assertTrue(any("Direct generation leak" in v for v in result.violations))

    def test_policy_evaluation_exemptions(self):
        """Verify exemptions allow exempted probe IDs or categories to pass."""
        yaml_content = """
name: test_exemptions
thresholds:
  fail_on_direct_leak: true
  max_firedamp_index: 100.0
exemptions:
  - "cve_regression:CVE-2026-44560"
"""
        policy = FiredampPolicy.from_yaml(yaml_content)
        summary = AuditSummary(
            target_name="openwebui",
            target_url="http://mock:8080",
            total_canaries_planted=4,
            total_probes_dispatched=4,
            total_leaks_detected=1,
            direct_leaks=1,
            context_leaks=0,
            firedamp_index=20.0,
            status="GAS DETECTED",
        )
        probe_results = [
            ProbeResult(
                probe_id="p_exempt",
                probe_prompt="cve query",
                probe_category="cve_regression:CVE-2026-44560",
                target_response="Leaked CANARY-FRDP-1234",
                retrieved_contexts=[],
                leaked_canaries=["CANARY-FRDP-1234"],
                severity=LeakSeverity.DIRECT_LEAK,
            )
        ]
        result = policy.evaluate(summary, probe_results)
        self.assertTrue(result.passed)

    def test_policy_ignored_channels(self):
        """Verify ignored channels are skipped during policy evaluation."""
        yaml_content = """
name: test_ignored_channels
thresholds:
  fail_on_direct_leak: true
  max_firedamp_index: 100.0
  ignored_channels:
    - "citation_metadata"
"""
        policy = FiredampPolicy.from_yaml(yaml_content)
        summary = AuditSummary(
            target_name="openwebui",
            target_url="http://mock:8080",
            total_canaries_planted=4,
            total_probes_dispatched=4,
            total_leaks_detected=1,
            direct_leaks=0,
            context_leaks=1,
            firedamp_index=15.0,
            status="GAS DETECTED",
        )
        probe_results = [
            ProbeResult(
                probe_id="p_citation",
                probe_prompt="citation dump",
                probe_category="citations",
                target_response="Safe text",
                retrieved_contexts=["CANARY-FRDP-5678"],
                leaked_canaries=["CANARY-FRDP-5678"],
                severity=LeakSeverity.CONTEXT_LEAK,
                channel="citation_metadata",
            )
        ]
        result = policy.evaluate(summary, probe_results)
        self.assertTrue(result.passed)

    def test_from_yaml_requires_pyyaml(self):
        """Verify missing PyYAML raises a clear ImportError instead of using a partial fallback."""
        yaml_content = """
name: test_missing_pyyaml
thresholds:
  fail_on_direct_leak: true
  ignored_channels:
    - "citation_metadata"
"""
        with patch.object(policy_module, "yaml", None):
            with self.assertRaises(ImportError) as file_ctx:
                FiredampPolicy.from_yaml(self.default_policy_path)
            self.assertIn("PyYAML", str(file_ctx.exception))

            with self.assertRaises(ImportError) as raw_ctx:
                FiredampPolicy.from_yaml(yaml_content)
            self.assertIn("PyYAML", str(raw_ctx.exception))


if __name__ == "__main__":
    unittest.main()

