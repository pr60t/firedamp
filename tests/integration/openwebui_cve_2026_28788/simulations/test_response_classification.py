"""
Deterministic Offline Simulation Suite for CVE-2026-28788 Response Classification.
NOTICE: SIMULATED — no live Open WebUI instance was contacted.

This test suite verifies Firedamp's CVE-2026-28788 probe logic and edge-case classification
against sanitized response fixtures conforming strictly to the upstream Open WebUI
v0.8.5 and v0.8.6 BatchProcessFilesResponse contract.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from adapters.base import UserSession
from core.engine import CanaryToken, ProbingEngine, LeakSeverity
from probes.cves import cve_2026_28788
from probes.cves.cve_2026_28788 import (
    register_trusted_disposable_resource,
    clear_trusted_registry,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestCVE28788ResponseClassificationSimulation(unittest.TestCase):
    """
    Offline response classification tests for CVE-2026-28788.
    All tests execute purely in-memory using file fixtures.
    """

    def setUp(self):
        self.run_id = "sim-run-cve28788-classification"
        self.engine = ProbingEngine(run_id=self.run_id)
        self.canary = CanaryToken.generate(category="financial", owner="alice")
        self.target_file_id = "disposable-target-f123"

        self.alice = UserSession(
            username="alice",
            role="user",
            token="token-alice-sim",
            metadata={
                "run_id": self.run_id,
                "user_id": "alice-uuid-12345",
                "file_ids": ["f-unrelated"],
                "knowledge_ids": ["kb-alice-knowledge-1"],
                "disposable_file_ids": [self.target_file_id],
                "disposable_provenance": {
                    self.target_file_id: {
                        "file_id": self.target_file_id,
                        "provisioned_by": "firedamp",
                        "owner": "alice",
                        "run_id": self.run_id,
                        "active": True,
                    }
                },
            },
        )
        self.bob = UserSession(
            username="bob",
            role="user",
            token="token-bob-sim",
            metadata={
                "run_id": self.run_id,
                "user_id": "bob-uuid-67890",
                "file_ids": [],
                "knowledge_ids": ["kb-alice-knowledge-1"],
            },
        )

        register_trusted_disposable_resource(self.run_id, self.target_file_id, "alice")

        self.mock_adapter = MagicMock()
        self.mock_adapter.validate_session.return_value = True
        self.mock_adapter.get_authenticated_user_id.side_effect = (
            lambda base, sess: sess.metadata.get("user_id") if self.mock_adapter.validate_session(base, sess) else None
        )
        self.mock_adapter.get_file_metadata.side_effect = lambda base, sess, fid: {
            "id": fid,
            "user_id": "alice-uuid-12345",
            "filename": "alice_original.txt",
            "meta": {"collection_name": "kb-alice-knowledge-1"},
            "created_at": 1732272000,
            "updated_at": 1732272000,
        }
        self.mock_adapter.read_file_content.return_value = "Baseline content with Alice Canary"
        self.mock_adapter.delete_file.return_value = True
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = (
            lambda base, sess: list(sess.metadata.get("knowledge_ids", [])) if isinstance(sess.metadata, dict) else []
        )
        self.mock_adapter.get_knowledge_base_files.side_effect = (
            lambda base, sess, kb: [self.target_file_id] if kb == "kb-alice-knowledge-1" else []
        )

    def tearDown(self):
        clear_trusted_registry()

    def test_simulation_notice(self):
        """Simulation tests explicitly confirm that no live Open WebUI instance was contacted."""
        notice = "SIMULATED — no live Open WebUI instance was contacted."
        self.assertIn("SIMULATED", notice)

    def test_vulnerable_v085_response_fixture_classification(self):
        """v0.8.5 fixture with target in results['completed'] and tracer readback produces COMPROMISED."""
        with open(FIXTURES_DIR / "vulnerable_response.json", "r", encoding="utf-8") as f:
            vulnerable_fixture = json.load(f)

        self.mock_adapter.overwrite_resource.return_value = vulnerable_fixture

        def readback_side_effect(base, sess, fid):
            # When Bob overwrites, the readback receives Bob's injected tracer
            last_call = self.mock_adapter.overwrite_resource.call_args
            if last_call:
                payload = last_call[1].get("payload") or (last_call[0][3] if len(last_call[0]) > 3 else "")
                return f"Overwritten text: {payload}"
            return "Baseline content with Alice Canary"

        self.mock_adapter.read_file_content.side_effect = readback_side_effect

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)
        self.assertIn("COMPROMISED", res.target_response)
        self.assertIn("Overwrite mutation proven in victim indexed content", res.target_response)

    def test_patched_v086_response_fixture_classification(self):
        """v0.8.6 fixture with target in errors['failed'] with ownership rejection produces CLEAN."""
        with open(FIXTURES_DIR / "patched_response.json", "r", encoding="utf-8") as f:
            patched_fixture = json.load(f)

        self.mock_adapter.overwrite_resource.return_value = patched_fixture

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("CLEAN", res.target_response)
        self.assertIn("authorization rejection", res.target_response)
        self.assertIn("Permission denied: not file owner", res.target_response)

    def test_contradictory_response_fixture_classification(self):
        """Contradictory fixture where target appears in both results and errors produces INCONCLUSIVE."""
        with open(FIXTURES_DIR / "contradictory_response.json", "r", encoding="utf-8") as f:
            contradictory_fixture = json.load(f)

        self.mock_adapter.overwrite_resource.return_value = contradictory_fixture

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("contradictory", res.target_response.lower())

    def test_invalid_attacker_authentication_classification(self):
        """Unauthenticated or invalid attacker token fails closed with INCONCLUSIVE."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Attacker authentication failed", res.target_response)

    def test_missing_target_in_batch_response_classification(self):
        """When target is completely omitted from both results and errors, produces INCONCLUSIVE."""
        with open(FIXTURES_DIR / "empty_results_errors.json", "r", encoding="utf-8") as f:
            empty_fixture = json.load(f)

        self.mock_adapter.overwrite_resource.return_value = empty_fixture

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("omitted target file", res.target_response.lower())

    def test_baseline_readback_failure_classification(self):
        """When baseline readback fails before overwrite, aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.read_file_content.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Failed to retrieve indexed baseline content", res.target_response)

    def test_unexpected_content_mutation_without_tracer_classification(self):
        """When server reports completed but attacker tracer is absent from readback, produces INCONCLUSIVE."""
        with open(FIXTURES_DIR / "vulnerable_response.json", "r", encoding="utf-8") as f:
            vulnerable_fixture = json.load(f)

        self.mock_adapter.overwrite_resource.return_value = vulnerable_fixture
        # Server content mutated unexpectedly, but doesn't contain attacker's specific canary
        self.mock_adapter.read_file_content.return_value = "Random unrelated file modification"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("attacker tracer was absent from indexed content", res.target_response.lower())

    def test_resource_ownership_mismatch_classification(self):
        """When target server metadata user_id mismatches Alice, probe aborts with INCONCLUSIVE."""
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": self.target_file_id,
            "user_id": "foreign-unrelated-user-uuid",
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock-simulation:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("does not match victim server user_id", res.target_response)


if __name__ == "__main__":
    unittest.main()
