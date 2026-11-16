"""
Unit tests for Milestone 1.4: Target Configuration Profile & Matrix Runner.
"""

import unittest

from core.target import (
    VectorDBType,
    MultitenancyMode,
    TargetConfigProfile,
    TargetEnvironment,
)
from core.reporter import FiredampReporter, AuditSummary
from core.engine import CanaryToken, ProbingEngine
from probes.cves import run_cve_suite
from adapters.base import UserSession
from unittest.mock import MagicMock


class TestTargetConfigMatrix(unittest.TestCase):
    """Test suite for target configuration profile parsing and conditional execution."""

    def test_default_config_profile(self):
        profile = TargetConfigProfile.from_args()
        self.assertEqual(profile.vector_db, VectorDBType.CHROMA)
        self.assertEqual(profile.multitenancy, MultitenancyMode.SHARED)
        self.assertIn("chroma", profile.active_preconditions)
        self.assertIn("chroma_multitenancy", profile.active_preconditions)
        self.assertIn("shared_store", profile.active_preconditions)
        self.assertNotIn("milvus_multitenancy", profile.active_preconditions)

    def test_milvus_config_profile(self):
        profile = TargetConfigProfile.from_args(vector_db="milvus", multitenancy="shared")
        self.assertEqual(profile.vector_db, VectorDBType.MILVUS)
        self.assertEqual(profile.multitenancy, MultitenancyMode.SHARED)
        self.assertIn("milvus", profile.active_preconditions)
        self.assertIn("milvus_multitenancy", profile.active_preconditions)
        self.assertIn("milvus_rbac", profile.active_preconditions)
        self.assertIn("shared_store", profile.active_preconditions)

    def test_isolated_multitenancy_mode(self):
        profile = TargetConfigProfile.from_args(vector_db="qdrant", multitenancy="isolated")
        self.assertEqual(profile.vector_db, VectorDBType.QDRANT)
        self.assertEqual(profile.multitenancy, MultitenancyMode.ISOLATED)
        self.assertIn("qdrant", profile.active_preconditions)
        self.assertIn("isolated_store", profile.active_preconditions)
        self.assertNotIn("shared_store", profile.active_preconditions)

    def test_conditional_cve_execution_chroma_vs_milvus(self):
        engine = ProbingEngine()
        canary = CanaryToken.generate()
        alice = UserSession(username="alice", role="owner", metadata={"knowledge_ids": ["kb1"], "file_ids": ["f1"]})
        bob = UserSession(username="bob", role="attacker", metadata={"knowledge_ids": [], "file_ids": []})
        mock_adapter = MagicMock()

        # Chroma profile: CVE-2026-54019 must be skipped
        chroma_profile = TargetConfigProfile.from_args(vector_db="chroma")
        chroma_results = run_cve_suite(
            adapter=mock_adapter,
            base_url="http://mock:8080",
            alice=alice,
            bob=bob,
            planted_canaries=[canary],
            engine=engine,
            dry_run=True,
            preconditions=chroma_profile.active_preconditions,
        )
        chroma_cves = [r.probe_category for r in chroma_results]
        self.assertFalse(any("CVE-2026-54019" in c for c in chroma_cves))

        # Milvus profile: CVE-2026-54019 must be executed
        milvus_profile = TargetConfigProfile.from_args(vector_db="milvus", multitenancy="shared")
        milvus_results = run_cve_suite(
            adapter=mock_adapter,
            base_url="http://mock:8080",
            alice=alice,
            bob=bob,
            planted_canaries=[canary],
            engine=engine,
            dry_run=True,
            preconditions=milvus_profile.active_preconditions,
        )
        milvus_cves = [r.probe_category for r in milvus_results]
        self.assertTrue(any("CVE-2026-54019" in c for c in milvus_cves))

    def test_reporter_config_profile_summary(self):
        reporter = FiredampReporter()
        profile = TargetConfigProfile.from_args(vector_db="milvus", multitenancy="shared")
        summary = reporter.calculate_summary(
            target_name="openwebui",
            target_url="http://localhost:8080",
            planted_canaries=[],
            probe_results=[],
            config_profile={
                "vector_db": profile.vector_db.value,
                "multitenancy": profile.multitenancy.value,
                "preconditions": profile.active_preconditions,
            },
        )
        self.assertIsNotNone(summary.config_profile)
        self.assertEqual(summary.config_profile["vector_db"], "milvus")
        self.assertEqual(summary.config_profile["multitenancy"], "shared")
        summary_dict = summary.to_dict()
        self.assertIn("config_profile", summary_dict)


if __name__ == "__main__":
    unittest.main()

