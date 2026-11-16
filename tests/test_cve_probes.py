"""
Unit tests for Tier-1 CVE behavioral regression probes (CVE-2026-44560, 45398, 28788, 54019).
"""

import unittest
from unittest.mock import MagicMock

from adapters.base import UserSession
from core.engine import CanaryToken, ProbingEngine, LeakSeverity
from probes.cves import (
    cve_2026_44560,
    cve_2026_45398,
    cve_2026_28788,
    cve_2026_54019,
    run_cve_suite,
)


class TestCVEBehavioralProbes(unittest.TestCase):
    """Test suite verifying behavioral execution and leak detection of CVE fixtures."""

    def setUp(self):
        self.engine = ProbingEngine()
        self.canary = CanaryToken.generate(category="financial", owner="Alice")
        self.alice = UserSession(
            username="alice",
            role="owner",
            token="token-alice",
            metadata={"file_ids": ["f123"], "knowledge_ids": ["kb-uuid-456"]},
        )
        self.bob = UserSession(
            username="bob",
            role="attacker",
            token="token-bob",
            metadata={"file_ids": [], "knowledge_ids": []},
        )
        self.mock_adapter = MagicMock()

    def test_cve_2026_44560_clean(self):
        self.mock_adapter.query_resource_direct.return_value = (
            "Access denied",
            [],
            {"error": "Unauthorized", "code": 403},
        )
        res = cve_2026_44560.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.channel, "direct_api")
        self.mock_adapter.query_resource_direct.assert_called_with(
            "http://mock:8080", self.bob, resource_ref="file-f123", k=50
        )

    def test_cve_2026_44560_leak(self):
        # Bob receives Alice's canary through predictable file-<id>
        self.mock_adapter.query_resource_direct.return_value = (
            f"Here is the data: {self.canary.token}",
            [f"Chunk: {self.canary.token}"],
            {"documents": [[self.canary.token]]},
        )
        res = cve_2026_44560.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertIn(self.canary.token, res.leaked_canaries)

    def test_cve_2026_45398_raw_uuid_leak(self):
        self.mock_adapter.query_resource_direct.return_value = (
            "",
            [f"Document content containing {self.canary.token}"],
            {},
        )
        res = cve_2026_45398.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.channel, "direct_api")

    def test_cve_2026_28788_write_poisoning_detected(self):
        # Server accepts Bob's overwrite on Alice's file
        self.mock_adapter.overwrite_resource.return_value = {"status": True}
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.channel, "write_side")

    def test_cve_2026_54019_milvus_injection_precondition(self):
        # When milvus_multitenancy is not in preconditions, runner should skip it
        results = run_cve_suite(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=True,
            preconditions=[],
        )
        cve_ids = [r.probe_category for r in results]
        self.assertTrue(any("CVE-2026-44560" in c for c in cve_ids))
        self.assertTrue(any("CVE-2026-45398" in c for c in cve_ids))
        self.assertTrue(any("CVE-2026-28788" in c for c in cve_ids))
        self.assertFalse(any("CVE-2026-54019" in c for c in cve_ids))

    def test_cve_2026_54019_milvus_injection_executed_when_preconditioned(self):
        results = run_cve_suite(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=True,
            preconditions=["milvus_multitenancy"],
        )
        cve_ids = [r.probe_category for r in results]
        self.assertTrue(any("CVE-2026-54019" in c for c in cve_ids))


if __name__ == "__main__":
    unittest.main()

