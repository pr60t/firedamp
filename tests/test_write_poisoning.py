"""
Unit and integration tests for Pillar 5: Write-Side Poisoning (Cross-Tenant Indirect Injection).
"""

import unittest
from adapters.base import TargetAdapter, UserSession
from core.engine import (
    CanaryToken,
    LeakSeverity,
    ProbeResult,
    ProbingEngine,
)
from probes.scenarios.write_poisoning import (
    run_write_poisoning_scenarios,
    test_cross_tenant_collection_injection,
    test_cross_tenant_file_overwrite,
)


class MockPoisonAdapter(TargetAdapter):
    """Mock adapter simulating write-side poisoning and integrity scenarios."""

    @property
    def target_name(self) -> str:
        return "mock_poison"

    def __init__(self, allow_injection: bool = False, allow_overwrite: bool = False):
        self.allow_injection = allow_injection
        self.allow_overwrite = allow_overwrite
        self.injected_documents = []
        self.overwritten_payloads = []

    def authenticate_user(self, base_url, username, password, role="user"):
        return UserSession(
            username=username,
            role=role,
            metadata={"knowledge_ids": ["alice-kb-uuid"], "file_ids": ["alice-file-id"]},
        )

    def ingest_document(self, base_url, session, document):
        return "doc-123"

    def inject_into_collection(self, base_url, session, target_collection_id, document):
        self.injected_documents.append((target_collection_id, document))
        if self.allow_injection:
            return {"status": True, "id": "injected-doc-id"}
        return {"error": "Access denied", "code": 403}

    def overwrite_resource(self, base_url, session, resource_ref, payload):
        self.overwritten_payloads.append((resource_ref, payload))
        if self.allow_overwrite:
            return {"status": True, "mutated": True}
        return {"error": "Unauthorized", "code": 403}

    def query_rag(self, base_url, session, prompt):
        # If Bob successfully injected into Alice's collection, Alice's query retrieves it
        if self.allow_injection and self.injected_documents:
            last_doc = self.injected_documents[-1][1]
            return (f"Retrieved content: {last_doc.content}", [last_doc.content], {})
        return ("Alice's clean private documents only.", [], {})

    def query_resource_direct(self, base_url, session, resource_ref, k=50):
        # If Bob successfully overwrote Alice's file, direct query returns Bob's payload
        if self.allow_overwrite and self.overwritten_payloads:
            last_payload = self.overwritten_payloads[-1][1]
            return (f"Direct file content: {last_payload}", [last_payload], {})
        return ("Original Alice file content.", [], {})

    def enumerate_resources(self, base_url, session):
        return []

    def share_resource(self, base_url, owner, resource_ref, grantee):
        return {"status": True}

    def revoke_resource(self, base_url, owner, resource_ref, grantee):
        return {"status": True}

    def cleanup(self, base_url, session):
        pass


class TestWritePoisoningScenarios(unittest.TestCase):
    """Test suite for write-side poisoning probes."""

    def setUp(self):
        self.engine = ProbingEngine()
        self.alice = UserSession("alice", "owner", metadata={"knowledge_ids": ["kb-alice"], "file_ids": ["file-alice"]})
        self.bob = UserSession("bob", "attacker", metadata={})

    def test_collection_injection_dry_run(self):
        """Verify dry-run execution of cross-tenant collection injection probe."""
        adapter = MockPoisonAdapter()
        res = test_cross_tenant_collection_injection(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:write_poisoning:collection_injection")
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.channel, "write_mutation")

    def test_collection_injection_clean(self):
        """Verify live execution when server blocks Bob from injecting into Alice's KB."""
        adapter = MockPoisonAdapter(allow_injection=False)
        res = test_cross_tenant_collection_injection(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_collection_injection_compromise_detected(self):
        """Verify probe catches integrity compromise when Bob injects tracer into Alice's KB."""
        adapter = MockPoisonAdapter(allow_injection=True)
        res = test_cross_tenant_collection_injection(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)
        self.assertTrue(len(res.leaked_canaries) > 0)
        self.assertTrue(res.leaked_canaries[0].startswith("CANARY-FRDP-"))

    def test_file_overwrite_dry_run(self):
        """Verify dry-run execution of cross-tenant file overwrite probe."""
        adapter = MockPoisonAdapter()
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:write_poisoning:file_overwrite")
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertFalse(res.is_leak)

    def test_file_overwrite_clean(self):
        """Verify live execution when server blocks Bob from overwriting Alice's file."""
        adapter = MockPoisonAdapter(allow_overwrite=False)
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertFalse(res.is_leak)

    def test_file_overwrite_compromise_detected(self):
        """Verify probe catches file overwrite mutation when Bob's tracer mutates Alice's file."""
        adapter = MockPoisonAdapter(allow_overwrite=True)
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)
        self.assertTrue(len(res.leaked_canaries) > 0)

    def test_run_write_poisoning_scenarios_suite(self):
        """Verify runner executes all write-poisoning scenario probes."""
        adapter = MockPoisonAdapter()
        results = run_write_poisoning_scenarios(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(len(results), 2)
        categories = [r.probe_category for r in results]
        self.assertIn("scenario:write_poisoning:collection_injection", categories)
        self.assertIn("scenario:write_poisoning:file_overwrite", categories)
        for r in results:
            self.assertEqual(r.channel, "write_mutation")
            self.assertFalse(r.is_leak)


if __name__ == "__main__":
    unittest.main()

