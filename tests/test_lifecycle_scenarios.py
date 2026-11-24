"""
Unit and integration tests for Pillar 4: Time & Sequence Attacks (Lifecycle Scenarios).
"""

import unittest
from unittest.mock import MagicMock

from adapters.base import TargetAdapter, UserSession
from core.engine import (
    CanaryToken,
    LeakSeverity,
    ProbeResult,
    ProbingEngine,
)
from probes.scenarios.lifecycle import (
    run_lifecycle_scenarios,
    test_delete_while_indexing,
    test_post_revocation_staleness,
    test_revocation_in_flight,
)


class MockLifecycleAdapter(TargetAdapter):
    """Mock adapter simulating various lifecycle and race condition behaviors."""

    @property
    def target_name(self) -> str:
        return "mock_lifecycle"

    def __init__(self, leak_on_revoke: bool = False, leak_on_delete: bool = False):
        self.shared_resources = set()
        self.revoked_resources = set()
        self.deleted_resources = set()
        self.leak_on_revoke = leak_on_revoke
        self.leak_on_delete = leak_on_delete
        self.canary_to_leak = None
        self.ingest_calls = 0
        self.cleanup_calls = 0
        self.query_direct_calls = []

    def authenticate_user(self, base_url, username, password, role="user"):
        return UserSession(
            username=username,
            role=role,
            metadata={"knowledge_ids": ["kb-123"], "file_ids": ["file-456"]},
        )

    def ingest_document(self, base_url, session, document):
        self.ingest_calls += 1
        if document.canaries:
            self.canary_to_leak = document.canaries[0].token
        return "mock-doc-ref"

    def query_rag(self, base_url, session, prompt):
        if self.leak_on_delete and self.canary_to_leak:
            return (f"Orphan discovered: {self.canary_to_leak}", [self.canary_to_leak], {})
        return ("No relevant documents found.", [], {})

    def query_resource_direct(self, base_url, session, resource_ref, k=50):
        self.query_direct_calls.append(resource_ref)
        if self.leak_on_revoke and self.canary_to_leak:
            return (f"Stale grant accessible: {self.canary_to_leak}", [self.canary_to_leak], {})
        return ("403 Forbidden: Resource access denied.", [], {"code": 403})

    def overwrite_resource(self, base_url, session, resource_ref, payload):
        return {"status": False, "code": 403}

    def enumerate_resources(self, base_url, session):
        return []

    def share_resource(self, base_url, owner, resource_ref, grantee):
        self.shared_resources.add((resource_ref, grantee.username))
        return {"status": True}

    def revoke_resource(self, base_url, owner, resource_ref, grantee):
        self.revoked_resources.add((resource_ref, grantee.username))
        return {"status": True}

    def cleanup(self, base_url, session):
        self.cleanup_calls += 1
        self.deleted_resources.add(session.username)


class TestLifecycleScenarios(unittest.TestCase):
    """Test suite for lifecycle scenario probes."""

    def setUp(self):
        self.engine = ProbingEngine()
        self.alice = UserSession("alice", "owner", metadata={"knowledge_ids": ["kb-123"]})
        self.bob = UserSession("bob", "attacker", metadata={})
        self.canary = CanaryToken.generate(category="financial", owner="alice")

    def test_revocation_in_flight_dry_run(self):
        """Verify dry-run execution of revocation-in-flight probe."""
        adapter = MockLifecycleAdapter()
        res = test_revocation_in_flight(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:lifecycle:revocation_in_flight")
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.channel, "lifecycle_event")

    def test_revocation_in_flight_mocked_clean(self):
        """Verify simulated execution of revocation-in-flight when platform properly denies access."""
        adapter = MockLifecycleAdapter(leak_on_revoke=False)
        adapter.canary_to_leak = self.canary.token
        res = test_revocation_in_flight(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=False,
            num_concurrent_queries=3,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn(("kb-123", "bob"), adapter.revoked_resources)

    def test_revocation_in_flight_leak_detected(self):
        """Verify revocation-in-flight detects race condition when queries return canary."""
        adapter = MockLifecycleAdapter(leak_on_revoke=True)
        adapter.canary_to_leak = self.canary.token
        res = test_revocation_in_flight(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=False,
            num_concurrent_queries=3,
        )
        self.assertTrue(res.is_leak)
        self.assertIn(self.canary.token, res.leaked_canaries)
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)

    def test_post_revocation_staleness_dry_run(self):
        """Verify dry-run execution of post-revocation staleness probe."""
        adapter = MockLifecycleAdapter()
        res = test_post_revocation_staleness(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            delay_seconds=0.0,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:lifecycle:post_revocation_staleness")
        self.assertFalse(res.is_leak)

    def test_post_revocation_staleness_leak_detected(self):
        """Verify post-revocation staleness detects leaks if server serves cached grants."""
        adapter = MockLifecycleAdapter(leak_on_revoke=True)
        adapter.canary_to_leak = self.canary.token
        res = test_post_revocation_staleness(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            delay_seconds=0.01,
            dry_run=False,
        )
        self.assertTrue(res.is_leak)
        self.assertIn(self.canary.token, res.leaked_canaries)

    def test_delete_while_indexing_dry_run(self):
        """Verify dry-run execution of delete-while-indexing probe."""
        adapter = MockLifecycleAdapter()
        res = test_delete_while_indexing(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:lifecycle:delete_while_indexing")
        self.assertFalse(res.is_leak)
        self.assertIn("DRY RUN", res.target_response)
        self.assertEqual(adapter.ingest_calls, 0)
        self.assertEqual(adapter.cleanup_calls, 0)

    def test_delete_while_indexing_live_mode_fails_inconclusive_without_mutation(self):
        """The probe must not ingest and invoke broad cleanup without a cancellable task handle."""
        adapter = MockLifecycleAdapter(leak_on_delete=True)
        res = test_delete_while_indexing(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=False,
        )
        self.assertIs(res.is_inconclusive, True)
        self.assertIs(res.is_clean, False)
        self.assertIs(res.is_leak, False)
        self.assertIs(res.inconclusive, True)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(adapter.ingest_calls, 0)
        self.assertEqual(adapter.cleanup_calls, 0)

    def test_run_lifecycle_scenarios_suite(self):
        """Verify running all 3 lifecycle scenarios in sequence."""
        adapter = MockLifecycleAdapter()
        results = run_lifecycle_scenarios(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(len(results), 3)
        categories = [r.probe_category for r in results]
        self.assertIn("scenario:lifecycle:revocation_in_flight", categories)
        self.assertIn("scenario:lifecycle:post_revocation_staleness", categories)
        self.assertIn("scenario:lifecycle:delete_while_indexing", categories)
        for r in results:
            self.assertEqual(r.channel, "lifecycle_event")
            self.assertFalse(r.is_leak)

    def test_revocation_in_flight_missing_kb_id_returns_inconclusive(self):
        """Revocation in flight must return INCONCLUSIVE without dispatching adapter calls when KB ID is missing."""
        alice_no_kb = UserSession("alice", "owner", metadata={})
        adapter = MockLifecycleAdapter(leak_on_revoke=True)
        res = test_revocation_in_flight(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_no_kb,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=False,
        )
        self.assertIs(res.is_inconclusive, True)
        self.assertIs(res.is_clean, False)
        self.assertIs(res.is_leak, False)
        self.assertIs(res.inconclusive, True)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(len(adapter.shared_resources), 0)
        self.assertEqual(len(adapter.revoked_resources), 0)
        self.assertEqual(len(adapter.query_direct_calls), 0)

    def test_revocation_in_flight_blank_or_file_only_returns_inconclusive(self):
        """Revocation in flight must not substitute a file ID or blank string for a knowledge base ID."""
        alice_file_only = UserSession("alice", "owner", metadata={"knowledge_ids": ["  ", ""], "file_ids": ["file-999"]})
        adapter = MockLifecycleAdapter(leak_on_revoke=True)
        res = test_revocation_in_flight(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_file_only,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=False,
        )
        self.assertIs(res.is_inconclusive, True)
        self.assertIs(res.is_clean, False)
        self.assertIs(res.is_leak, False)
        self.assertIs(res.inconclusive, True)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(len(adapter.shared_resources), 0)
        self.assertEqual(len(adapter.revoked_resources), 0)
        self.assertEqual(len(adapter.query_direct_calls), 0)

    def test_post_revocation_staleness_missing_kb_id_returns_inconclusive(self):
        """Post-revocation staleness must return INCONCLUSIVE without dispatching adapter calls when KB ID is missing."""
        alice_no_kb = UserSession("alice", "owner", metadata={})
        adapter = MockLifecycleAdapter(leak_on_revoke=True)
        res = test_post_revocation_staleness(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_no_kb,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            delay_seconds=0.0,
            dry_run=False,
        )
        self.assertIs(res.is_inconclusive, True)
        self.assertIs(res.is_clean, False)
        self.assertIs(res.is_leak, False)
        self.assertIs(res.inconclusive, True)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(len(adapter.shared_resources), 0)
        self.assertEqual(len(adapter.revoked_resources), 0)
        self.assertEqual(len(adapter.query_direct_calls), 0)

    def test_post_revocation_staleness_blank_or_file_only_returns_inconclusive(self):
        """Post-revocation staleness must not substitute a file ID or blank string for a knowledge base ID."""
        alice_file_only = UserSession("alice", "owner", metadata={"knowledge_ids": [], "file_ids": ["file-999"]})
        adapter = MockLifecycleAdapter(leak_on_revoke=True)
        res = test_post_revocation_staleness(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_file_only,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            delay_seconds=0.0,
            dry_run=False,
        )
        self.assertIs(res.is_inconclusive, True)
        self.assertIs(res.is_clean, False)
        self.assertIs(res.is_leak, False)
        self.assertIs(res.inconclusive, True)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(len(adapter.shared_resources), 0)
        self.assertEqual(len(adapter.revoked_resources), 0)
        self.assertEqual(len(adapter.query_direct_calls), 0)


if __name__ == "__main__":
    unittest.main()
