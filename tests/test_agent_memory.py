"""
Unit and integration tests for Pillar 6: Agent, Memory & Tool Channels.
"""

import unittest
from adapters.base import TargetAdapter, UserSession
from core.engine import (
    CanaryToken,
    LeakSeverity,
    ProbeResult,
    ProbingEngine,
)
from probes.scenarios.agent_memory import (
    run_agent_memory_scenarios,
    test_tool_cache_isolation,
    test_user_memory_route_isolation,
)


class MockAgentMemoryAdapter(TargetAdapter):
    """Mock adapter simulating user memory and tool caching behaviors."""

    @property
    def target_name(self) -> str:
        return "mock_agent_memory"

    def __init__(self, leak_memory: bool = False, leak_tool_cache: bool = False):
        self.leak_memory = leak_memory
        self.leak_tool_cache = leak_tool_cache
        self.stored_memories = {}
        self.cached_tool_outputs = {}

    def authenticate_user(self, base_url, username, password, role="user"):
        return UserSession(
            username=username,
            role=role,
            metadata={"id": f"user-{username}"},
        )

    def ingest_document(self, base_url, session, document):
        return "doc-123"

    def create_user_memory(self, base_url, session, content):
        self.stored_memories.setdefault(session.username, []).append(content)
        return {"status": True}

    def get_user_memories(self, base_url, session, target_user_id=None):
        if self.leak_memory:
            # Cross-tenant BOLA leak: returns all memories regardless of requester
            all_mems = []
            for user, mems in self.stored_memories.items():
                for m in mems:
                    all_mems.append({"user": user, "content": m})
            return all_mems
        return [{"content": m} for m in self.stored_memories.get(session.username, [])]

    def execute_tool_action(self, base_url, session, tool_name, tool_input):
        key = (tool_name, tool_input.get("query", ""))
        if session.username == "alice":
            self.cached_tool_outputs[key] = f"Tool output with token: {tool_input.get('nonce', '')}"
            return {"result": self.cached_tool_outputs[key]}

        # Bob requests:
        if self.leak_tool_cache and key in self.cached_tool_outputs:
            return {"result": self.cached_tool_outputs[key], "cached": True}
        return {"result": "Fresh unprivileged result"}

    def query_rag(self, base_url, session, prompt):
        if self.leak_memory and session.username == "bob":
            for user, mems in self.stored_memories.items():
                if user != "bob" and mems:
                    return (f"Recalled memory: {mems[0]}", [mems[0]], {})
        if self.leak_tool_cache and session.username == "bob":
            for key, val in self.cached_tool_outputs.items():
                return (f"Cached tool output: {val}", [val], {})
        return ("No memories or cached tool outputs found.", [], {})

    def query_resource_direct(self, base_url, session, resource_ref, k=50):
        if self.leak_memory and session.username == "bob" and "user-memory" in resource_ref:
            for user, mems in self.stored_memories.items():
                if mems:
                    return (f"Direct memory vector: {mems[0]}", [mems[0]], {})
        return ("403 Forbidden: Memory collection denied.", [], {"code": 403})

    def overwrite_resource(self, base_url, session, resource_ref, payload):
        return {"status": False}

    def enumerate_resources(self, base_url, session):
        return []

    def share_resource(self, base_url, owner, resource_ref, grantee):
        return {"status": True}

    def revoke_resource(self, base_url, owner, resource_ref, grantee):
        return {"status": True}

    def cleanup(self, base_url, session):
        pass


class TestAgentMemoryScenarios(unittest.TestCase):
    """Test suite for agent memory and tool cache isolation probes."""

    def setUp(self):
        self.engine = ProbingEngine()
        self.alice = UserSession("alice", "owner", metadata={"id": "user-alice"})
        self.bob = UserSession("bob", "attacker", metadata={"id": "user-bob"})

    def test_user_memory_route_isolation_dry_run(self):
        """Verify dry-run execution of user memory isolation probe."""
        adapter = MockAgentMemoryAdapter()
        res = test_user_memory_route_isolation(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:agent_memory:user_memory_isolation")
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.channel, "direct_api")

    def test_user_memory_route_isolation_clean(self):
        """Verify live execution when platform properly isolates user memory routes."""
        adapter = MockAgentMemoryAdapter(leak_memory=False)
        res = test_user_memory_route_isolation(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_user_memory_route_isolation_leak_detected(self):
        """Verify probe catches cross-tenant memory leakage when Bob accesses Alice's scratchpad."""
        adapter = MockAgentMemoryAdapter(leak_memory=True)
        res = test_user_memory_route_isolation(
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

    def test_tool_cache_isolation_dry_run(self):
        """Verify dry-run execution of tool cache isolation probe."""
        adapter = MockAgentMemoryAdapter()
        res = test_tool_cache_isolation(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(res.probe_category, "scenario:agent_memory:tool_cache_isolation")
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertFalse(res.is_leak)

    def test_tool_cache_isolation_clean(self):
        """Verify live execution when tool caches are properly isolated."""
        adapter = MockAgentMemoryAdapter(leak_tool_cache=False)
        res = test_tool_cache_isolation(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertFalse(res.is_leak)

    def test_tool_cache_isolation_leak_detected(self):
        """Verify probe catches cache bleed when Bob queries an identical tool operation."""
        adapter = MockAgentMemoryAdapter(leak_tool_cache=True)
        res = test_tool_cache_isolation(
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

    def test_run_agent_memory_scenarios_suite(self):
        """Verify runner executes all agent memory and tool cache scenario probes."""
        adapter = MockAgentMemoryAdapter()
        results = run_agent_memory_scenarios(
            adapter=adapter,
            base_url="http://mock",
            alice=self.alice,
            bob=self.bob,
            engine=self.engine,
            dry_run=True,
        )
        self.assertEqual(len(results), 2)
        categories = [r.probe_category for r in results]
        self.assertIn("scenario:agent_memory:user_memory_isolation", categories)
        self.assertIn("scenario:agent_memory:tool_cache_isolation", categories)
        for r in results:
            self.assertEqual(r.channel, "direct_api")
            self.assertFalse(r.is_leak)


if __name__ == "__main__":
    unittest.main()

