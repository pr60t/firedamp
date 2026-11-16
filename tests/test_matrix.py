"""
Unit tests for core/matrix.py: Authorization Matrix Replay Engine (RAG Autorize).
"""

import unittest
from unittest.mock import MagicMock

from adapters.base import UserSession
from core.engine import CanaryToken, ProbingEngine
from core.matrix import (
    ActorRole,
    AuthorizationStatus,
    StructuralDiffComparator,
    AuthorizationMatrixRunner,
)


class TestAuthorizationMatrix(unittest.TestCase):
    """Test suite for RAG Autorize request replay and structural diff evaluation."""

    def setUp(self):
        self.engine = ProbingEngine()
        self.canary = CanaryToken.generate(category="financial", owner="Alice")
        self.alice = UserSession(
            username="alice",
            role="owner",
            token="alice-token",
            metadata={"file_ids": ["f-alice-1"], "knowledge_ids": ["kb-alice-1"]},
        )
        self.bob = UserSession(
            username="bob",
            role="attacker",
            token="bob-token",
            metadata={"file_ids": [], "knowledge_ids": []},
        )
        self.mock_adapter = MagicMock()

    def test_structural_diff_enforced_403(self):
        status, leaked, overlap, details = StructuralDiffComparator.evaluate(
            owner_resp={"id": "f1", "name": "doc.md", "data": "confidential"},
            replayed_status=403,
            replayed_resp={"error": "Forbidden", "code": 403},
            replayed_contexts=[],
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertEqual(status, AuthorizationStatus.ENFORCED)
        self.assertEqual(len(leaked), 0)

    def test_structural_diff_canary_leak(self):
        status, leaked, overlap, details = StructuralDiffComparator.evaluate(
            owner_resp={"id": "f1", "name": "doc.md"},
            replayed_status=200,
            replayed_resp={"id": "f1", "content": f"Secret {self.canary.token}"},
            replayed_contexts=[f"Citation: {self.canary.token}"],
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertEqual(status, AuthorizationStatus.BYPASS_LEAK)
        self.assertIn(self.canary.token, leaked)

    def test_structural_diff_high_overlap_bypass(self):
        # Even without canary token, returning 200 with identical JSON keys is a structural bypass
        owner_body = {"id": "f1", "name": "doc.md", "chunks": ["c1", "c2"], "tenant": "alice"}
        replayed_body = {"id": "f1", "name": "doc.md", "chunks": ["c1", "c2"], "tenant": "alice"}
        status, leaked, overlap, details = StructuralDiffComparator.evaluate(
            owner_resp=owner_body,
            replayed_status=200,
            replayed_resp=replayed_body,
            replayed_contexts=[],
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertEqual(status, AuthorizationStatus.BYPASS_STRUCTURAL)
        self.assertGreater(overlap, 0.7)

    def test_matrix_runner_dry_run(self):
        runner = AuthorizationMatrixRunner(engine=self.engine)
        report = runner.run_matrix(
            adapter=self.mock_adapter,
            base_url="http://mock-target:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            dry_run=True,
        )
        self.assertTrue(report.passed)
        self.assertEqual(report.total_violations, 0)
        self.assertEqual(len(report.operations), 7)
        self.assertEqual(len(report.actors), 3)  # Intruder, Ex-Member, Anonymous
        self.assertEqual(len(report.grid), 7 * 3)

        for cell in report.grid:
            self.assertEqual(cell.auth_status, AuthorizationStatus.ENFORCED)
            if cell.actor_role == ActorRole.ANONYMOUS:
                self.assertEqual(cell.http_status, 401)
            else:
                self.assertEqual(cell.http_status, 403)

    def test_matrix_runner_detects_live_bypass(self):
        # Simulate an adapter where Bob gets 200 OK on vector retrieval query
        def fake_json(url, method="GET", data=None, headers=None, timeout=30):
            if "retrieval/query" in url:
                return {"documents": [["leaked confidential chunk"]], "code": 200}
            return {"error": "Forbidden", "code": 403}

        self.mock_adapter._json_request.side_effect = fake_json
        runner = AuthorizationMatrixRunner(engine=self.engine)
        report = runner.run_matrix(
            adapter=self.mock_adapter,
            base_url="http://mock-target:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            dry_run=False,
        )
        # Vector query should fail enforcement
        vector_cells = [c for c in report.grid if "retrieval/query" in c.op_name]
        self.assertTrue(any(c.is_violation or c.auth_status == AuthorizationStatus.ANOMALY for c in vector_cells))


if __name__ == "__main__":
    unittest.main()

