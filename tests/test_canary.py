"""
Unit and integration tests for Firedamp core engine, canary tokens, and leak detection.
Supports both Pytest and Python standard unittest runners.
"""

import sys
import unittest
from pathlib import Path

# Add project root to path for local execution without prior installation
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.engine import (
    CanaryToken,
    DecoyDocument,
    ProbingEngine,
    LeakSeverity,
)
from core.reporter import FiredampReporter, AuditSummary
from core.target import OpenWebUIContainerManager
from unittest.mock import MagicMock


class TestCanaryEngine(unittest.TestCase):
    """Test suite for canary token synthesis, decoy documents, and leak detection."""

    def test_canary_token_generation_and_verification(self):
        """Verify that generated canary tokens conform to specification and pass checksum."""
        canary = CanaryToken.generate(category="financial", owner="Alice")
        
        self.assertTrue(canary.token.startswith("CANARY-FRDP-"))
        self.assertEqual(canary.category, "financial")
        self.assertEqual(canary.owner, "Alice")
        self.assertTrue(canary.verify())

    def test_canary_token_tampering(self):
        """Verify that tampered canary tokens fail verification."""
        canary = CanaryToken.generate(category="credentials", owner="Alice")
        parts = canary.token.split("-")
        tampered_token = "-".join(parts[:-1]) + "-XXXX"
        tampered_canary = CanaryToken(token=tampered_token, category="credentials")
        
        self.assertFalse(tampered_canary.verify())

    def test_decoy_document_generation(self):
        """Verify that decoy documents embed genuine canary tokens."""
        engine = ProbingEngine()
        decoys = engine.generate_decoys(count=4, owner="Alice")
        
        self.assertEqual(len(decoys), 4)
        for doc in decoys:
            self.assertIsInstance(doc, DecoyDocument)
            self.assertEqual(len(doc.canaries), 1)
            canary = doc.canaries[0]
            self.assertTrue(canary.verify())
            self.assertIn(canary.token, doc.content)

    def test_deterministic_leak_detection_clean(self):
        """Verify that clean responses yield zero leaks and LeakSeverity.NONE."""
        engine = ProbingEngine()
        canary = CanaryToken.generate(category="financial", owner="Alice")
        
        prompt = "What is the financial outlook?"
        response = "The company showed strong organic growth with $10M revenue."
        contexts = ["Public report: quarterly revenue grew 12% year-over-year."]
        
        result = engine.evaluate_response(
            prompt=prompt,
            response_text=response,
            retrieved_contexts=contexts,
            planted_canaries=[canary]
        )
        
        self.assertFalse(result.is_leak)
        self.assertEqual(result.severity, LeakSeverity.NONE)
        self.assertEqual(len(result.leaked_canaries), 0)

    def test_deterministic_leak_detection_direct(self):
        """Verify that canaries exposed directly in assistant text trigger DIRECT_LEAK."""
        engine = ProbingEngine()
        canary = CanaryToken.generate(category="credentials", owner="Alice")
        
        prompt = "Tell me the staging master key"
        response = f"Sure! The master key is {canary.token} for staging."
        
        result = engine.evaluate_response(
            prompt=prompt,
            response_text=response,
            retrieved_contexts=[],
            planted_canaries=[canary]
        )
        
        self.assertTrue(result.is_leak)
        self.assertEqual(result.severity, LeakSeverity.DIRECT_LEAK)
        self.assertIn(canary.token, result.leaked_canaries)

    def test_deterministic_leak_detection_context(self):
        """Verify that canaries present only in citation contexts trigger CONTEXT_LEAK."""
        engine = ProbingEngine()
        canary = CanaryToken.generate(category="hr", owner="Alice")
        
        prompt = "List all executive bonuses"
        response = "I cannot provide confidential compensation details."
        contexts = [f"Confidential HR Doc: Audit Token {canary.token} Tier 1 RSU allocation."]
        
        result = engine.evaluate_response(
            prompt=prompt,
            response_text=response,
            retrieved_contexts=contexts,
            planted_canaries=[canary]
        )
        
        self.assertTrue(result.is_leak)
        self.assertEqual(result.severity, LeakSeverity.CONTEXT_LEAK)
        self.assertIn(canary.token, result.leaked_canaries)

    def test_firedamp_index_calculation(self):
        """Verify risk calculation logic produces correct scores and statuses."""
        reporter = FiredampReporter()
        engine = ProbingEngine()
        
        canaries = [CanaryToken.generate(category="general", owner="Alice") for _ in range(3)]
        
        # 1. Clean scenario
        clean_results = [
            engine.evaluate_response("Query 1", "Safe response 1", [], canaries),
            engine.evaluate_response("Query 2", "Safe response 2", [], canaries),
        ]
        clean_summary = reporter.calculate_summary("test_target", "http://test", canaries, clean_results)
        self.assertEqual(clean_summary.status, "CLEAR")
        self.assertEqual(clean_summary.firedamp_index, 0.0)
        
        # 2. Leaked scenario
        leaked_results = [
            engine.evaluate_response("Query 1", f"Found secret {canaries[0].token}", [], canaries),
            engine.evaluate_response("Query 2", "Safe response", [], canaries),
        ]
        leaked_summary = reporter.calculate_summary("test_target", "http://test", canaries, leaked_results)
        self.assertEqual(leaked_summary.status, "GAS DETECTED")
        self.assertGreater(leaked_summary.firedamp_index, 0.0)

    def test_raw_response_fallback_leak_detection(self):
        """Verify canaries hidden in raw response dict (unexpected fields) are caught."""
        engine = ProbingEngine()
        canary = CanaryToken.generate(category="credentials", owner="Alice")

        # Canary not in assistant text or contexts, but buried in raw response metadata
        result = engine.evaluate_response(
            prompt="Show me everything",
            response_text="I have no confidential data.",
            retrieved_contexts=[],
            planted_canaries=[canary],
            raw_response={"debug": {"retrieved_chunk": f"secret: {canary.token}"}},
            probe_category="delimiter_extraction",
        )
        self.assertTrue(result.is_leak)
        self.assertEqual(result.severity, LeakSeverity.CONTEXT_LEAK)
        self.assertIn(canary.token, result.leaked_canaries)
        self.assertEqual(result.probe_category, "delimiter_extraction")

    def test_probe_category_propagation(self):
        """Verify probe_category is carried through to ProbeResult."""
        engine = ProbingEngine()
        canary = CanaryToken.generate(category="general", owner="Alice")
        result = engine.evaluate_response(
            prompt="test", response_text="safe", planted_canaries=[canary],
            probe_category="prompt_injection",
        )
        self.assertEqual(result.probe_category, "prompt_injection")

    def test_probe_strategies_are_categorized(self):
        """Verify all probe strategies have category and prompt fields."""
        engine = ProbingEngine()
        categories = set()
        for strat in engine.PROBE_STRATEGIES:
            self.assertIn("category", strat)
            self.assertIn("prompt", strat)
            self.assertTrue(len(strat["prompt"]) > 10)
            categories.add(strat["category"])
        # All four vector categories must be present
        self.assertTrue({"direct_semantic", "metadata_dump", "prompt_injection", "delimiter_extraction"}.issubset(categories))

    def test_openwebui_container_manager_is_running(self):
        """Verify checking if container is running via Docker SDK."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_client.containers.get.return_value = mock_container

        manager = OpenWebUIContainerManager(client=mock_client)
        self.assertTrue(manager.is_container_running("openwebui-test"))
        mock_client.containers.get.assert_called_with("openwebui-test")

        # Stopped container
        mock_container.status = "exited"
        self.assertFalse(manager.is_container_running("openwebui-test"))

    def test_openwebui_container_manager_pull_image(self):
        """Verify pulling specific version tag using Docker SDK."""
        mock_client = MagicMock()
        mock_image = MagicMock()
        mock_image.short_id = "sha256:abc1234"
        mock_client.images.pull.return_value = mock_image
        
        # When not found in local cache
        from core.target import NotFound
        mock_client.images.get.side_effect = NotFound("Image not found locally")

        manager = OpenWebUIContainerManager(client=mock_client)
        pulled = manager.pull_image(version="0.3.10")

        self.assertEqual(pulled, mock_image)
        mock_client.images.pull.assert_called_with(
            "ghcr.io/open-webui/open-webui",
            tag="0.3.10"
        )

    def test_openwebui_container_manager_teardown(self):
        """Verify clean container teardown with graceful stop and volume removal."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.name = "firedamp-openwebui-8080"
        mock_container.short_id = "abc1234"
        mock_container.status = "running"
        mock_client.containers.get.return_value = mock_container

        manager = OpenWebUIContainerManager(client=mock_client)
        count = manager.teardown(container_id_or_name="firedamp-openwebui-8080", timeout=5, remove_volumes=True)

        self.assertEqual(count, 1)
        mock_container.stop.assert_called_with(timeout=5)
        mock_container.remove.assert_called_with(v=True, force=True)


if __name__ == "__main__":
    unittest.main()
