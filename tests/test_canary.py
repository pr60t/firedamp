"""
Unit and integration tests for Firedamp core engine, canary tokens, and leak detection.
Supports both Pytest and Python standard unittest runners.
"""

import json
import os
import sys
import tempfile
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
from core.target import OpenWebUIContainerManager, TargetEnvironment
from adapters import TargetAdapter, UserSession, ADAPTER_REGISTRY, get_adapter
from cli import run_scan_flow
from unittest.mock import MagicMock, patch


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
            channel="direct_api",
        )
        self.assertEqual(result.probe_category, "prompt_injection")
        self.assertEqual(result.channel, "direct_api")

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

    def test_reporter_markdown_rendering(self):
        """Verify Markdown PR-ready report generation for both clean and leaked audits."""
        reporter = FiredampReporter()
        engine = ProbingEngine()
        canaries = [CanaryToken.generate(category="financial", owner="Alice")]

        # Leaked summary
        results = [
            engine.evaluate_response("Query 1", f"Found {canaries[0].token}", [], canaries, probe_category="direct_semantic")
        ]
        summary = reporter.calculate_summary("openwebui", "http://localhost:8080", canaries, results)
        md = reporter.render_markdown(summary)

        self.assertIn("# 🚨 Firedamp Atmospheric Telemetry Report", md)
        self.assertIn("Firedamp Index", md)
        self.assertIn("Contaminated Airway Sample Logs", md)
        self.assertIn("direct_semantic", md)
        self.assertIn(canaries[0].token, md)

    def test_reporter_sarif_rendering(self):
        """Verify SARIF v2.1.0 output complies with GitHub Code Scanning schema requirements."""
        reporter = FiredampReporter()
        engine = ProbingEngine()
        canaries = [CanaryToken.generate(category="credentials", owner="Alice")]

        results = [
            engine.evaluate_response("Query 1", f"Exposed: {canaries[0].token}", [], canaries, probe_category="direct_semantic")
        ]
        summary = reporter.calculate_summary("openwebui", "http://localhost:8080", canaries, results)
        sarif = reporter.render_sarif(summary)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "Firedamp")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "FRDP001")
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")

    @patch("cli.RemoteTargetManager")
    @patch("cli.get_adapter")
    def test_e2e_mocked_scan_flow_success(self, mock_get_adapter, mock_target_mgr_cls):
        """Verify full run_scan_flow() pipeline from ingestion through probing and report export."""
        mock_mgr = MagicMock()
        mock_env = TargetEnvironment(
            name="openwebui",
            base_url="http://mock-target:8080",
            managed_by_docker=False
        )
        mock_mgr.start.return_value = mock_env
        mock_target_mgr_cls.return_value = mock_mgr

        mock_adapter = MagicMock(spec=TargetAdapter)
        mock_adapter.target_name = "openwebui"
        alice_session = UserSession(username="alice_owner", role="owner", token="alice_token")
        bob_session = UserSession(username="bob_attacker", role="attacker", token="bob_token")

        def fake_auth(url, username, password, role="user"):
            return alice_session if role == "owner" else bob_session

        mock_adapter.authenticate_user.side_effect = fake_auth
        planted_canary_tokens = []
        def fake_ingest(url, session, doc):
            for c in doc.canaries:
                planted_canary_tokens.append(c.token)
            return "kb-mock-123"

        mock_adapter.ingest_document.side_effect = fake_ingest

        def fake_query_rag(url, session, prompt, model=None):
            if session.role == "owner":
                token = planted_canary_tokens[0] if planted_canary_tokens else "CANARY-FRDP-NONE"
                return f"Baseline verification: {token}", [token], {}
            # Bob gets safe response (no leak)
            return "I have no access to that data.", [], {}

        mock_adapter.query_rag.side_effect = fake_query_rag
        mock_get_adapter.return_value = mock_adapter

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            exit_code = run_scan_flow(
                target="openwebui",
                target_url="http://mock-target:8080",
                canaries=2,
                output=tmp_path,
                format="json",
                fail_on_leak=True,
                dry_run=False,
            )

            self.assertEqual(exit_code, 0)
            mock_adapter.authenticate_user.assert_any_call(
                "http://mock-target:8080", username="alice_owner", password="AegisPassword!123", role="owner"
            )
            mock_adapter.authenticate_user.assert_any_call(
                "http://mock-target:8080", username="bob_attacker", password="BobPassword!456", role="attacker"
            )
            self.assertEqual(mock_adapter.ingest_document.call_count, 2)
            self.assertEqual(mock_adapter.query_rag.call_count, 3)  # 1 baseline + 2 Bob probes
            mock_adapter.cleanup.assert_called_once_with("http://mock-target:8080", alice_session)

            with open(tmp_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            self.assertEqual(report_data["status"], "CLEAR")
            self.assertEqual(report_data["total_canaries_planted"], 2)
            self.assertEqual(report_data["total_probes_dispatched"], 2)
            self.assertEqual(report_data["firedamp_index"], 0.0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @patch("cli.RemoteTargetManager")
    @patch("cli.get_adapter")
    @patch("cli.reporter.log_alert")
    def test_positive_baseline_failure_warning(self, mock_log_alert, mock_get_adapter, mock_target_mgr_cls):
        """Verify that scan warns user when Alice cannot retrieve her own canaries (indexing failure)."""
        mock_mgr = MagicMock()
        mock_env = TargetEnvironment(name="openwebui", base_url="http://mock-target:8080", managed_by_docker=False)
        mock_mgr.start.return_value = mock_env
        mock_target_mgr_cls.return_value = mock_mgr

        mock_adapter = MagicMock(spec=TargetAdapter)
        mock_adapter.authenticate_user.return_value = UserSession(username="alice", role="owner")
        mock_adapter.ingest_document.return_value = "kb-1"

        # Alice's baseline probe fails to retrieve any canary
        mock_adapter.query_rag.return_value = ("Sorry, I have no records found.", [], {})
        mock_get_adapter.return_value = mock_adapter

        exit_code = run_scan_flow(
            target="openwebui",
            target_url="http://mock-target:8080",
            canaries=2,
            dry_run=False,
        )

        self.assertEqual(exit_code, 0)
        alert_calls = [call.args[0] for call in mock_log_alert.call_args_list]
        self.assertTrue(any("Baseline warning: Alice could not retrieve her own canaries" in msg for msg in alert_calls))

    def test_registered_adapters_satisfy_contract(self):
        """Verify all registered adapters satisfy the TargetAdapter abstract protocol."""
        from adapters.openwebui import OpenWebUIAdapter
        self.assertIn("openwebui", ADAPTER_REGISTRY)

        required_methods = [
            "authenticate_user",
            "ingest_document",
            "query_rag",
            "cleanup",
        ]

        for adapter_name, adapter_cls in ADAPTER_REGISTRY.items():
            self.assertTrue(
                issubclass(adapter_cls, TargetAdapter),
                f"Adapter '{adapter_name}' must inherit from TargetAdapter"
            )
            instance = adapter_cls()
            self.assertTrue(isinstance(instance.target_name, str))
            self.assertTrue(len(instance.target_name) > 0)
            for method_name in required_methods:
                method = getattr(instance, method_name, None)
                self.assertIsNotNone(
                    method,
                    f"Adapter '{adapter_name}' missing required method '{method_name}'"
                )
                self.assertTrue(
                    callable(method),
                    f"'{method_name}' on adapter '{adapter_name}' must be callable"
                )


if __name__ == "__main__":
    unittest.main()
