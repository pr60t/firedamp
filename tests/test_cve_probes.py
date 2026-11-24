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
from probes.cves.cve_2026_28788 import (
    register_trusted_disposable_resource,
    clear_trusted_registry,
)


class TestCVEBehavioralProbes(unittest.TestCase):
    """Test suite verifying behavioral execution and leak detection of CVE fixtures."""

    def setUp(self):
        self.run_id = "test-run-cve28788"
        self.engine = ProbingEngine(run_id=self.run_id)
        self.canary = CanaryToken.generate(category="financial", owner="Alice")
        self.alice = UserSession(
            username="alice",
            role="owner",
            token="token-alice",
            metadata={
                "run_id": self.run_id,
                "user_id": "alice-user-uuid-123",
                "file_ids": ["f123"],
                "knowledge_ids": ["kb-uuid-456"],
                "disposable_file_ids": ["disposable-f123"],
                "disposable_provenance": {
                    "disposable-f123": {
                        "file_id": "disposable-f123",
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
            role="attacker",
            token="token-bob",
            metadata={"run_id": self.run_id, "user_id": "bob-user-uuid-456", "file_ids": [], "knowledge_ids": []},
        )
        self.mock_adapter = MagicMock()
        self.mock_adapter.enumerate_resources.return_value = []
        self.mock_adapter.validate_session.return_value = True
        self.mock_adapter.get_authenticated_user_id.side_effect = (
            lambda base, sess: sess.metadata.get("user_id") if self.mock_adapter.validate_session(base, sess) else None
        )
        self.mock_adapter.get_file_metadata.side_effect = lambda base, sess, fid: {
            "id": fid,
            "user_id": sess.metadata.get("user_id", sess.username),
            "owner": sess.username,
        }
        self.mock_adapter.delete_file.return_value = True
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        self.mock_adapter.get_accessible_knowledge_bases.side_effect = (
            lambda base, sess: list(sess.metadata.get("knowledge_ids", [])) if isinstance(sess.metadata, dict) else []
        )

        def _mock_get_kb_files(base, sess, kb):
            if kb != "kb-uuid-456":
                return []
            files = ["disposable-f123", "f123"]
            if isinstance(sess.metadata, dict):
                files.extend(sess.metadata.get("disposable_file_ids", []))
                files.extend(sess.metadata.get("file_ids", []))
                prov = sess.metadata.get("disposable_provenance")
                if isinstance(prov, dict):
                    files.extend(prov.keys())
            if hasattr(self.mock_adapter, "ingest_document") and hasattr(self.mock_adapter.ingest_document, "return_value"):
                ret = self.mock_adapter.ingest_document.return_value
                if isinstance(ret, str) and ret:
                    files.append(ret)
            return list(dict.fromkeys(files))

        self.mock_adapter.get_knowledge_base_files.side_effect = _mock_get_kb_files
        register_trusted_disposable_resource(self.run_id, "disposable-f123", "alice")

    def tearDown(self):
        clear_trusted_registry()

    def test_cve_2026_44560_clean(self):
        self.mock_adapter.query_rag.return_value = (
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
        self.assertEqual(res.channel, "citation_metadata")
        self.mock_adapter.query_rag.assert_called_with(
            "http://mock:8080",
            self.bob,
            prompt="Summarize the confidential canary contents from the attached file.",
            files=[{"type": "file", "id": "f123"}],
        )

    def test_cve_2026_44560_leak(self):
        # Bob receives Alice's canary through unauthorized file attachment in chat completions
        self.mock_adapter.query_rag.return_value = (
            f"Here is the data: {self.canary.token}",
            [f"Chunk: {self.canary.token}"],
            {"sources": [{"document": [self.canary.token]}]},
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

    def test_cve_2026_44560_missing_target_file_id_returns_inconclusive(self):
        """When victim (Alice) has no file IDs, CVE-2026-44560 probe returns INCONCLUSIVE and does not query."""
        alice_no_files = UserSession(
            username="alice",
            role="owner",
            token="token-alice",
            metadata={"file_ids": []},
        )
        res = cve_2026_44560.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=alice_no_files,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_inconclusive)
        self.assertFalse(res.is_clean)
        self.assertFalse(res.is_leak)
        self.assertTrue(res.inconclusive)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Missing required target file ID", res.target_response)
        self.mock_adapter.query_rag.assert_not_called()

    def test_cve_2026_44560_malformed_target_file_id_returns_inconclusive(self):
        """When victim (Alice) has malformed file ID entries, probe returns INCONCLUSIVE and does not query."""
        alice_bad_files = UserSession(
            username="alice",
            role="owner",
            token="token-alice",
            metadata={"file_ids": ["   "]},
        )
        res = cve_2026_44560.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=alice_bad_files,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_inconclusive)
        self.assertFalse(res.is_clean)
        self.assertFalse(res.is_leak)
        self.assertTrue(res.inconclusive)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.mock_adapter.query_rag.assert_not_called()

    def test_cve_2026_45398_raw_uuid_leak(self):
        self.mock_adapter.query_collection.return_value = (
            "",
            [f"Document content containing {self.canary.token}"],
            {},
        )
        self.mock_adapter.query_doc.return_value = ("", [], {})
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
        self.mock_adapter.query_collection.assert_called_with(
            "http://mock:8080",
            self.bob,
            collection_names=["kb-uuid-456"],
            query="anything",
            k=10,
            hybrid=False,
        )
        self.mock_adapter.query_doc.assert_called_with(
            "http://mock:8080",
            self.bob,
            collection_name="kb-uuid-456",
            query="anything",
            k=10,
        )

    def test_cve_2026_45398_missing_target_uuid_returns_inconclusive(self):
        """When victim (Alice) has no knowledge base IDs, CVE-2026-45398 probe returns INCONCLUSIVE and does not query."""
        alice_no_kbs = UserSession(
            username="alice",
            role="owner",
            token="token-alice",
            metadata={"knowledge_ids": []},
        )
        res = cve_2026_45398.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=alice_no_kbs,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_inconclusive)
        self.assertFalse(res.is_clean)
        self.assertFalse(res.is_leak)
        self.assertTrue(res.inconclusive)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Missing required target knowledge base UUID", res.target_response)
        self.mock_adapter.query_collection.assert_not_called()
        self.mock_adapter.query_doc.assert_not_called()

    def test_cve_2026_45398_malformed_target_uuid_returns_inconclusive(self):
        """When victim (Alice) has malformed knowledge base entries, probe returns INCONCLUSIVE and does not query."""
        alice_bad_kbs = UserSession(
            username="alice",
            role="owner",
            token="token-alice",
            metadata={"knowledge_ids": ["   "]},
        )
        res = cve_2026_45398.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=alice_bad_kbs,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_inconclusive)
        self.assertFalse(res.is_clean)
        self.assertFalse(res.is_leak)
        self.assertTrue(res.inconclusive)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.mock_adapter.query_collection.assert_not_called()
        self.mock_adapter.query_doc.assert_not_called()

    def test_cve_2026_28788_vulnerable_v085_response_produces_compromised(self):
        """Vulnerable v0.8.5-style HTTP 200 with target in results['completed'] and tracer verified produces COMPROMISED."""
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "completed"}],
            "errors": [],
        }
        def mock_read_file(base, sess, fid):
            last_call = self.mock_adapter.overwrite_resource.call_args
            if last_call:
                return last_call[1]["payload"]
            return "Original clean baseline content"

        self.mock_adapter.read_file_content.side_effect = mock_read_file

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
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)
        self.assertIn("COMPROMISED", res.target_response)
        self.assertEqual(self.mock_adapter.read_file_content.call_count, 2)

    def test_cve_2026_28788_patched_v086_response_produces_clean(self):
        """Patched v0.8.6-style HTTP 200 with target in errors and permission-denied reason produces CLEAN."""
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }
        self.mock_adapter.read_file_content.return_value = "Verified unchanged indexed content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_generic_processing_error_produces_inconclusive(self):
        """HTTP 200 with a generic per-file processing error produces INCONCLUSIVE."""
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Generic conversion error: invalid encoding",
                }
            ],
        }
        self.mock_adapter.read_file_content.return_value = "Verified unchanged indexed content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertNotIn("CLEAN", res.target_response)

    def test_cve_2026_28788_missing_target_entry_produces_inconclusive(self):
        """HTTP 200 with no matching target in either results or errors produces INCONCLUSIVE."""
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "other-unrelated-file-id", "status": "completed"}],
            "errors": [],
        }
        self.mock_adapter.read_file_content.return_value = "Verified unchanged indexed content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_completed_operation_with_unavailable_or_ambiguous_readback_never_clean(self):
        """A completed operation with unavailable or ambiguous readback never produces CLEAN."""
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "completed"}],
            "errors": [],
        }
        # 1. Unavailable readback -> INCONCLUSIVE
        self.mock_adapter.read_file_content.return_value = None
        res_unavailable = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res_unavailable.is_leak)
        self.assertIn("INCONCLUSIVE", res_unavailable.target_response)
        self.assertNotIn("CLEAN", res_unavailable.target_response)

        # 2. Ambiguous readback (tracer absent after retries) -> INCONCLUSIVE
        self.mock_adapter.read_file_content.return_value = "Intact file without tracer"
        res_ambiguous = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res_ambiguous.is_leak)
        self.assertIn("INCONCLUSIVE", res_ambiguous.target_response)
        self.assertNotIn("CLEAN", res_ambiguous.target_response)

    def test_cve_2026_28788_http_405_produces_inconclusive(self):
        """HTTP 405 Method Not Allowed produces INCONCLUSIVE (not an authorization block)."""
        self.mock_adapter.overwrite_resource.return_value = {"error": "Method Not Allowed", "code": 405}
        self.mock_adapter.read_file_content.return_value = "Clean indexed content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("405", res.target_response)

    def test_cve_2026_28788_raw_uploaded_content_cannot_establish_indexed_clean(self):
        """Raw uploaded content cannot establish an indexed-content CLEAN verdict."""
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "completed"}],
            "errors": [],
        }
        self.mock_adapter.read_file_content.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertNotIn("CLEAN", res.target_response)

    def test_cve_2026_28788_provisioning_failure_returns_inconclusive_and_no_overwrite_request(self):
        """Provisioning failure returns INCONCLUSIVE and sends no overwrite request."""
        self.alice.metadata["disposable_file_ids"] = []
        self.alice.metadata.pop("disposable_provenance", None)
        self.mock_adapter.ingest_document.side_effect = RuntimeError("Failed to provision disposable target")

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("provisioning failed", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_arbitrary_id_in_disposable_file_ids_is_rejected(self):
        """An arbitrary ID in disposable_file_ids without provenance is rejected with no overwrite sent."""
        self.alice.metadata["disposable_file_ids"] = ["arbitrary-unregistered-id-999"]
        self.alice.metadata["disposable_provenance"] = {}

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("registry verification", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_stale_disposable_id_is_rejected(self):
        """A stale disposable ID from a prior run is rejected with no overwrite sent."""
        self.alice.metadata["disposable_file_ids"] = ["stale-disposable-1"]
        self.alice.metadata["disposable_provenance"] = {
            "stale-disposable-1": {
                "file_id": "stale-disposable-1",
                "provisioned_by": "firedamp",
                "owner": "alice",
                "run_id": "stale-prior-run-id",
                "active": True,
            }
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_unverified_disposable_id_rejected_when_ordinary_file(self):
        """Target in ordinary file_ids is rejected with no overwrite sent."""
        self.alice.metadata["file_ids"] = ["f123"]
        self.alice.metadata["disposable_file_ids"] = ["f123"]
        self.alice.metadata["disposable_provenance"] = {
            "f123": {
                "file_id": "f123",
                "provisioned_by": "firedamp",
                "owner": "alice",
                "run_id": self.run_id,
                "active": True,
            }
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_unverified_disposable_id_rejected_when_wrong_owner_or_inactive(self):
        """Target with wrong owner or inactive state is rejected with no overwrite sent."""
        self.alice.metadata["disposable_file_ids"] = ["wrong-owner-file"]
        self.alice.metadata["disposable_provenance"] = {
            "wrong-owner-file": {
                "file_id": "wrong-owner-file",
                "provisioned_by": "firedamp",
                "owner": "mallory",
                "run_id": self.run_id,
                "active": True,
            }
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_verified_current_run_disposable_target_can_proceed(self):
        """A verified current-run disposable target can proceed to overwrite testing."""
        self.alice.metadata["disposable_file_ids"] = ["verified-current-target"]
        self.alice.metadata["disposable_provenance"] = {
            "verified-current-target": {
                "file_id": "verified-current-target",
                "provisioned_by": "firedamp",
                "owner": "alice",
                "run_id": self.run_id,
                "active": True,
            }
        }
        register_trusted_disposable_resource(self.run_id, "verified-current-target", "alice")
        self.mock_adapter.read_file_content.return_value = "Baseline verified content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "verified-current-target",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        call_kwargs = self.mock_adapter.overwrite_resource.call_args[1]
        self.assertEqual(call_kwargs["resource_ref"], "verified-current-target")
        self.assertFalse(res.is_leak)
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_no_destructive_request_sent_when_provenance_cannot_be_verified(self):
        """No destructive request is sent when target ownership or provenance cannot be verified."""
        self.alice.metadata["disposable_file_ids"] = ["unverifiable-target"]
        self.alice.metadata["disposable_provenance"] = {
            "unverifiable-target": {
                "file_id": "unverifiable-target",
                "provisioned_by": "untrusted_source",
                "owner": "alice",
                "run_id": self.run_id,
                "active": True,
            }
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_dynamic_provisioning_success_registers_provenance_and_proceeds(self):
        """Dynamic provisioning success registers provenance and proceeds with overwrite testing."""
        self.alice.metadata["disposable_file_ids"] = []
        self.alice.metadata["disposable_provenance"] = {}
        self.mock_adapter.ingest_document.return_value = "dynamic-target-file-1"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "dynamic-target-file-1",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.ingest_document.assert_called_once()
        self.mock_adapter.overwrite_resource.assert_called_once()
        call_kwargs = self.mock_adapter.overwrite_resource.call_args[1]
        self.assertEqual(call_kwargs["resource_ref"], "dynamic-target-file-1")
        self.assertIn("dynamic-target-file-1", self.alice.metadata["disposable_file_ids"])
        prov = self.alice.metadata["disposable_provenance"]["dynamic-target-file-1"]
        self.assertEqual(prov["provisioned_by"], "firedamp")
        self.assertEqual(prov["owner"], "alice")
        self.assertEqual(prov["run_id"], self.run_id)
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_http_403_clean_when_attacker_auth_verified_and_baseline_intact(self):
        """HTTP 403 reports CLEAN when attacker auth is independently validated and indexed baseline intact."""
        self.mock_adapter.enumerate_resources.return_value = ["bob-doc-1"]
        self.mock_adapter.overwrite_resource.return_value = {"error": "Forbidden", "code": 403}
        self.mock_adapter.read_file_content.return_value = "Verified unchanged indexed content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("CLEAN", res.target_response)
        self.assertIn("403", res.target_response)

    def test_cve_2026_28788_http_403_inconclusive_when_attacker_auth_fails(self):
        """HTTP 403 reports INCONCLUSIVE when attacker auth cannot be independently validated."""
        self.mock_adapter.validate_session.return_value = False
        self.mock_adapter.overwrite_resource.return_value = {"error": "Forbidden", "code": 403}
        self.mock_adapter.read_file_content.return_value = "Verified unchanged indexed content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertNotIn("CLEAN", res.target_response)
        self.assertIn("attacker authentication", res.target_response.lower())

    def test_cve_2026_28788_http_403_inconclusive_when_target_baseline_missing(self):
        """HTTP 403 reports INCONCLUSIVE when target baseline cannot be established."""
        self.mock_adapter.enumerate_resources.return_value = []
        self.mock_adapter.read_file_content.return_value = None
        self.mock_adapter.overwrite_resource.return_value = {"error": "Forbidden", "code": 403}

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertNotIn("CLEAN", res.target_response)

    def test_cve_2026_28788_http_403_compromised_when_tracer_in_victim_content(self):
        """HTTP 403 reports COMPROMISED if attacker tracer is verified in victim indexed content."""
        self.mock_adapter.enumerate_resources.return_value = []
        self.mock_adapter.overwrite_resource.return_value = {"error": "Forbidden", "code": 403}

        def mock_read_file(base, sess, fid):
            last_call = self.mock_adapter.overwrite_resource.call_args
            if last_call:
                return last_call[1]["payload"]
            return "Original clean baseline content"

        self.mock_adapter.read_file_content.side_effect = mock_read_file

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
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)
        self.assertIn("COMPROMISED", res.target_response)
        self.assertNotIn("CLEAN", res.target_response)

    def test_cve_2026_28788_http_404_without_baseline_produces_inconclusive(self):
        """HTTP 404 without confirmed baseline produces INCONCLUSIVE."""
        self.mock_adapter.overwrite_resource.return_value = {"error": "Not Found", "code": 404}
        self.mock_adapter.read_file_content.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_dry_run_non_destructive(self):
        """Dry-run must be genuinely non-destructive: no provisioning, no network calls, honest skipped result."""
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
            dry_run=True,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("SKIPPED: Dry-run enabled", res.target_response)
        self.mock_adapter.ingest_document.assert_not_called()
        self.mock_adapter.get_file_metadata.assert_not_called()
        self.mock_adapter.validate_session.assert_not_called()
        self.mock_adapter.get_authenticated_user_id.assert_not_called()
        self.mock_adapter.read_file_content.assert_not_called()
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.mock_adapter.delete_file.assert_not_called()

    def test_cve_2026_28788_engine_run_id_matching_alice_proceeds(self):
        """Matching authoritative engine and Alice run IDs proceed to overwrite testing."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_missing_run_id_aborts_inconclusive(self):
        """Missing authoritative engine run ID aborts with INCONCLUSIVE and sends no overwrite request."""
        engine_no_run = ProbingEngine(run_id=None)
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=engine_no_run,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("engine run id is missing or empty", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_empty_engine_run_id_aborts_inconclusive(self):
        """Empty or whitespace engine run ID aborts with INCONCLUSIVE and sends no overwrite request."""
        engine_empty_run = ProbingEngine(run_id="   ")
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=engine_empty_run,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("engine run id is missing or empty", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_alice_run_id_mismatch_aborts_inconclusive(self):
        """Alice metadata containing a stale/conflicting run ID aborts with INCONCLUSIVE and sends no overwrite request."""
        self.alice.metadata["run_id"] = "stale-conflicting-run-id"
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("conflicts with", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_locally_fabricated_provenance_rejected(self):
        """Locally fabricated provenance in metadata without trusted registry entry is rejected."""
        clear_trusted_registry()
        self.alice.metadata["disposable_file_ids"] = ["fabricated-target-1"]
        self.alice.metadata["disposable_provenance"] = {
            "fabricated-target-1": {
                "file_id": "fabricated-target-1",
                "provisioned_by": "firedamp",
                "owner": "alice",
                "run_id": self.run_id,
                "active": True,
            }
        }
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("registry verification", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_repeated_scans_with_different_run_ids(self):
        """Repeated scans with different run IDs isolate disposable targets to their owning run."""
        run_1 = "scan-run-001"
        run_2 = "scan-run-002"
        target_run_1 = "target-from-run-1"
        register_trusted_disposable_resource(run_1, target_run_1, "alice")

        # Scan 2 attempts to use target from run 1
        self.alice.metadata["run_id"] = run_2
        self.alice.metadata["disposable_file_ids"] = [target_run_1]
        engine_run_2 = ProbingEngine(run_id=run_2)

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=engine_run_2,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_server_ownership_cannot_be_established(self):
        """When server metadata returns None, probe aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = None
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("metadata", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_missing_server_side_user_id_aborts_inconclusive(self):
        """Missing server-side user_id aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {"id": "disposable-f123"}
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("missing or empty in file metadata", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_empty_server_side_user_id_aborts_inconclusive(self):
        """Empty server-side user_id aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {"id": "disposable-f123", "user_id": "   "}
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("missing or empty in file metadata", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_missing_alice_server_user_id_aborts_inconclusive(self):
        """Missing Alice server user ID in session metadata aborts with INCONCLUSIVE and sends no overwrite."""
        self.alice.metadata.pop("user_id", None)
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("missing or empty in session context", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_empty_alice_server_user_id_aborts_inconclusive(self):
        """Empty Alice server user ID in session metadata aborts with INCONCLUSIVE and sends no overwrite."""
        self.alice.metadata["user_id"] = "   "
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("missing or empty in session context", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_server_ownership_mismatch_rejected(self):
        """When server metadata reports a different owner, probe aborts without overwrite."""
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": "disposable-f123",
            "user_id": "mallory-other-user",
            "owner": "mallory-other-user",
        }
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("does not match", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_server_ownership_successful_exact_match(self):
        """Exact server user_id match allows overwrite testing to proceed."""
        self.alice.metadata["user_id"] = "exact-alice-uuid-999"
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": "disposable-f123",
            "user_id": "exact-alice-uuid-999",
        }
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_pre_write_guard_target_existence_failed(self):
        """When server metadata returns an ID mismatch, probe aborts without overwrite."""
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": "different-file-id",
            "user_id": "alice-user-uuid-123",
        }
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("does not match", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_pre_write_guard_baseline_content_retrieval_failed(self):
        """When pre-write baseline retrieval fails, probe aborts with INCONCLUSIVE and no overwrite."""
        self.mock_adapter.read_file_content.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("baseline content", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_pre_write_guard_baseline_hash_computation_failed(self):
        """When pre-write baseline content cannot be hashed, probe aborts with INCONCLUSIVE."""
        self.mock_adapter.read_file_content.return_value = 12345  # Unsupported type for SHA-256

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("sha-256", res.target_response.lower())
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_attacker_identity_correct_bob(self):
        """When authenticated user matches expected Bob user_id, verification succeeds and proceeds."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = "bob-user-uuid-456"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_attacker_identity_token_belongs_to_alice_inconclusive(self):
        """When token belongs to Alice instead of Bob, aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = "alice-user-uuid-123"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Authenticated session identity 'alice-user-uuid-123' does not match expected attacker persona ID 'bob-user-uuid-456'", res.target_response)

    def test_cve_2026_28788_attacker_identity_token_belongs_to_third_user_inconclusive(self):
        """When token belongs to a third user, aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = "third-party-uuid-999"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("third-party-uuid-999", res.target_response)

    def test_cve_2026_28788_attacker_identity_missing_bob_user_id_inconclusive(self):
        """When Bob session context is missing user_id, aborts with INCONCLUSIVE and sends no overwrite."""
        self.bob.metadata["user_id"] = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Expected attacker server user ID is missing or empty", res.target_response)

    def test_cve_2026_28788_attacker_identity_missing_response_id_inconclusive(self):
        """When adapter returns empty or missing ID, aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Attacker authentication failed or returned empty server user ID", res.target_response)

    def test_cve_2026_28788_attacker_identity_http_401_and_403_inconclusive(self):
        """When attacker session returns 401 or 403, aborts with INCONCLUSIVE and sends no overwrite."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_attacker_identity_transport_failure_inconclusive(self):
        """When attacker identity query encounters transport error, reports INCONCLUSIVE."""
        self.mock_adapter.get_authenticated_user_id.side_effect = ConnectionError("Network unreachable")

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("transport error: network unreachable", res.target_response.lower())

    def test_cve_2026_28788_attacker_identity_zero_resources_succeeds(self):
        """Attacker with 0 resources is verified through get_authenticated_user_id and proceeds."""
        self.mock_adapter.get_authenticated_user_id.side_effect = None
        self.mock_adapter.get_authenticated_user_id.return_value = "bob-user-uuid-456"
        self.mock_adapter.enumerate_resources.return_value = []
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_adapter_with_only_boolean_validate_session_fails_closed(self):
        """Adapter that only supports boolean validate_session() fails closed without invoking overwrite."""
        self.mock_adapter.validate_session.return_value = True
        del self.mock_adapter.get_authenticated_user_id

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Adapter does not support authoritative user ID retrieval", res.target_response)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_simulated_cli_identities_distinct_and_validated(self):
        """Simulated CLI Alice and Bob sessions have distinct synthetic IDs correctly verified by SimulatedCLIAdapter."""
        from cli import SimulatedCLIAdapter
        sim_adapter = SimulatedCLIAdapter()
        scan_run_id = self.run_id

        alice_session = UserSession(
            username="alice_owner",
            role="owner",
            token="simulated-alice-token",
            metadata={
                "run_id": scan_run_id,
                "user_id": "sim-alice-user-id",
                "file_ids": ["sim-file-1"],
                "knowledge_ids": ["sim-kb-uuid-1"],
            },
        )
        bob_session = UserSession(
            username="bob_attacker",
            role="attacker",
            token="simulated-bob-token",
            metadata={
                "run_id": scan_run_id,
                "user_id": "sim-bob-user-id",
                "file_ids": [],
                "knowledge_ids": [],
            },
        )

        # 1. Distinct synthetic server user IDs
        self.assertNotEqual(alice_session.metadata["user_id"], bob_session.metadata["user_id"])
        self.assertEqual(alice_session.metadata["user_id"], "sim-alice-user-id")
        self.assertEqual(bob_session.metadata["user_id"], "sim-bob-user-id")

        # 2. Simulated adapter returns matching ID for each session
        alice_auth_id = sim_adapter.get_authenticated_user_id("http://mock-simulation:8080", alice_session)
        bob_auth_id = sim_adapter.get_authenticated_user_id("http://mock-simulation:8080", bob_session)
        self.assertEqual(alice_auth_id, "sim-alice-user-id")
        self.assertEqual(bob_auth_id, "sim-bob-user-id")
        self.assertNotEqual(alice_auth_id, bob_auth_id)

        # 3. Correct validation via _validate_attacker_identity
        is_valid, err = cve_2026_28788._validate_attacker_identity(
            sim_adapter, "http://mock-simulation:8080", bob_session
        )
        self.assertTrue(is_valid)
        self.assertIsNone(err)

        # 4. Probe rejects mismatch (e.g. if Alice's token/session were passed as Bob)
        impersonating_bob = UserSession(
            username="bob_attacker",
            role="attacker",
            token="simulated-alice-token",
            metadata={
                "run_id": scan_run_id,
                "user_id": "sim-bob-user-id",
                "file_ids": [],
                "knowledge_ids": [],
            },
        )
        mock_impersonating_adapter = MagicMock()
        mock_impersonating_adapter.get_authenticated_user_id.return_value = "sim-alice-user-id"
        is_valid, err = cve_2026_28788._validate_attacker_identity(
            mock_impersonating_adapter, "http://mock-simulation:8080", impersonating_bob
        )
        self.assertFalse(is_valid)
        self.assertIn("INCONCLUSIVE", err)
        self.assertIn("does not match", err)

    def test_cve_2026_28788_auth_validation_transport_error(self):
        """When validate_session encounters transport error, reports INCONCLUSIVE."""
        self.mock_adapter.validate_session.side_effect = ConnectionError("Connection refused")
        self.mock_adapter.overwrite_resource.return_value = {"error": "Forbidden", "code": 403}
        self.mock_adapter.read_file_content.return_value = "Baseline content"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("attacker authentication", res.target_response.lower())

    def test_cve_2026_28788_auth_validation_authenticated_with_zero_resources(self):
        """Attacker with 0 resources but valid session is treated as authenticated."""
        self.mock_adapter.validate_session.return_value = True
        self.mock_adapter.enumerate_resources.return_value = []
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_http_404_without_auth_rejection_evidence_inconclusive(self):
        """HTTP 404 without authorization-specific rejection evidence produces INCONCLUSIVE."""
        self.mock_adapter.validate_session.return_value = True
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "error": "File not found in system",
            "code": 404,
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("404", res.target_response)

    def test_cve_2026_28788_http_404_with_auth_rejection_evidence_clean(self):
        """HTTP 404 with authorization-specific rejection evidence and intact baseline produces CLEAN."""
        self.mock_adapter.validate_session.return_value = True
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "error": "Permission denied: resource not found or unauthorized",
            "code": 404,
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("CLEAN", res.target_response)

    def test_cve_2026_28788_contradictory_batch_response_inconclusive(self):
        """Target file appearing in both results and errors lists is rejected as contradictory."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "completed"}],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("contradictory", res.target_response.lower())

    def test_cve_2026_28788_undocumented_success_status_inconclusive(self):
        """Undocumented status 'success' in results produces INCONCLUSIVE."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "success"}],
            "errors": [],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("expected exact 'completed'", res.target_response.lower())

    def test_cve_2026_28788_undocumented_queued_status_inconclusive(self):
        """Undocumented status 'queued' in results produces INCONCLUSIVE."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "queued"}],
            "errors": [],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("expected exact 'completed'", res.target_response.lower())

    def test_cve_2026_28788_undocumented_boolean_status_inconclusive(self):
        """Response with legacy boolean status and no results/errors lists is rejected as malformed."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {"status": True}

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("missing results and errors", res.target_response.lower())

    def test_cve_2026_28788_target_omitted_from_both_results_and_errors_inconclusive(self):
        """Target file omitted from both results and errors lists produces INCONCLUSIVE."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "other-unrelated-file-id", "status": "completed"}],
            "errors": [],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("omitted target file", res.target_response.lower())

    def test_cve_2026_28788_malformed_non_dict_response_inconclusive(self):
        """Non-dict response from overwrite endpoint produces INCONCLUSIVE."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = ["malformed", "list"]

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("malformed non-dict response", res.target_response.lower())

    def test_cve_2026_28788_pre_existing_resource_not_deleted(self):
        """Pre-existing resources passed via disposable_file_ids are not deleted by this probe invocation."""
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "disposable-f123",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_not_called()
        self.assertNotIn("cleanup", res.target_response.lower())

    def test_cve_2026_28788_cleanup_attempted_after_post_provisioning_ownership_failure(self):
        """When server ownership verification fails after provisioning, deletion is NOT attempted and CLEANUP SKIPPED is reported."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-1"
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_not_called()
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("CLEANUP SKIPPED: Server-side ownership could not be verified; manual cleanup may be required.", res.target_response)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_cve_2026_28788_cleanup_mismatched_server_ownership_not_deleted(self):
        """A newly provisioned resource with mismatched server-side ownership is NOT deleted."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-mismatch"
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": "dyn-target-prov-mismatch",
            "user_id": "foreign-user-id-999",
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_not_called()
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("CLEANUP SKIPPED: Server-side ownership could not be verified; manual cleanup may be required.", res.target_response)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_cve_2026_28788_cleanup_unavailable_metadata_not_deleted(self):
        """A newly provisioned resource with unavailable metadata is NOT deleted."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-unavailable"
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_not_called()
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("CLEANUP SKIPPED: Server-side ownership could not be verified; manual cleanup may be required.", res.target_response)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_cve_2026_28788_cleanup_no_server_user_id_not_deleted(self):
        """A resource with no server-side user_id is NOT deleted."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-no-uid"
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": "dyn-target-prov-no-uid",
            "user_id": "",
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_not_called()
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("CLEANUP SKIPPED: Server-side ownership could not be verified; manual cleanup may be required.", res.target_response)
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)

    def test_cve_2026_28788_cleanup_verified_alice_ownership_is_deleted(self):
        """A newly provisioned resource with verified Alice ownership is deleted."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-verified"
        self.mock_adapter.get_file_metadata.side_effect = None
        self.mock_adapter.get_file_metadata.return_value = {
            "id": "dyn-target-prov-verified",
            "user_id": "alice-user-uuid-123",
        }
        self.mock_adapter.read_file_content.return_value = None  # Baseline fails post-ownership-verification

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-verified"
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("[Cleanup: disposable file 'dyn-target-prov-verified' deleted successfully]", res.target_response)

    def test_cve_2026_28788_cleanup_attempted_after_post_provisioning_baseline_failure(self):
        """Targeted cleanup is attempted if baseline retrieval fails after provisioning."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-2"
        self.mock_adapter.read_file_content.return_value = None

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-2"
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_cleanup_attempted_after_post_provisioning_hashing_failure(self):
        """Targeted cleanup is attempted if baseline hashing fails after provisioning."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-3"
        self.mock_adapter.read_file_content.return_value = 12345

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-3"
        )
        self.mock_adapter.overwrite_resource.assert_not_called()
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_cleanup_attempted_after_post_provisioning_overwrite_exception(self):
        """Targeted cleanup is attempted if overwrite_resource raises an unexpected exception."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-4"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.side_effect = ConnectionResetError("Connection reset by peer")

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-4"
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("unexpected exception", res.target_response.lower())

    def test_cve_2026_28788_type_error_does_not_retry_overwrite(self):
        """A TypeError from overwrite_resource does not trigger a second overwrite request."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-4"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.side_effect = TypeError("unexpected keyword argument 'xyz'")

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-4"
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("TypeError", res.target_response)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertFalse(res.is_leak)

    def test_cve_2026_28788_cleanup_attempted_after_post_provisioning_malformed_response(self):
        """Targeted cleanup is attempted if overwrite endpoint returns a malformed response."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-5"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = "non-dict-string-response"

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-5"
        )
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_cleanup_attempted_after_post_provisioning_readback_failure(self):
        """Targeted cleanup is attempted if readback returns None after overwrite."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dyn-target-prov-6"
        self.mock_adapter.read_file_content.side_effect = ["Baseline content", None]
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "dyn-target-prov-6", "status": "completed"}],
            "errors": [],
        }

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dyn-target-prov-6"
        )
        self.assertIn("INCONCLUSIVE", res.target_response)

    def test_cve_2026_28788_targeted_cleanup_success(self):
        """Targeted cleanup calls delete_file exclusively on dynamically provisioned target and reports success."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dynamic-cleanup-target"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "dynamic-cleanup-target",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }
        self.mock_adapter.delete_file.return_value = True

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.mock_adapter.delete_file.assert_called_once_with(
            "http://mock:8080", self.alice, "dynamic-cleanup-target"
        )
        self.assertIn("deleted successfully", res.target_response.lower())

    def test_cve_2026_28788_targeted_cleanup_failure_reported(self):
        """Targeted cleanup failure for dynamically provisioned target is reported in target_response."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dynamic-cleanup-target"
        self.mock_adapter.read_file_content.return_value = "Baseline content"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [
                {
                    "file_id": "dynamic-cleanup-target",
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }
        self.mock_adapter.delete_file.return_value = False

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertIn("cleanup failed", res.target_response.lower())

    def test_cve_2026_28788_cleanup_failure_does_not_change_compromised_to_clean(self):
        """Failed cleanup does not change a COMPROMISED verdict to CLEAN."""
        self.alice.metadata["disposable_file_ids"] = []
        self.mock_adapter.ingest_document.return_value = "dynamic-cleanup-target"
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "dynamic-cleanup-target", "status": "completed"}],
            "errors": [],
        }
        self.mock_adapter.delete_file.return_value = False

        def mock_read_file(base, sess, fid):
            last_call = self.mock_adapter.overwrite_resource.call_args
            if last_call:
                return last_call[1]["payload"]
            return "Baseline content"

        self.mock_adapter.read_file_content.side_effect = mock_read_file

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.DIRECT_LEAK)
        self.assertIn("COMPROMISED", res.target_response)
        self.assertIn("cleanup failed", res.target_response.lower())

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

    def test_cve_2026_54019_resource_id_injection_syntax(self):
        self.mock_adapter.query_collection.return_value = (
            "Syntax error",
            [],
            {"error": "Invalid syntax", "code": 400},
        )
        self.mock_adapter.query_doc.return_value = (
            "Syntax error",
            [],
            {"error": "Invalid syntax", "code": 400},
        )
        res = cve_2026_54019.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        coll_args = self.mock_adapter.query_collection.call_args
        self.assertEqual(
            coll_args[1]["collection_names"],
            ["x' or resource_id != '' or resource_id == 'x"],
        )
        self.assertEqual(coll_args[1]["k"], 10)
        self.assertEqual(coll_args[1]["hybrid"], False)
        doc_args = self.mock_adapter.query_doc.call_args
        self.assertEqual(
            doc_args[1]["collection_name"],
            "x' or resource_id != '' or resource_id == 'x",
        )
        self.assertEqual(doc_args[1]["k"], 10)

    def test_cve_2026_54019_collection_leak_detected(self):
        # Collection query succeeds in retrieving Alice's canary
        self.mock_adapter.query_collection.return_value = (
            "",
            [f"Leaked chunk with canary: {self.canary.token}"],
            {"documents": [[f"Leaked chunk with canary: {self.canary.token}"]]},
        )
        self.mock_adapter.query_doc.return_value = ("", [], {})
        res = cve_2026_54019.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.CONTEXT_LEAK)
        self.assertIn(self.canary.token, res.leaked_canaries)

    def test_cve_2026_54019_no_fabricated_collection_dependency(self):
        """CVE-2026-54019 does not depend on a fabricated collection identifier when Alice lacks knowledge IDs."""
        self.mock_adapter.query_collection.return_value = ("No leak", [], {})
        self.mock_adapter.query_doc.return_value = ("No leak", [], {})
        alice_no_kb = UserSession("alice", "owner", metadata={})
        res = cve_2026_54019.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=alice_no_kb,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertFalse(res.is_leak)
        coll_args = self.mock_adapter.query_collection.call_args
        self.assertEqual(
            coll_args[1]["collection_names"],
            ["x' or resource_id != '' or resource_id == 'x"],
        )
        doc_args = self.mock_adapter.query_doc.call_args
        self.assertEqual(
            doc_args[1]["collection_name"],
            "x' or resource_id != '' or resource_id == 'x",
        )

    def test_cve_2026_54019_doc_leak_detected(self):
        # Document query succeeds in retrieving Alice's canary
        self.mock_adapter.query_collection.return_value = ("", [], {})
        self.mock_adapter.query_doc.return_value = (
            "",
            [f"Leaked doc with canary: {self.canary.token}"],
            {"documents": [[f"Leaked doc with canary: {self.canary.token}"]]},
        )
        res = cve_2026_54019.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[self.canary],
            engine=self.engine,
        )
        self.assertTrue(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.CONTEXT_LEAK)
        self.assertIn(self.canary.token, res.leaked_canaries)

    def test_cve_2026_28788_registry_rejects_owner_username_kwarg_with_type_error(self):
        """TrustedScanDisposableRegistry.register strictly rejects unexpected keyword argument 'owner_username'."""
        from probes.cves.cve_2026_28788 import _TRUSTED_SCAN_REGISTRY
        test_run = "regression-run-uuid-001"
        test_file = "disposable-file-uuid-001"
        with self.assertRaises(TypeError) as ctx:
            _TRUSTED_SCAN_REGISTRY.register(
                run_id=test_run,
                resource_id=test_file,
                owner_username="alice",  # Invalid keyword argument
            )
        self.assertIn("owner_username", str(ctx.exception))

    def test_cve_2026_28788_registry_registration_canonical_owner(self):
        """TrustedScanDisposableRegistry.register accepts canonical owner parameter and indexes correctly."""
        from probes.cves.cve_2026_28788 import _TRUSTED_SCAN_REGISTRY
        test_run = "canonical-run-uuid-001"
        test_file = "disposable-file-uuid-001"
        _TRUSTED_SCAN_REGISTRY.register(
            run_id=test_run,
            resource_id=test_file,
            owner="alice",
        )
        self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_registered(test_run, test_file, "alice"))
        self.assertFalse(_TRUSTED_SCAN_REGISTRY.is_registered(test_run, test_file, "bob"))

    def test_cve_2026_28788_registry_registration_with_owner_and_optional_metadata(self):
        """TrustedScanDisposableRegistry.register accepts optional metadata without compromising ownership checks."""
        from probes.cves.cve_2026_28788 import _TRUSTED_SCAN_REGISTRY
        test_run = "canonical-run-uuid-002"
        test_file = "disposable-file-uuid-002"
        _TRUSTED_SCAN_REGISTRY.register(
            run_id=test_run,
            resource_id=test_file,
            owner="alice",
            metadata={
                "server_user_id": "aaaaaaaa-0000-0000-0000-000000000085",
                "kb_id": "cccccccc-0000-0000-0000-000000000085",
                "filename": "alice_disposable.txt",
                "lab_managed": True,
            },
        )
        self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_registered(test_run, test_file, "alice"))
        self.assertFalse(_TRUSTED_SCAN_REGISTRY.is_registered(test_run, test_file, "wrong-owner"))

    def test_cve_2026_28788_registry_registration_missing_or_blank_owner_raises_error(self):
        """TrustedScanDisposableRegistry.register raises TypeError if owner omitted, or ValueError if empty."""
        from probes.cves.cve_2026_28788 import _TRUSTED_SCAN_REGISTRY
        with self.assertRaises(TypeError):
            _TRUSTED_SCAN_REGISTRY.register(run_id="run-x", resource_id="res-y")
        with self.assertRaises(ValueError):
            _TRUSTED_SCAN_REGISTRY.register(run_id="run-x", resource_id="res-y", owner="")
        with self.assertRaises(ValueError):
            _TRUSTED_SCAN_REGISTRY.register(run_id="run-x", resource_id="res-y", owner="   ")

    def test_cve_2026_28788_helper_register_trusted_disposable_resource_requires_owner(self):
        """register_trusted_disposable_resource helper strictly requires owner and forwards optional metadata."""
        from probes.cves.cve_2026_28788 import register_trusted_disposable_resource, _TRUSTED_SCAN_REGISTRY
        test_run = "helper-run-uuid-003"
        test_file = "helper-file-uuid-003"
        register_trusted_disposable_resource(
            run_id=test_run,
            resource_id=test_file,
            owner="alice",
            metadata={"lab_managed": True},
        )
        self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_registered(test_run, test_file, "alice"))
        with self.assertRaises(TypeError):
            register_trusted_disposable_resource(run_id="run-z", resource_id="res-z")

    def test_probing_engine_constructor_rejects_canary_generator_kwarg(self):
        """ProbingEngine.__init__ raises TypeError when passed unexpected 'canary_generator' kwarg."""
        from core.engine import ProbingEngine
        with self.assertRaises(TypeError) as ctx:
            ProbingEngine(canary_generator=None)
        self.assertIn("canary_generator", str(ctx.exception))

    def test_probing_engine_constructor_canonical_run_id(self):
        """ProbingEngine.__init__ canonically accepts run_id and assigns it properly."""
        from core.engine import ProbingEngine
        test_run_id = "test-run-canonical-12345"
        engine = ProbingEngine(run_id=test_run_id)
        self.assertEqual(engine.run_id, test_run_id)
        self.assertEqual(engine.canary_prefix, "CANARY-FRDP")

    def test_run_firedamp_probe_script_constructs_probing_engine_correctly(self):
        """Integration runner run_firedamp_probe constructs ProbingEngine using canonical API."""
        import ast
        import json
        import tempfile
        from unittest.mock import patch, MagicMock
        from pathlib import Path
        import sys
        from core.engine import LeakSeverity, ProbingEngine

        # Direct script execution places SCRIPT_DIR on sys.path; package imports do
        # not. Mirror that execution environment for this runner-wiring test.
        script_dir = (
            Path(__file__).resolve().parent
            / "integration" / "openwebui_cve_2026_28788" / "scripts"
        )
        if str(script_dir) not in sys.path:
            sys.path.insert(0, str(script_dir))
        from tests.integration.openwebui_cve_2026_28788.scripts import run_firedamp_probe

        # 1. AST check: ensure no canary_generator kwarg in script source
        script_path = Path(run_firedamp_probe.__file__)
        tree = ast.parse(script_path.read_text(encoding="utf-8"))
        probing_engine_calls = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = getattr(node.func, "id", None)
                if func_name == "ProbingEngine":
                    probing_engine_calls += 1
                    kw_names = [kw.arg for kw in node.keywords]
                    self.assertNotIn("canary_generator", kw_names)
                    self.assertIn("run_id", kw_names)
        self.assertGreaterEqual(probing_engine_calls, 1)

        # 2. Execution check with mock args and mock cve_2026_28788.run
        mock_setup = {
            "base_url": "http://127.0.0.1:13085",
            "alice": {"token": "alice-tok", "user_id": "alice-uid"},
            "bob": {"token": "bob-tok", "user_id": "bob-uid"},
            "knowledge_base": {"id": "kb-test-123"},
            "disposable_file": {"id": "file-test-123"},
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_file = Path(tmp_dir) / "setup.json"
            setup_file.write_text(json.dumps(mock_setup), encoding="utf-8")
            output_file = Path(tmp_dir) / "probe_output.json"

            # This test verifies runner wiring, not the lab-safety HTTP contract.
            # The lab_safety module has separate tests for file permissions, target
            # scope, identities, ownership, membership, and baseline verification.
            with patch("sys.argv", ["run_firedamp_probe.py", "--setup-file", str(setup_file), "--output", str(output_file)]), \
                 patch.object(run_firedamp_probe, "validate_setup_file", return_value=mock_setup) as mock_validate, \
                 patch.object(
                     run_firedamp_probe,
                     "verify_setup_target",
                     return_value={"version": "0.8.5", "content_sha256": "a" * 64},
                 ) as mock_preflight, \
                 patch("probes.cves.cve_2026_28788.run") as mock_probe_run:
                mock_res = MagicMock()
                mock_res.severity = LeakSeverity.NONE
                mock_res.target_response = "CLEAN: Server returned per-file authorization rejection"
                mock_res.leaked_canaries = []
                mock_probe_run.return_value = mock_res

                run_firedamp_probe.main()

                mock_validate.assert_called_once_with(str(setup_file), allow_non_loopback=False)
                mock_preflight.assert_called_once()
                self.assertTrue(mock_preflight.call_args.kwargs["require_baseline"])
                mock_probe_run.assert_called_once()
                call_kwargs = mock_probe_run.call_args.kwargs
                passed_engine = call_kwargs["engine"]
                self.assertIsInstance(passed_engine, ProbingEngine)
                self.assertTrue(passed_engine.run_id.startswith("firedamp-lab-run-"))
                self.assertEqual(passed_engine.canary_prefix, "CANARY-FRDP")

                out_data = json.loads(output_file.read_text(encoding="utf-8"))
                self.assertEqual(out_data["cve_id"], "CVE-2026-28788")
                self.assertTrue(out_data["is_clean"])
                self.assertFalse(out_data["is_vulnerable"])

    def test_cve_2026_28788_target_file_in_second_kb_selected(self):
        """When Alice has multiple KBs and target file belongs to the second KB, the second KB is selected."""
        self.alice.metadata["knowledge_ids"] = ["kb-alpha-111", "kb-beta-222"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            ["other-file-x"] if kb == "kb-alpha-111" else ["disposable-f123"]
        )
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "completed"}],
            "errors": [],
        }
        self.mock_adapter.read_file_content.side_effect = ["Baseline content", "POISONED TRACER: token-1"]

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertEqual(self.mock_adapter.overwrite_resource.call_args.kwargs["collection_name"], "kb-beta-222")

    def test_cve_2026_28788_target_file_not_in_any_kb_inconclusive_zero_overwrite(self):
        """When target file belongs to none of Alice's accessible KBs, returns INCONCLUSIVE and sends zero overwrite requests."""
        self.alice.metadata["knowledge_ids"] = ["kb-alpha-111", "kb-beta-222"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: ["other-file-1", "other-file-2"]

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("does not belong to any verified knowledge base", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_ambiguous_file_membership_inconclusive_zero_overwrite(self):
        """When target file is associated with multiple accessible KBs, returns INCONCLUSIVE and sends zero overwrite requests."""
        self.alice.metadata["knowledge_ids"] = ["kb-alpha-111", "kb-beta-222"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: ["disposable-f123"]

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Ambiguous knowledge base membership", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_single_kb_lab_behavior_valid(self):
        """Existing single-KB lab setup cleanly resolves the KB and proceeds normally."""
        self.alice.metadata["knowledge_ids"] = ["kb-uuid-456"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            ["disposable-f123"] if kb == "kb-uuid-456" else []
        )
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [],
            "errors": [{"file_id": "disposable-f123", "status": "failed", "error": "Permission denied: not file owner"}],
        }
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertEqual(self.mock_adapter.overwrite_resource.call_args.kwargs["collection_name"], "kb-uuid-456")
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("CLEAN", res.target_response)

    def test_resolve_file_knowledge_base_all_checked_one_match(self):
        """When all candidate KBs are verified and exactly one contains target, returns (kb_id, None)."""
        from probes.knowledge_membership import resolve_file_knowledge_base
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = ["kb-1", "kb-2"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            ["other-file"] if kb == "kb-1" else ["target-file-777"]
        )
        kb, err = resolve_file_knowledge_base(self.mock_adapter, "http://mock", self.alice, "target-file-777")
        self.assertEqual(kb, "kb-2")
        self.assertIsNone(err)

    def test_resolve_file_knowledge_base_one_match_one_failed_lookup(self):
        """When 1 KB matches but another candidate lookup returns None, returns (None, Incomplete verification)."""
        from probes.knowledge_membership import resolve_file_knowledge_base
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = ["kb-good", "kb-broken"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            ["target-file-777"] if kb == "kb-good" else None
        )
        kb, err = resolve_file_knowledge_base(self.mock_adapter, "http://mock", self.alice, "target-file-777")
        self.assertIsNone(kb)
        self.assertIsNotNone(err)
        self.assertIn("Incomplete verification", err)
        self.assertIn("kb-broken", err)

    def test_resolve_file_knowledge_base_zero_matches_one_failed_lookup(self):
        """When 0 KBs match so far but at least 1 candidate lookup returns None, returns (None, Incomplete verification)."""
        from probes.knowledge_membership import resolve_file_knowledge_base
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = ["kb-empty", "kb-broken"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            [] if kb == "kb-empty" else None
        )
        kb, err = resolve_file_knowledge_base(self.mock_adapter, "http://mock", self.alice, "target-file-777")
        self.assertIsNone(kb)
        self.assertIsNotNone(err)
        self.assertIn("Incomplete verification", err)

    def test_resolve_file_knowledge_base_metadata_mapping_alone_cannot_establish_membership(self):
        """Session metadata mapping alone cannot establish file membership when adapter lookup returns None."""
        from probes.knowledge_membership import resolve_file_knowledge_base
        self.alice.metadata["knowledge_base_files"] = {"kb-1": ["target-file-777"]}
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = ["kb-1"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: None
        kb, err = resolve_file_knowledge_base(self.mock_adapter, "http://mock", self.alice, "target-file-777")
        self.assertIsNone(kb)
        self.assertIsNotNone(err)
        self.assertIn("Incomplete verification", err)

    def test_resolve_file_knowledge_base_rejects_malformed_candidate_ids(self):
        from probes.knowledge_membership import resolve_file_knowledge_base

        for malformed in (["kb-a", None], ["kb-a", " "], ["kb-a", "kb-a"], {"kb-a"}):
            adapter = MagicMock()
            adapter.get_accessible_knowledge_bases.return_value = malformed
            kb, error = resolve_file_knowledge_base(adapter, "http://mock", self.alice, "target-file")
            self.assertIsNone(kb)
            self.assertIn("Malformed candidate", error)
            adapter.get_knowledge_base_files.assert_not_called()

    def test_resolve_file_knowledge_base_rejects_malformed_membership_ids(self):
        from probes.knowledge_membership import resolve_file_knowledge_base

        for malformed in (["target-file", None], ["target-file", " "], ["target-file", "target-file"]):
            adapter = MagicMock()
            adapter.get_accessible_knowledge_bases.return_value = ["kb-a"]
            adapter.get_knowledge_base_files.return_value = malformed
            kb, error = resolve_file_knowledge_base(adapter, "http://mock", self.alice, "target-file")
            self.assertIsNone(kb)
            self.assertIn("Incomplete verification", error)

    def test_resolve_file_knowledge_base_candidate_enumeration_failure(self):
        """When adapter.get_accessible_knowledge_bases returns None, resolution fails closed."""
        from probes.knowledge_membership import resolve_file_knowledge_base
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = None
        kb, err = resolve_file_knowledge_base(self.mock_adapter, "http://mock", self.alice, "target-file-777")
        self.assertIsNone(kb)
        self.assertIsNotNone(err)
        self.assertIn("Incomplete candidate", err)

    def test_cve_2026_28788_one_match_one_failed_lookup_inconclusive_zero_overwrite(self):
        """Full probe: 1 KB matches but another candidate lookup returns None -> INCONCLUSIVE and 0 overwrites."""
        self.alice.metadata["knowledge_ids"] = ["kb-alpha-111", "kb-beta-222"]
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = ["kb-alpha-111", "kb-beta-222"]
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            ["disposable-f123"] if kb == "kb-alpha-111" else None
        )
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Incomplete verification", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_candidate_enumeration_failure_inconclusive_zero_overwrite(self):
        """Full probe: candidate KB enumeration fails (None) -> INCONCLUSIVE and 0 overwrites."""
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = None
        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Incomplete candidate knowledge base enumeration", res.target_response)
        self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_zero_overwrite_on_all_unresolved_membership_cases(self):
        """Ensures that for any unresolved case (candidate failure, lookup failure, ambiguity, 0 matches), 0 overwrites occur."""
        unresolved_scenarios = [
            # (accessible_kbs, get_kb_files_side_effect)
            (None, lambda b, s, k: ["disposable-f123"]),  # candidate failure
            (["kb-1", "kb-2"], lambda b, s, k: ["disposable-f123"] if k == "kb-1" else None),  # 1 match + 1 failure
            (["kb-1", "kb-2"], lambda b, s, k: [] if k == "kb-1" else None),  # 0 match + 1 failure
            (["kb-1", "kb-2"], lambda b, s, k: ["disposable-f123"]),  # ambiguous match
            (["kb-1", "kb-2"], lambda b, s, k: ["other-file"]),  # 0 matches
        ]
        for candidate_kbs, kb_files_fn in unresolved_scenarios:
            self.mock_adapter.overwrite_resource.reset_mock()
            self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
            self.mock_adapter.get_accessible_knowledge_bases.return_value = candidate_kbs
            self.mock_adapter.get_knowledge_base_files.side_effect = kb_files_fn

            res = cve_2026_28788.run(
                adapter=self.mock_adapter,
                base_url="http://mock:8080",
                alice=self.alice,
                bob=self.bob,
                planted_canaries=[],
                engine=self.engine,
                dry_run=False,
            )
            self.assertEqual(res.severity, LeakSeverity.NONE)
            self.assertIn("INCONCLUSIVE", res.target_response)
            self.mock_adapter.overwrite_resource.assert_not_called()

    def test_cve_2026_28788_target_kb_on_page_2_of_candidate_enumeration(self):
        """When user has 35 accessible KBs and target is in KB #32 (page 2), successfully resolves and executes overwrite."""
        candidate_kbs = [f"kb-{i}" for i in range(35)]
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = candidate_kbs
        self.mock_adapter.get_knowledge_base_files.side_effect = lambda base, sess, kb: (
            ["disposable-f123"] if kb == "kb-32" else ["other-file"]
        )
        self.mock_adapter.overwrite_resource.return_value = {
            "results": [{"file_id": "disposable-f123", "status": "completed"}],
            "errors": [],
        }
        self.mock_adapter.read_file_content.side_effect = ["Baseline content", "POISONED TRACER: token-1"]

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.mock_adapter.overwrite_resource.assert_called_once()
        self.assertEqual(self.mock_adapter.overwrite_resource.call_args.kwargs["collection_name"], "kb-32")

    def test_cve_2026_28788_candidate_enumeration_failure_never_calls_membership_or_overwrite(self):
        """When candidate enumeration fails (returns None), resolver never starts file-membership or overwrite requests."""
        self.mock_adapter.get_accessible_knowledge_bases.side_effect = None
        self.mock_adapter.get_accessible_knowledge_bases.return_value = None
        self.mock_adapter.get_knowledge_base_files.reset_mock()
        self.mock_adapter.overwrite_resource.reset_mock()

        res = cve_2026_28788.run(
            adapter=self.mock_adapter,
            base_url="http://mock:8080",
            alice=self.alice,
            bob=self.bob,
            planted_canaries=[],
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Incomplete candidate knowledge base enumeration", res.target_response)
        self.mock_adapter.get_knowledge_base_files.assert_not_called()
        self.mock_adapter.overwrite_resource.assert_not_called()


if __name__ == "__main__":
    unittest.main()

