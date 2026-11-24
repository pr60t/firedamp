"""
Unit and integration tests for Pillar 5: Write-Side Poisoning (Cross-Tenant Indirect Injection).
"""

import hashlib
import unittest
from typing import Any, Dict, List, Optional, Tuple
from adapters.base import TargetAdapter, UserSession
from core.engine import (
    CanaryToken,
    DecoyDocument,
    LeakSeverity,
    ProbeResult,
    ProbingEngine,
)
from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY
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

    def __init__(
        self,
        allow_injection: bool = False,
        allow_overwrite: bool = False,
        kb_files: Optional[Dict[str, List[str]]] = None,
        failing_kbs: Optional[List[str]] = None,
        accessible_kbs: Optional[List[str]] = None,
        fail_candidate_enumeration: bool = False,
        knowledge_base_owner_override: Optional[str] = None,
    ):
        self.allow_injection = allow_injection
        self.allow_overwrite = allow_overwrite
        self.injected_documents = []
        self.overwritten_payloads = []
        self.kb_files = kb_files if kb_files is not None else {
            "kb-alice": ["file-alice"],
            "authoritative-kb-123": ["target-doc-456"],
        }
        self.failing_kbs = list(failing_kbs) if failing_kbs is not None else []
        self.accessible_kbs = accessible_kbs
        self.fail_candidate_enumeration = fail_candidate_enumeration
        self.knowledge_base_owner_override = knowledge_base_owner_override
        self.membership_calls = []
        self.current_content = "Original Alice file content."
        self.deleted_files = []
        self.uploaded_file_id = "bob-upload-file-id"

    def get_accessible_knowledge_bases(self, base_url, session):
        if self.fail_candidate_enumeration:
            return None
        if self.accessible_kbs is not None:
            return list(self.accessible_kbs)
        if session and isinstance(session.metadata, dict) and "knowledge_ids" in session.metadata:
            return list(session.metadata["knowledge_ids"])
        if self.kb_files is not None:
            return list(self.kb_files.keys())
        return []

    def get_knowledge_base_metadata(self, base_url, session, knowledge_id):
        owner_id = self.knowledge_base_owner_override
        if owner_id is None:
            owner_id = session.metadata.get("user_id") if isinstance(session.metadata, dict) else None
        return {"id": knowledge_id, "user_id": owner_id}

    def get_knowledge_base_files(self, base_url, session, knowledge_id):
        self.membership_calls.append(knowledge_id)
        if self.failing_kbs and knowledge_id in self.failing_kbs:
            return None
        if self.kb_files is not None and knowledge_id in self.kb_files:
            return list(self.kb_files[knowledge_id])
        return []

    def get_authenticated_user_id(self, base_url, session):
        return session.metadata.get("user_id") if isinstance(session.metadata, dict) else None

    def get_file_metadata(self, base_url, session, file_id):
        owner_id = session.metadata.get("user_id") if isinstance(session.metadata, dict) else None
        return {"id": file_id, "user_id": owner_id, "filename": "disposable.txt"}

    def read_file_content(self, base_url, session, file_id):
        return self.current_content

    def delete_file(self, base_url, session, file_id):
        self.deleted_files.append(file_id)
        return True

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
            return {"status": True, "id": "injected-doc-id", "uploaded_file_id": self.uploaded_file_id}
        return {"error": "Access denied", "code": 403, "uploaded_file_id": self.uploaded_file_id}

    def overwrite_resource(
        self,
        base_url,
        session,
        resource_ref,
        payload,
        collection_name=None,
        file_model=None,
        **kwargs,
    ):
        self.overwritten_payloads.append((resource_ref, payload, collection_name))
        if self.allow_overwrite:
            self.current_content = payload
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
        _TRUSTED_SCAN_REGISTRY.clear()
        self.run_id = "write-poisoning-test-run"
        self.engine = ProbingEngine(run_id=self.run_id)
        self.alice = self._registered_alice("file-alice", ["kb-alice"])
        self.bob = UserSession(
            "bob", "attacker", metadata={"user_id": "bob-server-id", "run_id": self.run_id}
        )

    def tearDown(self):
        _TRUSTED_SCAN_REGISTRY.clear()

    def _registered_alice(self, file_id, knowledge_ids, *, ordinary_file_ids=None, extra_metadata=None):
        baseline = "Original Alice file content."
        metadata = {
            "user_id": "alice-server-id",
            "run_id": self.run_id,
            "knowledge_ids": list(knowledge_ids),
            "file_ids": [file_id],
            "ordinary_file_ids": list(ordinary_file_ids or []),
            "disposable_file_ids": [file_id],
        }
        if extra_metadata:
            metadata.update(extra_metadata)
        _TRUSTED_SCAN_REGISTRY.register(
            run_id=self.run_id,
            resource_id=file_id,
            owner="alice",
            metadata={"baseline_sha256": hashlib.sha256(baseline.encode("utf-8")).hexdigest()},
        )
        return UserSession("alice", "owner", metadata=metadata)

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
        """Verify simulated execution when server blocks Bob from injecting into Alice's KB."""
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
        self.assertIn("CLEAN", res.target_response)
        self.assertEqual(adapter.deleted_files, [adapter.uploaded_file_id])

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
        self.assertEqual(adapter.deleted_files, [adapter.uploaded_file_id])

    def test_collection_injection_refuses_without_current_run_disposable_anchor(self):
        """No collection injection is attempted against an unregistered/pre-existing Alice file."""
        alice = UserSession("alice", "owner", metadata={
            "user_id": "alice-server-id", "run_id": self.run_id,
            "file_ids": ["ordinary-file"], "ordinary_file_ids": ["ordinary-file"],
            "disposable_file_ids": [], "knowledge_ids": ["kb-alice"],
        })
        adapter = MockPoisonAdapter(allow_injection=True)
        res = test_cross_tenant_collection_injection(adapter, "http://mock", alice, self.bob, self.engine)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(adapter.injected_documents, [])
        self.assertEqual(adapter.deleted_files, [])

    def test_collection_injection_requires_target_kb_to_be_alice_owned(self):
        """A readable but third-party-owned KB is not a valid Alice target."""
        adapter = MockPoisonAdapter(allow_injection=True, knowledge_base_owner_override="third-party-id")
        res = test_cross_tenant_collection_injection(adapter, "http://mock", self.alice, self.bob, self.engine)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("not authoritatively owned by Alice", res.target_response)
        self.assertEqual(adapter.injected_documents, [])
        self.assertEqual(adapter.deleted_files, [])

    def test_collection_injection_refuses_preexisting_bob_upload_id(self):
        """An adapter response cannot turn an existing Bob file into a disposable upload."""
        adapter = MockPoisonAdapter(allow_injection=False)
        self.bob.metadata["ordinary_file_ids"] = [adapter.uploaded_file_id]
        res = test_cross_tenant_collection_injection(adapter, "http://mock", self.alice, self.bob, self.engine)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(adapter.deleted_files, [])

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
        """Verify simulated execution when server blocks Bob from overwriting Alice's file."""
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

    def test_file_overwrite_missing_collection_reports_inconclusive(self):
        """Missing target collection information does not produce a successful or clean write-poisoning verdict."""
        alice_no_kb = self._registered_alice("file-alice", [])
        adapter = MockPoisonAdapter(allow_overwrite=False)
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_no_kb,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertFalse(res.is_leak)
        self.assertEqual(res.severity, LeakSeverity.NONE)
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(len(adapter.overwritten_payloads), 0)

    def test_file_overwrite_explicit_collection_preserved(self):
        """Existing valid explicit collection selection remains intact and is passed to overwrite_resource."""
        alice_with_kb = self._registered_alice("target-doc-456", ["authoritative-kb-123"])
        adapter = MockPoisonAdapter(allow_overwrite=False)
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_with_kb,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(len(adapter.overwritten_payloads), 1)
        self.assertEqual(adapter.overwritten_payloads[0][0], "target-doc-456")
        self.assertEqual(adapter.overwritten_payloads[0][2], "authoritative-kb-123")
        self.assertFalse(res.is_leak)

    def test_file_overwrite_second_kb_selected_when_file_in_second_kb(self):
        """When Alice has two KBs and the file is in the second KB, the second KB is selected."""
        alice_multi_kb = self._registered_alice("target-file-beta", ["kb-alpha", "kb-beta"])
        adapter = MockPoisonAdapter(
            allow_overwrite=False,
            kb_files={"kb-alpha": ["unrelated-f1"], "kb-beta": ["target-file-beta"]},
        )
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_multi_kb,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertEqual(len(adapter.overwritten_payloads), 1)
        self.assertEqual(adapter.overwritten_payloads[0][0], "target-file-beta")
        self.assertEqual(adapter.overwritten_payloads[0][2], "kb-beta")
        self.assertFalse(res.is_leak)

    def test_file_overwrite_file_not_in_any_kb_inconclusive_zero_overwrites(self):
        """When target file belongs to none of Alice's accessible KBs, returns INCONCLUSIVE with zero overwrite calls."""
        alice_multi_kb = self._registered_alice("orphan-file", ["kb-alpha", "kb-beta"])
        adapter = MockPoisonAdapter(
            allow_overwrite=False,
            kb_files={"kb-alpha": ["f1"], "kb-beta": ["f2"]},
        )
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_multi_kb,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("does not belong to any verified knowledge base", res.target_response)
        self.assertEqual(len(adapter.overwritten_payloads), 0)

    def test_file_overwrite_ambiguous_membership_inconclusive_zero_overwrites(self):
        """When target file belongs to multiple accessible KBs, returns INCONCLUSIVE with zero overwrite calls."""
        alice_multi_kb = self._registered_alice("shared-file", ["kb-alpha", "kb-beta"])
        adapter = MockPoisonAdapter(
            allow_overwrite=False,
            kb_files={"kb-alpha": ["shared-file"], "kb-beta": ["shared-file"]},
        )
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_multi_kb,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Ambiguous knowledge base membership", res.target_response)
        self.assertEqual(len(adapter.overwritten_payloads), 0)

    def test_generic_write_poisoning_and_cve_28788_shared_resolution_rules(self):
        """Confirm write_poisoning and cve_2026_28788 use the identical resolve_file_knowledge_base implementation."""
        from probes.knowledge_membership import resolve_file_knowledge_base as neutral_resolver
        from probes.cves.cve_2026_28788 import resolve_file_knowledge_base as cve_resolver
        from probes.scenarios.write_poisoning import resolve_file_knowledge_base as scenario_resolver
        self.assertIs(neutral_resolver, cve_resolver)
        self.assertIs(neutral_resolver, scenario_resolver)

        # Verify resolution rules on both
        session = UserSession("alice", "owner", metadata={"knowledge_ids": ["kb1", "kb2"]})
        adapter = MockPoisonAdapter(kb_files={"kb1": ["f1"], "kb2": ["f2"]})
        kb_cve, err_cve = cve_resolver(adapter, "http://mock", session, "f2")
        kb_scen, err_scen = scenario_resolver(adapter, "http://mock", session, "f2")
        self.assertEqual(kb_cve, "kb2")
        self.assertEqual(kb_scen, "kb2")
        self.assertIsNone(err_cve)
        self.assertIsNone(err_scen)

    def test_collection_injection_does_not_mistake_collection_id_for_file_id(self):
        """BaseAdapter.inject_into_collection does not call overwrite_resource and does not mistake collection ID for file ID."""
        class MockBaseSubclass(MockPoisonAdapter):
            def __init__(self):
                super().__init__()
                self.overwrite_called = False
            def overwrite_resource(self, base_url, session, resource_ref, payload, **kwargs):
                self.overwrite_called = True
                return {"status": True}

        # Ensure we test TargetAdapter's actual inject_into_collection implementation
        MockBaseSubclass.inject_into_collection = TargetAdapter.inject_into_collection

        base_sub = MockBaseSubclass()
        doc = DecoyDocument("decoy", "content", "write_poison", [])
        res = base_sub.inject_into_collection("http://mock", self.bob, "coll-uuid-999", doc)
        self.assertFalse(base_sub.overwrite_called)
        self.assertIn("error", res)
        self.assertEqual(res.get("code"), 501)

    def test_unsupported_collection_injection_fails_closed(self):
        """Unsupported collection injection returns structured error and never claims success."""
        class MinimalAdapter(MockPoisonAdapter):
            pass

        # Use base TargetAdapter inject_into_collection
        MinimalAdapter.inject_into_collection = TargetAdapter.inject_into_collection

        adapter = MinimalAdapter()
        doc = DecoyDocument("decoy", "content", "write_poison", [])
        res = adapter.inject_into_collection("http://mock", self.bob, "target-coll-123", doc)
        self.assertIsInstance(res, dict)
        self.assertIn("error", res)
        self.assertIn("not supported by this adapter", res["error"])
        self.assertEqual(res.get("code"), 501)
        self.assertFalse(res.get("status") is True)

    def test_fake_adapter_implements_explicit_membership_interface(self):
        """MockPoisonAdapter cleanly distinguishes verified empty from failed/unverified lookups."""
        adapter = MockPoisonAdapter(
            kb_files={"kb-empty": [], "kb-good": ["f1"]},
            failing_kbs=["kb-failing"],
            accessible_kbs=["kb-empty", "kb-good", "kb-failing"],
        )
        # Accessible KBs enumeration
        self.assertEqual(adapter.get_accessible_knowledge_bases("http://mock", self.alice), ["kb-empty", "kb-good", "kb-failing"])

        # Verified empty returns []
        self.assertEqual(adapter.get_knowledge_base_files("http://mock", self.alice, "kb-empty"), [])

        # Verified populated returns List[str]
        self.assertEqual(adapter.get_knowledge_base_files("http://mock", self.alice, "kb-good"), ["f1"])

        # Failed/unverified lookup returns None
        self.assertIsNone(adapter.get_knowledge_base_files("http://mock", self.alice, "kb-failing"))

    def test_file_overwrite_one_match_one_failed_lookup_inconclusive_zero_overwrites(self):
        """When 1 KB matches but another candidate lookup returns None, overwrite aborts with 0 requests."""
        alice_multi_kb = self._registered_alice("target-f1", ["kb-alpha", "kb-beta"])
        adapter = MockPoisonAdapter(
            allow_overwrite=False,
            kb_files={"kb-alpha": ["target-f1"], "kb-beta": ["f2"]},
            failing_kbs=["kb-beta"],
        )
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_multi_kb,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Incomplete verification", res.target_response)
        self.assertEqual(len(adapter.overwritten_payloads), 0)

    def test_file_overwrite_candidate_enumeration_failure_never_calls_membership_or_overwrite(self):
        """When candidate enumeration fails (None), neither file membership nor overwrite requests are sent."""
        alice_session = self._registered_alice("target-f1", ["kb-alpha"])
        adapter = MockPoisonAdapter(fail_candidate_enumeration=True)
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_session,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Incomplete candidate knowledge base enumeration", res.target_response)
        self.assertEqual(len(adapter.membership_calls), 0)
        self.assertEqual(len(adapter.overwritten_payloads), 0)


    def test_file_overwrite_refuses_ordinary_file_even_if_listed_as_disposable(self):
        """An ordinary file ID cannot be promoted to disposable by mutable session metadata."""
        alice_ordinary = self._registered_alice(
            "ordinary-file", ["kb-alice"], ordinary_file_ids=["ordinary-file"]
        )
        adapter = MockPoisonAdapter(allow_overwrite=True, kb_files={"kb-alice": ["ordinary-file"]})
        res = test_cross_tenant_file_overwrite(
            adapter=adapter, base_url="http://mock", alice=alice_ordinary, bob=self.bob,
            engine=self.engine, dry_run=False,
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertEqual(adapter.overwritten_payloads, [])
        self.assertEqual(adapter.deleted_files, [])

    def test_file_overwrite_metadata_mapping_alone_cannot_establish_membership(self):
        """Session metadata mapping cannot bypass failed adapter lookup; aborts with 0 overwrites."""
        alice_session = self._registered_alice(
            "target-f1", ["kb-alpha"],
            extra_metadata={"knowledge_base_files": {"kb-alpha": ["target-f1"]}},
        )
        adapter = MockPoisonAdapter(
            allow_overwrite=False,
            kb_files={"kb-alpha": ["target-f1"]},
            failing_kbs=["kb-alpha"],
        )
        res = test_cross_tenant_file_overwrite(
            adapter=adapter,
            base_url="http://mock",
            alice=alice_session,
            bob=self.bob,
            engine=self.engine,
            dry_run=False,
        )
        self.assertIn("INCONCLUSIVE", res.target_response)
        self.assertIn("Incomplete verification", res.target_response)
        self.assertEqual(len(adapter.overwritten_payloads), 0)


if __name__ == "__main__":
    unittest.main()

