"""
Unit tests for modular OpenWebUIAdapter mixins (Auth, Ingest, Query, Lifecycle).
"""

import unittest
from unittest.mock import MagicMock, patch

from adapters.base import TargetAdapter, UserSession
from adapters.openwebui import OpenWebUIAdapter


class TestOpenWebUIAdapterMixins(unittest.TestCase):
    """Test suite verifying modular mixin operations with mocked HTTP requests."""

    def setUp(self):
        self.adapter = OpenWebUIAdapter()
        self.base_url = "http://mock-target:8080"
        self.alice = UserSession(
            username="alice",
            role="owner",
            token="alice-token",
            headers={"Authorization": "Bearer alice-token"},
            metadata={"file_ids": ["f1"], "knowledge_ids": ["kb1"], "email": "alice@firedamp.test"},
        )
        self.bob = UserSession(
            username="bob",
            role="attacker",
            token="bob-token",
            headers={"Authorization": "Bearer bob-token"},
            metadata={"file_ids": [], "knowledge_ids": [], "email": "bob@firedamp.test"},
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_query_collection_exact_request(self, mock_json):
        mock_json.return_value = {
            "documents": [["canary-token-chunk-1", "canary-token-chunk-2"]]
        }
        text, contexts, raw = self.adapter.query_collection(
            self.base_url,
            self.bob,
            collection_names=["x' or resource_id != '' or resource_id == 'x"],
            query="anything",
            k=10,
            hybrid=False,
        )
        self.assertEqual(len(contexts), 2)
        self.assertIn("canary-token-chunk-1", contexts)
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/retrieval/query/collection",
            method="POST",
            data={
                "collection_names": ["x' or resource_id != '' or resource_id == 'x"],
                "query": "anything",
                "k": 10,
                "hybrid": False,
            },
            headers={"Authorization": "Bearer bob-token"},
            timeout=30,
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_query_doc_exact_request(self, mock_json):
        mock_json.return_value = {
            "documents": [["doc-chunk-alpha", "doc-chunk-beta"]]
        }
        text, contexts, raw = self.adapter.query_doc(
            self.base_url,
            self.bob,
            collection_name="target-doc-id",
            query="anything",
            k=10,
        )
        self.assertEqual(len(contexts), 2)
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/retrieval/query/doc",
            method="POST",
            data={
                "collection_name": "target-doc-id",
                "query": "anything",
                "k": 10,
            },
            headers={"Authorization": "Bearer bob-token"},
            timeout=30,
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_query_resource_direct_retrieval(self, mock_json):
        mock_json.return_value = {
            "documents": [["chunk1 containing secret", "chunk2"]]
        }
        text, contexts, raw = self.adapter.query_resource_direct(
            self.base_url, self.bob, "file-12345"
        )
        self.assertEqual(len(contexts), 2)
        self.assertIn("chunk1 containing secret", contexts)
        mock_json.assert_called_once()
        args, kwargs = mock_json.call_args
        self.assertEqual(args[0], "http://mock-target:8080/api/v1/retrieval/query/collection")
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["headers"], {"Authorization": "Bearer bob-token"})
        self.assertEqual(kwargs["data"]["collection_names"], ["file-12345"])

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_query_rag_with_files_exact_request(self, mock_json):
        mock_json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Assistant generated text",
                        "citations": [{"content": "Citation chunk 1"}],
                        "sources": ["Source chunk 2"],
                    },
                    "context": "Context chunk 3",
                }
            ],
            "context": "Top level context chunk 4",
        }
        text, contexts, raw = self.adapter.query_rag(
            self.base_url,
            self.bob,
            prompt="Summarize the attached file canary contents.",
            files=[{"type": "file", "id": "f123"}],
        )
        self.assertEqual(text, "Assistant generated text")
        self.assertIn("Citation chunk 1", contexts)
        self.assertIn("Source chunk 2", contexts)
        self.assertIn("Context chunk 3", contexts)
        self.assertIn("Top level context chunk 4", contexts)
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/chat/completions",
            method="POST",
            data={
                "model": "llama3:8b",
                "messages": [{"role": "user", "content": "Summarize the attached file canary contents."}],
                "stream": False,
                "files": [{"type": "file", "id": "f123"}],
            },
            headers={"Authorization": "Bearer bob-token"},
            timeout=120,
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_full_file_model_request_contract(self, mock_json):
        """Adapter preserves full upstream FileModel, owner ID, and sets collection_name properly."""
        mock_json.return_value = {
            "results": [{"file_id": "file-12345", "status": "completed"}],
            "errors": [],
        }
        full_file_model = {
            "id": "file-12345",
            "user_id": "alice-uuid-999",
            "hash": "abc123sha256",
            "filename": "confidential_project.txt",
            "path": "/data/uploads/f123.txt",
            "data": {"content": "Original Alice text"},
            "meta": {"collection_name": "kb-uuid-456", "size": 1024},
            "created_at": 1700000000,
            "updated_at": 1700000500,
        }
        res = self.adapter.overwrite_resource(
            self.base_url,
            self.bob,
            resource_ref="file-12345",
            payload="POISONED TRACER: token-abc",
            collection_name="kb-uuid-456",
            file_model=full_file_model,
        )
        self.assertEqual(res["results"][0]["status"], "completed")
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/retrieval/process/files/batch",
            method="POST",
            data={
                "files": [
                    {
                        "id": "file-12345",
                        "user_id": "alice-uuid-999",
                        "hash": "abc123sha256",
                        "filename": "confidential_project.txt",
                        "path": "/data/uploads/f123.txt",
                        "data": {"content": "POISONED TRACER: token-abc"},
                        "meta": {"collection_name": "kb-uuid-456", "size": 1024},
                        "created_at": 1700000000,
                        "updated_at": 1700000500,
                    }
                ],
                "collection_name": "kb-uuid-456",
            },
            headers={"Authorization": "Bearer bob-token"},
        )

    @patch.object(OpenWebUIAdapter, "get_file_metadata")
    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_retrieves_authoritative_metadata_when_omitted(self, mock_json, mock_meta):
        """When file_model is omitted, retrieves authoritative metadata and preserves victim owner ID."""
        mock_meta.return_value = {
            "id": "file-12345",
            "user_id": "alice-uuid-999",
            "filename": "victim_doc.txt",
            "data": {"content": "original content"},
            "meta": {},
        }
        mock_json.return_value = {"results": [{"file_id": "file-12345", "status": "completed"}], "errors": []}

        bob_session = UserSession(
            username="bob",
            role="attacker",
            token="bob-token",
            headers={"Authorization": "Bearer bob-token"},
            metadata={"knowledge_ids": ["kb-session-789"]},
        )
        res = self.adapter.overwrite_resource(
            self.base_url,
            bob_session,
            resource_ref="file-12345",
            payload="POISONED TRACER",
            collection_name="alice-target-kb-456",
        )
        self.assertEqual(res["results"][0]["status"], "completed")
        mock_meta.assert_called_once_with(self.base_url, bob_session, "file-12345")
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/retrieval/process/files/batch",
            method="POST",
            data={
                "files": [
                    {
                        "id": "file-12345",
                        "user_id": "alice-uuid-999",
                        "filename": "victim_doc.txt",
                        "data": {"content": "POISONED TRACER"},
                        "meta": {},
                    }
                ],
                "collection_name": "alice-target-kb-456",
            },
            headers={"Authorization": "Bearer bob-token"},
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_missing_explicit_collection_rejected_even_with_session_kbs(self, mock_json):
        """Missing explicit collection returns an error and never dispatches batch request, even when Bob has knowledge_ids."""
        session_with_kb = UserSession(
            username="bob",
            role="attacker",
            token="bob-token",
            headers={"Authorization": "Bearer bob-token"},
            metadata={"knowledge_ids": ["attacker-kb-1", "attacker-kb-2"]},
        )
        valid_model = {"id": "file-12345", "user_id": "alice-uuid-999"}
        res = self.adapter.overwrite_resource(
            self.base_url,
            session_with_kb,
            "file-12345",
            "payload",
            collection_name=None,
            file_model=valid_model,
        )
        self.assertIn("error", res)
        self.assertIn("explicit non-empty collection_name required", res["error"])
        mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_attacker_kb_not_selected(self, mock_json):
        """Bob having an accessible KB does not cause that KB to be selected."""
        session_with_attacker_kb = UserSession(
            username="bob",
            role="attacker",
            token="bob-token",
            headers={"Authorization": "Bearer bob-token"},
            metadata={"knowledge_ids": ["attacker-accessible-kb"]},
        )
        valid_model = {"id": "file-12345", "user_id": "alice-uuid-999"}
        res = self.adapter.overwrite_resource(
            self.base_url,
            session_with_attacker_kb,
            "file-12345",
            "payload",
            collection_name=None,
            file_model=valid_model,
        )
        self.assertIn("error", res)
        mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_missing_explicit_collection_does_not_fallback_to_meta(self, mock_json):
        """Missing explicit collection does not fall back to meta.collection_name."""
        model_with_meta_kb = {
            "id": "file-12345",
            "user_id": "alice-uuid-999",
            "meta": {"collection_name": "victim-meta-kb"},
        }
        res = self.adapter.overwrite_resource(
            self.base_url,
            self.bob,
            "file-12345",
            "payload",
            collection_name=None,
            file_model=model_with_meta_kb,
        )
        self.assertIn("error", res)
        self.assertIn("explicit non-empty collection_name required", res["error"])
        mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_valid_explicit_alice_collection_passed_unchanged(self, mock_json):
        """A valid explicit Alice target collection is passed unchanged to batch endpoint."""
        mock_json.return_value = {"results": [], "errors": []}
        valid_model = {"id": "file-12345", "user_id": "alice-uuid-999"}
        res = self.adapter.overwrite_resource(
            self.base_url,
            self.bob,
            "file-12345",
            "payload",
            collection_name="alice-verified-kb-456",
            file_model=valid_model,
        )
        mock_json.assert_called_once()
        self.assertEqual(mock_json.call_args[1]["data"]["collection_name"], "alice-verified-kb-456")

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_invalid_explicit_collection_causes_no_batch_request(self, mock_json):
        """An invalid explicit collection causes no batch request."""
        valid_model = {"id": "file-12345", "user_id": "alice-uuid-999"}
        invalid_collections = ["", "   ", None, 12345, []]
        for invalid_col in invalid_collections:
            res = self.adapter.overwrite_resource(
                self.base_url,
                self.bob,
                "file-12345",
                "payload",
                collection_name=invalid_col,  # type: ignore
                file_model=valid_model,
            )
            self.assertIn("error", res, f"Expected error for collection: {repr(invalid_col)}")
            mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_mismatched_id_rejected(self, mock_json):
        """Explicit file_model with mismatched ID fails closed without sending HTTP batch request."""
        mismatched_model = {
            "id": "different-file-id",
            "user_id": "alice-uuid-999",
        }
        res = self.adapter.overwrite_resource(
            self.base_url, self.bob, "file-12345", "payload",
            collection_name="kb-123", file_model=mismatched_model
        )
        self.assertIn("error", res)
        self.assertIn("does not match resource_ref", res["error"])
        mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_missing_or_invalid_user_id_rejected(self, mock_json):
        """FileModel with missing, empty, whitespace, or non-string user_id fails closed without HTTP request."""
        invalid_cases = [
            {"id": "file-12345"},
            {"id": "file-12345", "user_id": ""},
            {"id": "file-12345", "user_id": "   "},
            {"id": "file-12345", "user_id": None},
            {"id": "file-12345", "user_id": 12345},
        ]
        for idx, model in enumerate(invalid_cases):
            res = self.adapter.overwrite_resource(
                self.base_url, self.bob, "file-12345", "payload",
                collection_name="kb-123", file_model=model
            )
            self.assertIn("error", res, f"Expected error for case {idx}: {model}")
            mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_non_dict_file_model_rejected(self, mock_json):
        """Non-dict file_model fails closed without sending HTTP batch request."""
        for invalid_model in ["not-a-dict", ["file-12345"], 123]:
            res = self.adapter.overwrite_resource(
                self.base_url, self.bob, "file-12345", "payload",
                collection_name="kb-123", file_model=invalid_model  # type: ignore
            )
            self.assertIn("error", res)
            mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "get_file_metadata")
    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_failed_metadata_retrieval_rejected(self, mock_json, mock_meta):
        """When metadata retrieval fails or returns invalid model, fails closed without HTTP batch request."""
        # Case 1: get_file_metadata returns None
        mock_meta.return_value = None
        res1 = self.adapter.overwrite_resource(
            self.base_url, self.bob, "file-12345", "payload", collection_name="kb-123"
        )
        self.assertIn("error", res1)
        mock_json.assert_not_called()

        # Case 2: get_file_metadata returns mismatched id
        mock_meta.return_value = {"id": "other-id", "user_id": "alice-uid"}
        res2 = self.adapter.overwrite_resource(
            self.base_url, self.bob, "file-12345", "payload", collection_name="kb-123"
        )
        self.assertIn("error", res2)
        mock_json.assert_not_called()

        # Case 3: get_file_metadata returns missing/empty user_id
        mock_meta.return_value = {"id": "file-12345", "user_id": ""}
        res3 = self.adapter.overwrite_resource(
            self.base_url, self.bob, "file-12345", "payload", collection_name="kb-123"
        )
        self.assertIn("error", res3)
        mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_missing_collection_rejected(self, mock_json):
        """When no valid collection can be established, fails closed without sending HTTP request."""
        valid_model = {
            "id": "file-12345",
            "user_id": "alice-uuid-999",
            "meta": {},
        }
        bob_no_kb = UserSession(
            username="bob", role="attacker", token="bob-token",
            headers={"Authorization": "Bearer bob-token"}, metadata={"knowledge_ids": []}
        )
        res = self.adapter.overwrite_resource(
            self.base_url, bob_no_kb, "file-12345", "payload",
            collection_name=None, file_model=valid_model
        )
        self.assertIn("error", res)
        self.assertIn("explicit non-empty collection_name required", res["error"])
        mock_json.assert_not_called()

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_rejection_no_unsupported_fallback(self, mock_json):
        """When server returns error on batch endpoint, returns error without fallback."""
        mock_json.return_value = {"error": "Not Found", "code": 404}
        valid_model = {"id": "file-12345", "user_id": "alice-uuid-999"}
        res = self.adapter.overwrite_resource(
            self.base_url, self.bob, "file-12345", "poisoned content",
            collection_name="kb-123", file_model=valid_model
        )
        self.assertEqual(res, {"error": "Not Found", "code": 404})
        self.assertEqual(mock_json.call_count, 1)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_read_file_content_authorized_path(self, mock_json):
        mock_json.return_value = "Content of Alice private file"
        content = self.adapter.read_file_content(self.base_url, self.alice, "f1")
        self.assertEqual(content, "Content of Alice private file")
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/files/f1/data/content",
            method="GET",
            headers={"Authorization": "Bearer alice-token"},
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_read_file_content_fallback_path(self, mock_json):
        # Primary returns None/error, secondary returns file object with data.content
        mock_json.side_effect = [
            None,
            {"data": {"content": "Fallback content from file record"}},
        ]
        content = self.adapter.read_file_content(self.base_url, self.alice, "f1")
        self.assertEqual(content, "Fallback content from file record")
        self.assertEqual(mock_json.call_count, 2)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_read_file_content_never_calls_raw_content_endpoint(self, mock_json):
        # Primary /data/content returns None, secondary /files/{id} returns no data.content
        mock_json.side_effect = [
            None,
            {"id": "f1", "meta": {"name": "test.txt"}},
        ]
        content = self.adapter.read_file_content(self.base_url, self.alice, "f1")
        self.assertIsNone(content)
        # Verify it made exactly 2 calls and NEVER called /api/v1/files/f1/content
        self.assertEqual(mock_json.call_count, 2)
        called_urls = [call[0][0] for call in mock_json.call_args_list]
        self.assertIn("http://mock-target:8080/api/v1/files/f1/data/content", called_urls)
        self.assertIn("http://mock-target:8080/api/v1/files/f1", called_urls)
        self.assertNotIn("http://mock-target:8080/api/v1/files/f1/content", called_urls)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_query_collection_error_handling(self, mock_json):
        mock_json.return_value = {"error": "Invalid syntax", "code": 400}
        text, contexts, raw = self.adapter.query_collection(
            self.base_url,
            self.bob,
            collection_names=["malformed-filter"],
        )
        self.assertEqual(text, "")
        self.assertEqual(contexts, [])
        self.assertEqual(raw, {"error": "Invalid syntax", "code": 400})

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_enumerate_resources(self, mock_json):
        # First call for files, second for knowledge
        mock_json.side_effect = [
            [{"id": "file-1"}, {"id": "file-2"}],
            [{"id": "kb-1"}],
        ]
        discovered = self.adapter.enumerate_resources(self.base_url, self.bob)
        self.assertEqual(discovered, ["file-1", "file-2", "kb-1"])

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_share_and_revoke_resource(self, mock_json):
        mock_json.return_value = {"status": "success"}

        # Share
        share_res = self.adapter.share_resource(self.base_url, self.alice, "kb-1", self.bob)
        self.assertEqual(share_res, {"status": "success"})

        # Revoke
        revoke_res = self.adapter.revoke_resource(self.base_url, self.alice, "kb-1", self.bob)
        self.assertEqual(revoke_res, {"status": "success"})
        self.assertEqual(mock_json.call_count, 2)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_authenticate_user_top_level_id_success(self, mock_json):
        """Open WebUI v0.8.5/v0.8.6 top-level 'id' extraction succeeds."""
        mock_json.return_value = {
            "token": "valid-jwt-token-123",
            "token_type": "Bearer",
            "id": "openwebui-user-uuid-789",
            "email": "alice@firedamp-audit.internal",
            "name": "Alice",
            "role": "user",
        }
        session = self.adapter.authenticate_user(self.base_url, "alice", "AlicePass!123", role="owner")
        self.assertEqual(session.token, "valid-jwt-token-123")
        self.assertEqual(session.metadata["user_id"], "openwebui-user-uuid-789")
        self.assertEqual(session.headers, {"Authorization": "Bearer valid-jwt-token-123"})

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_authenticate_user_missing_or_malformed_top_level_id(self, mock_json):
        """When top-level 'id' is missing, empty, or non-string, user_id is None (fail-closed)."""
        # Case 1: missing id
        mock_json.return_value = {"token": "valid-jwt-token-123"}
        s1 = self.adapter.authenticate_user(self.base_url, "alice", "AlicePass!123")
        self.assertIsNone(s1.metadata["user_id"])

        # Case 2: empty string id
        mock_json.return_value = {"token": "valid-jwt-token-123", "id": ""}
        s2 = self.adapter.authenticate_user(self.base_url, "alice", "AlicePass!123")
        self.assertIsNone(s2.metadata["user_id"])

        # Case 3: whitespace-only id
        mock_json.return_value = {"token": "valid-jwt-token-123", "id": "   "}
        s3 = self.adapter.authenticate_user(self.base_url, "alice", "AlicePass!123")
        self.assertIsNone(s3.metadata["user_id"])

        # Case 4: non-string id
        mock_json.return_value = {"token": "valid-jwt-token-123", "id": 12345}
        s4 = self.adapter.authenticate_user(self.base_url, "alice", "AlicePass!123")
        self.assertIsNone(s4.metadata["user_id"])

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_delete_file_upstream_response_success(self, mock_json):
        """Open WebUI v0.8.5/v0.8.6 deletion returns {"message": "File deleted successfully"}."""
        mock_json.return_value = {"message": "File deleted successfully"}
        success = self.adapter.delete_file(self.base_url, self.alice, "target-f123")
        self.assertTrue(success)
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/files/target-f123",
            method="DELETE",
            headers={"Authorization": "Bearer alice-token"},
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_delete_file_failure_modes(self, mock_json):
        """Verify delete_file fails closed on HTTP errors, transport errors, and malformed bodies."""
        # HTTP 404 / 403 error
        mock_json.return_value = {"error": {"detail": "File not found"}, "code": 404}
        self.assertFalse(self.adapter.delete_file(self.base_url, self.alice, "target-f123"))

        # Transport exception captured by _json_request
        mock_json.return_value = {"error": "Connection refused"}
        self.assertFalse(self.adapter.delete_file(self.base_url, self.alice, "target-f123"))

        # Empty response
        mock_json.return_value = {}
        self.assertFalse(self.adapter.delete_file(self.base_url, self.alice, "target-f123"))

        # Unrecognized response body without message confirmation
        mock_json.return_value = {"unrelated": "data"}
        self.assertFalse(self.adapter.delete_file(self.base_url, self.alice, "target-f123"))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_delete_file_negative_message_contracts(self, mock_json):
        """Verify delete_file rejects arbitrary substrings like 'deleted' or 'success'."""
        for negative_msg in [
            "File not deleted",
            "Deletion failed",
            "Deletion success could not be confirmed",
        ]:
            mock_json.return_value = {"message": negative_msg}
            self.assertFalse(
                self.adapter.delete_file(self.base_url, self.alice, "target-f123"),
                f"Expected False for message: {negative_msg}",
            )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_validate_session_success_and_failures(self, mock_json):
        """Verify validate_session against /api/v1/auths/."""
        # Success via /api/v1/auths/
        mock_json.return_value = {"id": "user-uuid", "email": "alice@test.internal"}
        self.assertTrue(self.adapter.validate_session(self.base_url, self.alice))

        # Failure via 401/403
        mock_json.return_value = {"error": "Unauthorized", "code": 401}
        self.assertFalse(self.adapter.validate_session(self.base_url, self.alice))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_file_metadata_success_and_failure(self, mock_json):
        """Verify get_file_metadata retrieves server file record."""
        mock_json.return_value = {"id": "f1", "user_id": "alice-id", "filename": "test.md"}
        meta = self.adapter.get_file_metadata(self.base_url, self.alice, "f1")
        self.assertEqual(meta["user_id"], "alice-id")

        mock_json.return_value = {"error": "Not found", "code": 404}
        self.assertIsNone(self.adapter.get_file_metadata(self.base_url, self.alice, "f1"))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_authenticated_user_id_success(self, mock_json):
        """Verify get_authenticated_user_id obtains non-empty id from GET /api/v1/auths/."""
        mock_json.return_value = {
            "id": "openwebui-uuid-999",
            "email": "bob@firedamp.test",
            "name": "Bob",
            "role": "user",
        }
        uid = self.adapter.get_authenticated_user_id(self.base_url, self.bob)
        self.assertEqual(uid, "openwebui-uuid-999")
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/auths/",
            method="GET",
            headers={"Authorization": "Bearer bob-token"},
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_authenticated_user_id_missing_or_malformed_id(self, mock_json):
        """Verify get_authenticated_user_id fails closed when id is missing, empty, or whitespace."""
        # Missing id (only email/role)
        mock_json.return_value = {"email": "bob@firedamp.test", "role": "user"}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

        # Empty string
        mock_json.return_value = {"id": ""}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

        # Whitespace
        mock_json.return_value = {"id": "   "}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

        # Non-string
        mock_json.return_value = {"id": 12345}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_authenticated_user_id_http_errors_and_transport_failure(self, mock_json):
        """Verify fail-closed behavior on 401, 403, and transport exceptions."""
        mock_json.return_value = {"error": "Unauthorized", "code": 401}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

        mock_json.return_value = {"error": "Forbidden", "code": 403}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

        mock_json.return_value = {"error": "Connection refused"}
        self.assertIsNone(self.adapter.get_authenticated_user_id(self.base_url, self.bob))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_primary_success(self, mock_json):
        """Verify get_knowledge_base_files parses items from /api/v1/knowledge/{id}/files?page=1."""
        mock_json.return_value = {
            "items": [
                {"id": "file-1"},
                {"file": {"id": "file-2"}},
                {"file_id": "file-3"},
            ],
            "total": 3,
        }
        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertEqual(files, ["file-1", "file-2", "file-3"])
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/knowledge/kb-uuid-1/files?page=1",
            method="GET",
            headers={"Authorization": "Bearer alice-token"},
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_target_on_page_2(self, mock_json):
        """Verify get_knowledge_base_files correctly paginates and finds target file on page 2."""
        page1 = {"items": [{"id": f"page1-f{i}"} for i in range(30)], "total": 32}
        page2 = {"items": [{"id": "page2-f0"}, {"id": "target-file-on-page-2"}], "total": 32}
        mock_json.side_effect = [page1, page2]

        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertIsNotNone(files)
        self.assertEqual(len(files), 32)
        self.assertIn("target-file-on-page-2", files)
        self.assertEqual(mock_json.call_count, 2)
        self.assertEqual(
            mock_json.call_args_list[0][0][0],
            "http://mock-target:8080/api/v1/knowledge/kb-uuid-1/files?page=1",
        )
        self.assertEqual(
            mock_json.call_args_list[1][0][0],
            "http://mock-target:8080/api/v1/knowledge/kb-uuid-1/files?page=2",
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_target_on_page_after_page_2(self, mock_json):
        """Verify get_knowledge_base_files correctly paginates beyond page 2 (page 3)."""
        page1 = {"items": [{"id": f"page1-f{i}"} for i in range(30)], "total": 65}
        page2 = {"items": [{"id": f"page2-f{i}"} for i in range(30)], "total": 65}
        page3 = {
            "items": [{"id": f"page3-f{i}"} for i in range(4)] + [{"id": "target-file-on-page-3"}],
            "total": 65,
        }
        mock_json.side_effect = [page1, page2, page3]

        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertIsNotNone(files)
        self.assertEqual(len(files), 65)
        self.assertIn("target-file-on-page-3", files)
        self.assertEqual(mock_json.call_count, 3)
        self.assertEqual(
            mock_json.call_args_list[2][0][0],
            "http://mock-target:8080/api/v1/knowledge/kb-uuid-1/files?page=3",
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_successfully_enumerated_empty_kb(self, mock_json):
        """Verify successfully enumerated empty knowledge base returns [] instead of None."""
        mock_json.return_value = {"items": [], "total": 0}
        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-empty-1")
        self.assertEqual(files, [])

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_first_page_succeeds_subsequent_page_fails(self, mock_json):
        """When first page succeeds but a subsequent page fails, returns None and does not return partial list."""
        page1 = {"items": [{"id": f"page1-f{i}"} for i in range(30)], "total": 45}
        page2 = {"error": "Internal Server Error", "code": 500}
        mock_json.side_effect = [page1, page2]

        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertIsNone(files)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_malformed_responses(self, mock_json):
        """Verify invalid or malformed responses fail closed returning None."""
        # 1. Missing total
        mock_json.return_value = {"items": [{"id": "file-1"}]}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 2. String total
        mock_json.return_value = {"items": [{"id": "file-1"}], "total": "1"}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 3. Total shifted between pages
        mock_json.side_effect = [
            {"items": [{"id": f"f{i}"} for i in range(30)], "total": 40},
            {"items": [{"id": f"f{i}"} for i in range(30, 40)], "total": 35},
        ]
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 4. Premature empty items before total satisfied
        mock_json.side_effect = [
            {"items": [{"id": f"f{i}"} for i in range(30)], "total": 40},
            {"items": [], "total": 40},
        ]
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 5. Malformed item type (e.g. integer or dict missing id)
        mock_json.side_effect = None
        mock_json.return_value = {"items": [12345], "total": 1}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))
        mock_json.return_value = {"items": [{"id": None}], "total": 1}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 6. HTTP error on first page
        mock_json.return_value = {"error": "Not Found", "code": 404}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_duplicate_file_id_single_page_rejected(self, mock_json):
        """Verify duplicate file IDs within a single page cause get_knowledge_base_files to return None."""
        mock_json.return_value = {
            "items": [{"id": "file-1"}, {"id": "file-1"}],
            "total": 2,
        }
        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertIsNone(files)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_duplicate_file_id_across_pages_rejected(self, mock_json):
        """Verify duplicate file IDs across pages cause get_knowledge_base_files to return None."""
        page1 = {
            "items": [{"id": f"file-{i}"} for i in range(30)],
            "total": 31,
        }
        page2 = {
            "items": [{"id": "file-0"}],  # duplicate of file-0 from page 1
            "total": 31,
        }
        mock_json.side_effect = [page1, page2]
        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertIsNone(files)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_valid_pagination_unique_ids_succeeds(self, mock_json):
        """Verify valid pagination with strictly unique file IDs succeeds and matches expected total."""
        page1 = {
            "items": [{"id": f"file-{i}"} for i in range(30)],
            "total": 35,
        }
        page2 = {
            "items": [{"id": f"file-{i}"} for i in range(30, 35)],
            "total": 35,
        }
        mock_json.side_effect = [page1, page2]
        files = self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1")
        self.assertIsNotNone(files)
        self.assertEqual(len(files), 35)
        self.assertEqual(files, [f"file-{i}" for i in range(35)])

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_malformed_nested_file_metadata(self, mock_json):
        """Verify get_knowledge_base_files returns None for malformed nested file values."""
        # 1. Nested file is a string
        mock_json.return_value = {"items": [{"file": "unexpected"}], "total": 1}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 2. Nested file is a list
        mock_json.return_value = {"items": [{"file": ["unexpected"]}], "total": 1}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

        # 3. Nested file is an integer
        mock_json.return_value = {"items": [{"file": 123}], "total": 1}
        self.assertIsNone(self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_knowledge_base_files_supported_item_shapes(self, mock_json):
        """Verify valid supported response shapes for file items continue working."""
        # 1. Standard dictionary with "id"
        mock_json.return_value = {"items": [{"id": "file-1"}], "total": 1}
        self.assertEqual(
            self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"),
            ["file-1"],
        )

        # 2. Nested dictionary with "file": {"id": "file-1"}
        mock_json.return_value = {"items": [{"file": {"id": "file-1"}}], "total": 1}
        self.assertEqual(
            self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"),
            ["file-1"],
        )

        # 3. Dictionary with "file_id"
        mock_json.return_value = {"items": [{"file_id": "file-1"}], "total": 1}
        self.assertEqual(
            self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"),
            ["file-1"],
        )

        # 4. Bare string item
        mock_json.return_value = {"items": ["file-1"], "total": 1}
        self.assertEqual(
            self.adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-uuid-1"),
            ["file-1"],
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_35_kbs_paginated_to_page_2(self, mock_json):
        """Verify get_accessible_knowledge_bases paginates 35 KBs across page 1 and page 2."""
        page1 = {
            "items": [{"id": f"kb-{i}"} for i in range(30)],
            "total": 35,
        }
        page2 = {
            "items": [{"id": f"kb-{i}"} for i in range(30, 35)],
            "total": 35,
        }
        mock_json.side_effect = [page1, page2]

        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertIsNotNone(kbs)
        self.assertEqual(len(kbs), 35)
        self.assertEqual(kbs[:5], ["kb-0", "kb-1", "kb-2", "kb-3", "kb-4"])
        self.assertEqual(kbs[-5:], ["kb-30", "kb-31", "kb-32", "kb-33", "kb-34"])
        self.assertEqual(mock_json.call_count, 2)
        self.assertEqual(
            mock_json.call_args_list[0][0][0],
            "http://mock-target:8080/api/v1/knowledge/?page=1",
        )
        self.assertEqual(
            mock_json.call_args_list[1][0][0],
            "http://mock-target:8080/api/v1/knowledge/?page=2",
        )

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_zero_accessible_kbs(self, mock_json):
        """Verify user with zero accessible KBs returns [] and inconsistent total=0 fails closed."""
        # Clean empty
        mock_json.return_value = {"items": [], "total": 0}
        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertEqual(kbs, [])

        # Inconsistent: total=0 but items non-empty
        mock_json.return_value = {"items": [{"id": "kb-ghost"}], "total": 0}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_first_page_succeeds_second_page_fails(self, mock_json):
        """When first page succeeds but second page returns an error, returns None."""
        page1 = {"items": [{"id": f"kb-{i}"} for i in range(30)], "total": 35}
        page2 = {"error": "Internal server error", "code": 500}
        mock_json.side_effect = [page1, page2]

        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertIsNone(kbs)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_total_changing_between_pages(self, mock_json):
        """When total shifts between page 1 and page 2, returns None."""
        page1 = {"items": [{"id": f"kb-{i}"} for i in range(30)], "total": 35}
        page2 = {"items": [{"id": f"kb-{i}"} for i in range(30, 40)], "total": 40}
        mock_json.side_effect = [page1, page2]

        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertIsNone(kbs)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_missing_or_invalid_total(self, mock_json):
        """Verify missing, boolean, string, or negative total fails closed."""
        # Missing total
        mock_json.return_value = {"items": [{"id": "kb-1"}]}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

        # String total
        mock_json.return_value = {"items": [{"id": "kb-1"}], "total": "1"}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

        # Bool total
        mock_json.return_value = {"items": [{"id": "kb-1"}], "total": True}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

        # Negative total
        mock_json.return_value = {"items": [], "total": -5}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_malformed_items_or_missing_ids(self, mock_json):
        """Verify non-dict/str items or missing/blank IDs fail closed."""
        # Non-dict/str item
        mock_json.return_value = {"items": [999], "total": 1}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

        # Missing id
        mock_json.return_value = {"items": [{"id": None}], "total": 1}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

        # Blank id
        mock_json.return_value = {"items": [{"id": "   "}], "total": 1}
        self.assertIsNone(self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_duplicate_kb_ids_across_pages_rejected(self, mock_json):
        """Verify duplicate KB IDs across pages are rejected rather than silently truncated."""
        page1 = {"items": [{"id": f"kb-{i}"} for i in range(30)], "total": 32}
        page2 = {"items": [{"id": "kb-29"}, {"id": "kb-30"}], "total": 32}  # kb-29 duplicate from page 1
        mock_json.side_effect = [page1, page2]

        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertIsNone(kbs)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_premature_empty_page_rejected(self, mock_json):
        """Verify empty page returned before reaching total is rejected."""
        page1 = {"items": [{"id": f"kb-{i}"} for i in range(30)], "total": 35}
        page2 = {"items": [], "total": 35}
        mock_json.side_effect = [page1, page2]

        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertIsNone(kbs)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_get_accessible_knowledge_bases_exceeding_max_supported_page_count(self, mock_json):
        """Verify total exceeding max page capacity is rejected."""
        mock_json.return_value = {"items": [{"id": "kb-1"}], "total": 3500}
        kbs = self.adapter.get_accessible_knowledge_bases(self.base_url, self.alice)
        self.assertIsNone(kbs)

    def test_base_adapter_explicit_membership_defaults(self):
        """Verify base TargetAdapter default implementations return None for unverified operations."""
        class MinimalBaseAdapter(TargetAdapter):
            @property
            def target_name(self): return "minimal"
            def authenticate_user(self, *a, **kw): pass
            def ingest_document(self, *a, **kw): pass
            def query_rag(self, *a, **kw): pass
            def query_resource_direct(self, *a, **kw): pass
            def overwrite_resource(self, *a, **kw): pass
            def enumerate_resources(self, *a, **kw): return []
            def share_resource(self, *a, **kw): return True
            def revoke_resource(self, *a, **kw): return True
            def cleanup(self, *a, **kw): pass

        adapter = MinimalBaseAdapter()
        self.assertIsNone(adapter.get_knowledge_base_files(self.base_url, self.alice, "kb-1"))
        self.assertIsNone(adapter.get_accessible_knowledge_bases(self.base_url, self.alice))

    @patch.object(OpenWebUIAdapter, "_json_request")
    @patch.object(OpenWebUIAdapter, "_multipart_upload")
    def test_inject_into_collection_success_flow(self, mock_upload, mock_json):
        """Verifies inject_into_collection uploads Bob file then adds to Alice collection via /file/add."""
        mock_upload.return_value = {"id": "uploaded-file-uuid-777"}
        mock_json.return_value = {"status": True}

        from core.engine import DecoyDocument
        doc = DecoyDocument("poison", "adversarial payload", "write_poison", [])

        res = self.adapter.inject_into_collection(
            self.base_url,
            self.bob,
            target_collection_id="alice-kb-uuid-999",
            document=doc,
        )
        self.assertEqual(res, {"status": True, "uploaded_file_id": "uploaded-file-uuid-777"})
        self.assertEqual(self.bob.metadata["file_ids"], ["uploaded-file-uuid-777"])
        mock_upload.assert_called_once()
        mock_json.assert_called_once_with(
            "http://mock-target:8080/api/v1/knowledge/alice-kb-uuid-999/file/add",
            method="POST",
            data={"file_id": "uploaded-file-uuid-777"},
            headers={"Authorization": "Bearer bob-token"},
        )


    @patch.object(OpenWebUIAdapter, "_json_request", side_effect=RuntimeError("link transport reset"))
    @patch.object(OpenWebUIAdapter, "_multipart_upload")
    def test_inject_into_collection_preserves_uploaded_id_when_link_request_raises(self, mock_upload, mock_json):
        mock_upload.return_value = {"id": "uploaded-file-after-link-error"}
        from core.engine import DecoyDocument
        document = DecoyDocument("poison", "payload", "write_poison", [])

        result = self.adapter.inject_into_collection(
            self.base_url, self.bob, "alice-kb-123", document
        )

        self.assertIn("error", result)
        self.assertEqual(result["uploaded_file_id"], "uploaded-file-after-link-error")
        self.assertIn("uploaded-file-after-link-error", self.bob.metadata["file_ids"])
        mock_upload.assert_called_once()
        mock_json.assert_called_once()


    @patch.object(OpenWebUIAdapter, "_json_request")
    @patch.object(OpenWebUIAdapter, "_multipart_upload")
    def test_inject_into_collection_missing_collection_id_rejected(self, mock_upload, mock_json):
        """Rejects missing or invalid collection ID before making upload or API requests."""
        from core.engine import DecoyDocument
        doc = DecoyDocument("poison", "adversarial payload", "write_poison", [])

        for invalid_coll in [None, "", "   ", 123]:
            res = self.adapter.inject_into_collection(
                self.base_url,
                self.bob,
                target_collection_id=invalid_coll,  # type: ignore
                document=doc,
            )
            self.assertIn("error", res)
            self.assertIn("explicit non-empty collection ID required", res["error"])
            mock_upload.assert_not_called()
            mock_json.assert_not_called()

    def test_base_adapter_inject_into_collection_fails_closed_without_calling_overwrite(self):
        """Base TargetAdapter fails closed without mistaking collection ID for file ID."""
        class TestTargetAdapter(TargetAdapter):
            @property
            def target_name(self): return "test_adapter"
            def __init__(self):
                self.overwrite_called = False
            def authenticate_user(self, *a, **kw): pass
            def ingest_document(self, *a, **kw): pass
            def query_rag(self, *a, **kw): pass
            def query_resource_direct(self, *a, **kw): pass
            def overwrite_resource(self, *a, **kw):
                self.overwrite_called = True
                return {"status": True}
            def enumerate_resources(self, *a, **kw): return []
            def share_resource(self, *a, **kw): return True
            def revoke_resource(self, *a, **kw): return True
            def cleanup(self, *a, **kw): pass

        adapter = TestTargetAdapter()
        from core.engine import DecoyDocument
        doc = DecoyDocument("poison", "adversarial payload", "write_poison", [])

        res = adapter.inject_into_collection(self.base_url, self.bob, "collection-uuid-1", doc)
        self.assertFalse(adapter.overwrite_called)
        self.assertIn("error", res)
        self.assertIn("not supported by this adapter", res["error"])
        self.assertEqual(res.get("code"), 501)

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_composite_adapter_accessible_kbs_and_membership_resolution_end_to_end(self, mock_json):
        """
        Composite end-to-end contract test:
        Verifies actual OpenWebUIAdapter.get_accessible_knowledge_bases(),
        actual OpenWebUIAdapter.get_knowledge_base_files(), and actual
        neutral resolve_file_knowledge_base() work together seamlessly.
        Only the HTTP transport boundary (_json_request) is mocked.
        """
        from probes.knowledge_membership import resolve_file_knowledge_base

        target_file_id = "target-secret-file-999"
        requested_urls = []

        def transport_mock(url, method="GET", data=None, headers=None, timeout=30):
            requested_urls.append(url)
            # 1. Candidate KB enumeration pagination (35 KBs: 0-29 on page 1, 30-34 on page 2)
            if "/api/v1/knowledge/?page=1" in url:
                return {
                    "items": [{"id": f"kb-{i}"} for i in range(30)],
                    "total": 35,
                }
            if "/api/v1/knowledge/?page=2" in url:
                return {
                    "items": [{"id": f"kb-{i}"} for i in range(30, 35)],
                    "total": 35,
                }

            # 2. File membership for kb-32 (paginated, 31 files, target on page 2)
            if "/api/v1/knowledge/kb-32/files?page=1" in url:
                return {
                    "items": [{"id": f"unrelated-file-{i}"} for i in range(30)],
                    "total": 31,
                }
            if "/api/v1/knowledge/kb-32/files?page=2" in url:
                return {
                    "items": [{"id": target_file_id}],
                    "total": 31,
                }

            # 3. File membership for all other 34 KBs (verified empty)
            for i in range(35):
                if i != 32 and f"/api/v1/knowledge/kb-{i}/files?page=1" in url:
                    return {
                        "items": [],
                        "total": 0,
                    }

            return {"error": f"Unhandled mock request: {url}", "code": 404}

        mock_json.side_effect = transport_mock

        # Execute neutral resolver using the real adapter instance
        resolved_kb, err = resolve_file_knowledge_base(
            adapter=self.adapter,
            base_url=self.base_url,
            session=self.alice,
            target_file_id=target_file_id,
        )

        # Expected result: exactly ("kb-32", None)
        self.assertEqual(resolved_kb, "kb-32")
        self.assertIsNone(err)

        # Verify candidate pages 1 and 2 were requested
        self.assertIn("http://mock-target:8080/api/v1/knowledge/?page=1", requested_urls)
        self.assertIn("http://mock-target:8080/api/v1/knowledge/?page=2", requested_urls)

        # Verify all 35 candidate KBs were checked
        for i in range(35):
            expected_kb_url = f"http://mock-target:8080/api/v1/knowledge/kb-{i}/files?page=1"
            self.assertIn(expected_kb_url, requested_urls)

        # Verify kb-32 membership pages 1 and 2 were requested
        self.assertIn("http://mock-target:8080/api/v1/knowledge/kb-32/files?page=1", requested_urls)
        self.assertIn("http://mock-target:8080/api/v1/knowledge/kb-32/files?page=2", requested_urls)


    @patch.object(OpenWebUIAdapter, "delete_file")
    @patch.object(OpenWebUIAdapter, "get_file_metadata")
    @patch.object(OpenWebUIAdapter, "get_authenticated_user_id")
    def test_cleanup_deletes_only_registered_current_run_disposables(self, mock_auth, mock_meta, mock_delete):
        from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY

        _TRUSTED_SCAN_REGISTRY.clear()
        try:
            run_id = "adapter-cleanup-run"
            disposable_id = "scan-created-file"
            _TRUSTED_SCAN_REGISTRY.register(run_id, disposable_id, "alice")
            session = UserSession(
                username="alice", role="user", headers={"Authorization": "Bearer alice-token"},
                metadata={
                    "run_id": run_id,
                    "user_id": "alice-server-id",
                    "knowledge_ids": ["preexisting-kb"],
                    "file_ids": ["ordinary-file", disposable_id],
                    "ordinary_file_ids": ["ordinary-file"],
                    "disposable_file_ids": [disposable_id],
                },
            )
            mock_auth.return_value = "alice-server-id"
            mock_meta.return_value = {"id": disposable_id, "user_id": "alice-server-id"}
            mock_delete.return_value = True

            with patch.object(self.adapter, "_json_request") as mock_json:
                self.adapter.cleanup(self.base_url, session)

            mock_auth.assert_called_once_with(self.base_url, session)
            mock_meta.assert_called_once_with(self.base_url, session, disposable_id)
            mock_delete.assert_called_once_with(self.base_url, session, disposable_id)
            mock_json.assert_not_called()
            self.assertEqual(session.metadata["file_ids"], ["ordinary-file"])
            self.assertEqual(session.metadata["disposable_file_ids"], [])
            self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_cleaned_up(run_id, disposable_id, "alice"))
        finally:
            _TRUSTED_SCAN_REGISTRY.clear()

    @patch.object(OpenWebUIAdapter, "delete_file")
    @patch.object(OpenWebUIAdapter, "get_file_metadata")
    @patch.object(OpenWebUIAdapter, "get_authenticated_user_id")
    def test_cleanup_does_not_delete_when_owner_reverification_fails(self, mock_auth, mock_meta, mock_delete):
        from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY

        _TRUSTED_SCAN_REGISTRY.clear()
        try:
            run_id = "adapter-cleanup-owner-failure"
            disposable_id = "scan-created-file"
            _TRUSTED_SCAN_REGISTRY.register(run_id, disposable_id, "alice")
            session = UserSession(
                username="alice", role="user", headers={"Authorization": "Bearer alice-token"},
                metadata={"run_id": run_id, "user_id": "alice-server-id", "file_ids": [disposable_id], "disposable_file_ids": [disposable_id]},
            )
            mock_auth.return_value = "alice-server-id"
            mock_meta.return_value = {"id": disposable_id, "user_id": "somebody-else"}

            self.adapter.cleanup(self.base_url, session)

            mock_delete.assert_not_called()
            self.assertEqual(session.metadata["disposable_file_ids"], [disposable_id])
            self.assertTrue(_TRUSTED_SCAN_REGISTRY.is_registered(run_id, disposable_id, "alice"))
        finally:
            _TRUSTED_SCAN_REGISTRY.clear()



if __name__ == "__main__":
    unittest.main()

