"""
Unit tests for modular OpenWebUIAdapter mixins (Auth, Ingest, Query, Lifecycle).
"""

import unittest
from unittest.mock import MagicMock, patch

from adapters.base import UserSession
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
        self.assertIn("/api/v1/retrieval/query", args[0])

    @patch.object(OpenWebUIAdapter, "_json_request")
    def test_overwrite_resource_batch_process(self, mock_json):
        mock_json.return_value = {"status": True}
        res = self.adapter.overwrite_resource(
            self.base_url, self.bob, "file-12345", "poisoned content"
        )
        self.assertEqual(res, {"status": True})
        mock_json.assert_called_once()
        args, kwargs = mock_json.call_args
        self.assertIn("/api/v1/files/batch/process", args[0])

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


if __name__ == "__main__":
    unittest.main()

