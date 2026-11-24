"""Regression tests for strict CVE lab target and setup-file boundaries."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lab_safety import validate_setup_file, validate_target_url, verify_target_version, verify_setup_target


class TestLabSafety(unittest.TestCase):
    def test_loopback_targets_are_limited_to_pinned_ports_and_versions(self):
        self.assertEqual(validate_target_url("http://127.0.0.1:13085"), "0.8.5")
        self.assertEqual(validate_target_url("http://localhost:13086"), "0.8.6")
        with self.assertRaises(ValueError):
            validate_target_url("http://127.0.0.1:8080")
        with self.assertRaises(ValueError):
            validate_target_url("http://127.0.0.1:13085", expected_version="0.8.6")

    def test_non_loopback_requires_explicit_opt_in_and_version(self):
        with self.assertRaises(ValueError):
            validate_target_url("http://10.0.0.5:8080")
        with self.assertRaises(ValueError):
            validate_target_url("http://10.0.0.5:8080", allow_non_loopback=True)
        self.assertEqual(
            validate_target_url("http://10.0.0.5:8080", allow_non_loopback=True, expected_version="0.8.5"),
            "0.8.5",
        )

    def test_url_userinfo_query_fragment_and_path_are_rejected(self):
        for url in (
            "http://user:pass@127.0.0.1:13085",
            "http://127.0.0.1:13085/path",
            "http://127.0.0.1:13085/?x=1",
            "http://127.0.0.1:13085/#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_target_url(url)

    def test_version_endpoint_must_match_expected_pinned_version(self):
        request = lambda url, **kwargs: {"status_code": 200, "data": {"version": "0.8.5"}, "error": None}
        self.assertEqual(verify_target_version("http://127.0.0.1:13085", request), "0.8.5")
        wrong = lambda url, **kwargs: {"status_code": 200, "data": {"version": "0.8.6"}, "error": None}
        with self.assertRaises(RuntimeError):
            verify_target_version("http://127.0.0.1:13085", wrong)

    def test_setup_file_requires_identity_marker_and_restrictive_permissions(self):
        data = {
            "base_url": "http://127.0.0.1:13085",
            "lab_identity": {"name": "firedamp-cve-2026-28788", "schema_version": 1, "expected_version": "0.8.5"},
            "alice": {"token": "a-token", "user_id": "alice-id"},
            "bob": {"token": "b-token", "user_id": "bob-id"},
            "knowledge_base": {"id": "kb-id"},
            "disposable_file": {
                "id": "file-id", "filename": "alice_disposable.txt",
                "original_content_sha256": "a" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "setup.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(validate_setup_file(path)["lab_identity"]["expected_version"], "0.8.5")
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                validate_setup_file(path)
            os.chmod(path, 0o600)
            data.pop("lab_identity")
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                validate_setup_file(path)


    def test_setup_target_rejects_knowledge_base_not_owned_by_alice(self):
        setup = {
            "base_url": "http://127.0.0.1:13085",
            "lab_identity": {"expected_version": "0.8.5"},
            "alice": {"token": "alice-token", "user_id": "alice-id"},
            "bob": {"token": "bob-token", "user_id": "bob-id"},
            "knowledge_base": {"id": "kb-id"},
            "disposable_file": {"id": "file-id", "filename": "alice_disposable.txt", "original_content_sha256": "a" * 64},
        }
        responses = iter([
            {"status_code": 200, "data": {"version": "0.8.5"}, "error": None},
            {"status_code": 200, "data": {"id": "alice-id", "role": "user"}, "error": None},
            {"status_code": 200, "data": {"id": "bob-id", "role": "user"}, "error": None},
            {"status_code": 200, "data": {"id": "kb-id", "user_id": "other-owner"}, "error": None},
        ])
        with self.assertRaisesRegex(RuntimeError, "not authoritatively owned by Alice"):
            verify_setup_target(setup, lambda *args, **kwargs: next(responses))



if __name__ == "__main__":
    unittest.main()
