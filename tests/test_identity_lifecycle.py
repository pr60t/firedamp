"""
Unit and regression tests for test identity lifecycle, provisioning,
journaling, and post-release security controls.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from adapters.base import TargetAdapter, UserSession
from adapters.openwebui import OpenWebUIAdapter
from core.identity import (
    IdentityMode,
    IdentityJournal,
    IdentityManager,
    ProvisionedIdentityRecord,
    generate_secure_password,
    sanitize_run_id_for_filename,
)
from cli import run_scan_flow, cleanup_identities_flow, resolve_admin_credentials


class MockTargetAdapter(TargetAdapter):
    """Mock adapter for testing identity lifecycle orchestration."""
    target_name = "mock_adapter"

    def __init__(self):
        self.users: dict = {}
        self.deleted_users: list = []
        self.admin_valid: bool = True

    def authenticate_user(self, base_url: str, username: str, password: str, role: str = "user") -> UserSession:
        return UserSession(
            username=username,
            role=role,
            token=f"token-{username}",
            metadata={"user_id": f"uid-{username}", "file_ids": [], "knowledge_ids": []},
        )

    def validate_session(self, base_url: str, session: UserSession) -> bool:
        return bool(session and session.token)

    def get_authenticated_user_id(self, base_url: str, session: UserSession) -> str:
        if session and isinstance(session.metadata, dict):
            return session.metadata.get("user_id", f"uid-{session.username}")
        return f"uid-{session.username}"

    def check_admin_permissions(self, base_url: str, admin_token: str) -> bool:
        return self.admin_valid and bool(admin_token and "admin" in admin_token.lower())

    def provision_user(self, base_url: str, admin_token: str, username: str, password: str, role: str = "user") -> dict:
        if not self.check_admin_permissions(base_url, admin_token):
            raise PermissionError("Admin permissions denied")
        if role == "admin":
            raise ValueError("Cannot provision admin role")
        uid = f"srv-id-{username}"
        self.users[uid] = {"username": username, "role": role, "email": f"{username}@test.internal"}
        return {"user_id": uid, "username": username, "email": f"{username}@test.internal", "role": role}

    def delete_user(self, base_url: str, admin_token: str, user_id: str) -> bool:
        if not self.check_admin_permissions(base_url, admin_token):
            return False
        if user_id in self.users:
            del self.users[user_id]
        self.deleted_users.append(user_id)
        return True

    def verify_user_deleted(self, base_url: str, admin_token: str, user_id: str) -> bool:
        return user_id not in self.users

    def ingest_document(self, base_url: str, session: UserSession, document) -> str:
        return "doc-123"

    def query_rag(self, base_url: str, session: UserSession, prompt: str, files=None):
        return ("No leaks found", [], {})

    def query_resource_direct(self, base_url: str, session: UserSession, resource_ref: str, k: int = 50):
        return ("Access denied", [], {"code": 403})

    def overwrite_resource(self, base_url: str, session: UserSession, resource_ref: str, payload: str, collection_name=None, file_model=None):
        return {"error": "denied", "code": 403}

    def enumerate_resources(self, base_url: str, session: UserSession):
        return []

    def share_resource(self, base_url: str, owner: UserSession, resource_ref: str, grantee: UserSession):
        return {}

    def revoke_resource(self, base_url: str, owner: UserSession, resource_ref: str, grantee: UserSession):
        return {}

    def cleanup(self, base_url: str, session: UserSession) -> None:
        pass


class TestPasswordGenerator(unittest.TestCase):
    """Test cryptographic password generation properties."""

    def test_length_and_complexity(self):
        pwd = generate_secure_password(32)
        self.assertEqual(len(pwd), 32)
        self.assertTrue(any(c.isupper() for c in pwd), "Missing uppercase")
        self.assertTrue(any(c.islower() for c in pwd), "Missing lowercase")
        self.assertTrue(any(c.isdigit() for c in pwd), "Missing digit")
        self.assertTrue(any(c in "!@#$%^&*-_=+" for c in pwd), "Missing symbol")

    def test_minimum_length_enforcement(self):
        pwd = generate_secure_password(8)
        self.assertGreaterEqual(len(pwd), 16)

    def test_entropy_uniqueness(self):
        passwords = {generate_secure_password(32) for _ in range(50)}
        self.assertEqual(len(passwords), 50, "Generated duplicate passwords")


class TestIdentityJournal(unittest.TestCase):
    """Test identity journal file permissions, atomic writes, and data integrity."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="firedamp_journal_test_")
        self.journal = IdentityJournal(base_dir=Path(self.test_dir))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_directory_permissions(self):
        mode = os.stat(self.test_dir).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o700)

    def test_atomic_write_and_file_permissions(self):
        records = [
            ProvisionedIdentityRecord(
                username="alice_test",
                role="user",
                user_id="uid-alice-123",
                email="alice@test.internal",
            ),
            ProvisionedIdentityRecord(
                username="bob_test",
                role="user",
                user_id="uid-bob-456",
                email="bob@test.internal",
            ),
        ]
        path = self.journal.write_journal(
            run_id="scan-test-1",
            target_url="https://target.local:8080",
            target_adapter="openwebui",
            identities=records,
            status="provisioned",
        )
        self.assertTrue(path.exists())
        mode = os.stat(path).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

        # Confirm content contains no secrets
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("password", content.lower())
        self.assertNotIn("token", content.lower())

        data = json.loads(content)
        self.assertEqual(data["run_id"], "scan-test-1")
        self.assertEqual(data["status"], "provisioned")
        self.assertEqual(len(data["identities"]), 2)
        self.assertEqual(data["identities"][0]["user_id"], "uid-alice-123")

    def test_update_status(self):
        records = [
            ProvisionedIdentityRecord(username="u1", role="user", user_id="id-1")
        ]
        self.journal.write_journal("run-status-test", "https://t", "openwebui", records)
        ok = self.journal.update_status("run-status-test", "cleaned")
        self.assertTrue(ok)
        entry = self.journal.read_journal("run-status-test")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["status"], "cleaned")

    def test_list_journals(self):
        self.journal.write_journal("run-a", "https://t", "openwebui", [])
        self.journal.write_journal("run-b", "https://t", "openwebui", [])
        journals = self.journal.list_journals()
        run_ids = {j["run_id"] for j in journals}
        self.assertIn("run-a", run_ids)
        self.assertIn("run-b", run_ids)


class TestIdentityManagerValidation(unittest.TestCase):
    """Test validation of operator-supplied existing identities."""

    def setUp(self):
        self.adapter = MockTargetAdapter()

    def test_valid_existing_identities(self):
        alice = UserSession("alice", "owner", token="tok-alice", metadata={"user_id": "uid-alice"})
        bob = UserSession("bob", "attacker", token="tok-bob", metadata={"user_id": "uid-bob"})
        valid, err = IdentityManager.validate_existing_identities(
            self.adapter, "https://t", alice, bob
        )
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_shared_token_rejected(self):
        alice = UserSession("alice", "owner", token="shared-token", metadata={"user_id": "uid-alice"})
        bob = UserSession("bob", "attacker", token="shared-token", metadata={"user_id": "uid-bob"})
        valid, err = IdentityManager.validate_existing_identities(
            self.adapter, "https://t", alice, bob
        )
        self.assertFalse(valid)
        self.assertIn("must not share the same authentication token", err)

    def test_same_server_id_rejected(self):
        alice = UserSession("alice", "owner", token="tok-alice", metadata={"user_id": "common-user-id"})
        bob = UserSession("bob", "attacker", token="tok-bob", metadata={"user_id": "common-user-id"})
        valid, err = IdentityManager.validate_existing_identities(
            self.adapter, "https://t", alice, bob
        )
        self.assertFalse(valid)
        self.assertIn("same server-side user ID", err)

    def test_missing_token_rejected(self):
        alice = UserSession("alice", "owner", token="", metadata={"user_id": "uid-alice"})
        bob = UserSession("bob", "attacker", token="tok-bob", metadata={"user_id": "uid-bob"})
        valid, err = IdentityManager.validate_existing_identities(
            self.adapter, "https://t", alice, bob
        )
        self.assertFalse(valid)
        self.assertIn("lacks an authentication token", err)


class TestIdentityManagerProvisioning(unittest.TestCase):
    """Test provisioning and cleanup lifecycle."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="firedamp_mgr_test_")
        self.journal = IdentityJournal(base_dir=Path(self.test_dir))
        self.manager = IdentityManager(journal=self.journal)
        self.adapter = MockTargetAdapter()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_provision_identities_success(self):
        alice, bob, records = self.manager.provision_identities(
            adapter=self.adapter,
            base_url="https://t",
            admin_token="valid-admin-token",
            run_id="run-prov-1",
        )
        self.assertEqual(alice.role, "owner")
        self.assertEqual(bob.role, "attacker")
        self.assertIn("firedamp_alice_", alice.username)
        self.assertIn("firedamp_bob_", bob.username)
        self.assertTrue(alice.metadata.get("provisioned_by_firedamp"))
        self.assertTrue(bob.metadata.get("provisioned_by_firedamp"))
        self.assertNotEqual(alice.metadata["user_id"], bob.metadata["user_id"])

        # Check journal entry
        entry = self.journal.read_journal("run-prov-1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["status"], "provisioned")
        self.assertEqual(len(entry["identities"]), 2)

    def test_provision_preflight_admin_check_fails(self):
        self.adapter.admin_valid = False
        with self.assertRaises(PermissionError):
            self.manager.provision_identities(
                adapter=self.adapter,
                base_url="https://t",
                admin_token="invalid-admin-token",
                run_id="run-prov-fail",
            )

    def test_ordered_cleanup_deletes_bob_then_alice(self):
        alice, bob, records = self.manager.provision_identities(
            adapter=self.adapter,
            base_url="https://t",
            admin_token="valid-admin-token",
            run_id="run-prov-clean",
        )
        bob_uid = bob.metadata["user_id"]
        alice_uid = alice.metadata["user_id"]
        self.assertIn(bob_uid, self.adapter.users)
        self.assertIn(alice_uid, self.adapter.users)

        success, failures = self.manager.cleanup_provisioned_identities(
            adapter=self.adapter,
            base_url="https://t",
            admin_token="valid-admin-token",
            run_id="run-prov-clean",
            records=records,
        )
        self.assertTrue(success)
        self.assertEqual(failures, [])
        self.assertNotIn(bob_uid, self.adapter.users)
        self.assertNotIn(alice_uid, self.adapter.users)

        # Verify Bob was deleted first
        self.assertEqual(self.adapter.deleted_users, [bob_uid, alice_uid])

        # Verify journal status updated
        entry = self.journal.read_journal("run-prov-clean")
        self.assertEqual(entry["status"], "cleaned")

    def test_interrupted_run_recovery(self):
        # Manually create a journal record as if scan was interrupted before cleanup
        records = [
            ProvisionedIdentityRecord("firedamp_bob_rec", "user", "srv-id-bob-rec"),
            ProvisionedIdentityRecord("firedamp_alice_rec", "user", "srv-id-alice-rec"),
        ]
        self.adapter.users["srv-id-bob-rec"] = {"username": "bob"}
        self.adapter.users["srv-id-alice-rec"] = {"username": "alice"}

        self.journal.write_journal(
            run_id="run-interrupted",
            target_url="https://127.0.0.1:8080",
            target_adapter="mock_adapter",
            identities=records,
            status="provisioned",
        )

        with patch("adapters.get_adapter", return_value=self.adapter):
            success, msg = self.manager.recover_and_cleanup_run(
                run_id="run-interrupted",
                admin_token="valid-admin-token",
            )
        self.assertTrue(success)
        self.assertNotIn("srv-id-bob-rec", self.adapter.users)
        self.assertNotIn("srv-id-alice-rec", self.adapter.users)
        entry = self.journal.read_journal("run-interrupted")
        self.assertEqual(entry["status"], "cleaned")


class TestOpenWebUIUserManagementMixin(unittest.TestCase):
    """Test Open WebUI user management mixin methods and error handling."""

    def setUp(self):
        self.adapter = OpenWebUIAdapter()

    def test_check_admin_permissions_success(self):
        with patch.object(self.adapter, "_json_request", return_value=[{"id": "usr-1", "name": "Admin"}]):
            self.assertTrue(self.adapter.check_admin_permissions("https://target", "admin-token"))

    def test_check_admin_permissions_unauthorized(self):
        with patch.object(self.adapter, "_json_request", return_value={"error": "Unauthorized", "code": 401}):
            self.assertFalse(self.adapter.check_admin_permissions("https://target", "bad-token"))

    def test_provision_user_refuses_admin_role(self):
        with self.assertRaises(ValueError):
            self.adapter.provision_user("https://t", "adm-tok", "hacker", "pass", role="admin")

    def test_provision_user_success(self):
        with patch.object(self.adapter, "_json_request", return_value={"id": "usr-new-123"}):
            res = self.adapter.provision_user("https://t", "adm-tok", "alice_test", "StrongPass123!@#")
            self.assertEqual(res["user_id"], "usr-new-123")
            self.assertEqual(res["username"], "alice_test")

    def test_delete_user_success(self):
        with patch.object(self.adapter, "_json_request", return_value={"message": "User deleted successfully"}):
            self.assertTrue(self.adapter.delete_user("https://t", "adm-tok", "usr-to-del"))

    def test_verify_user_deleted_returns_true_on_404(self):
        with patch.object(self.adapter, "_json_request", return_value={"error": "Not found", "code": 404}):
            self.assertTrue(self.adapter.verify_user_deleted("https://t", "adm-tok", "usr-deleted"))

    def test_verify_user_deleted_returns_false_if_still_exists(self):
        with patch.object(self.adapter, "_json_request", return_value={"id": "usr-still-here"}):
            self.assertFalse(self.adapter.verify_user_deleted("https://t", "adm-tok", "usr-still-here"))


class TestCLISmokeAndOptions(unittest.TestCase):
    """Test CLI behavior for identity modes, dry-run, and cleanup commands."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="firedamp_cli_test_")
        self.orig_env = os.environ.get("FIREDAMP_JOURNAL_DIR")
        os.environ["FIREDAMP_JOURNAL_DIR"] = self.test_dir

    def tearDown(self):
        if self.orig_env is not None:
            os.environ["FIREDAMP_JOURNAL_DIR"] = self.orig_env
        else:
            os.environ.pop("FIREDAMP_JOURNAL_DIR", None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_provisioning_without_confirmation_fails(self):
        exit_code = run_scan_flow(
            dry_run=True,
            identity_mode="provision",
            confirm_provisioning=False,
        )
        self.assertEqual(exit_code, 1)

    def test_provisioning_with_confirmation_dry_run_succeeds(self):
        exit_code = run_scan_flow(
            dry_run=True,
            identity_mode="provision",
            confirm_provisioning=True,
            canaries=1,
            suite="default",
        )
        self.assertEqual(exit_code, 0)

    def test_existing_mode_dry_run_succeeds(self):
        exit_code = run_scan_flow(
            dry_run=True,
            identity_mode="existing",
            canaries=1,
            suite="default",
        )
        self.assertEqual(exit_code, 0)

    def test_invalid_identity_mode_fails(self):
        exit_code = run_scan_flow(
            dry_run=True,
            identity_mode="invalid_mode",
        )
        self.assertEqual(exit_code, 1)

    def test_cleanup_identities_flow_missing_journal(self):
        exit_code = cleanup_identities_flow(run_id="nonexistent-run-id-99999")
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
