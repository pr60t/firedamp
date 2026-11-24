#!/usr/bin/env python3
"""
Tests for CVE-2026-28788 Lab Provisioning.
Verifies the 11 safety and contract requirements for Open WebUI user provisioning:
1. Initial administrator bootstrap succeeds.
2. Existing administrator signin succeeds when public signup is disabled.
3. Alice is created through the admin-only endpoint.
4. Bob is created through the admin-only endpoint.
5. Alice and Bob receive the user role.
6. A 403 from public signup does not prevent successful admin provisioning.
7. Invalid administrator credentials cause provisioning to fail safely.
8. Existing accounts are handled without duplicate creation.
9. Existing accounts with unexpected roles are rejected.
10. No password or token is printed in logs.
11. Both v0.8.5 and v0.8.6 use the same correct provisioning behavior.
12. Temporary setup JSON files have restrictive permissions (0600).
"""

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure setup_lab can be imported
lab_scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
if str(lab_scripts_dir) not in sys.path:
    sys.path.insert(0, str(lab_scripts_dir))

import setup_lab  # noqa: E402


class TestLabProvisioning(unittest.TestCase):

    def setUp(self):
        self.base_url = "http://127.0.0.1:13085"
        self.admin_email = "admin@lab.local"
        self.admin_pass = "AdminLabPass123!"
        self.alice_email = "alice@lab.local"
        self.alice_pass = "AliceLabPass123!"
        self.bob_email = "bob@lab.local"
        self.bob_pass = "BobLabPass123!"

    # 1. Initial administrator bootstrap succeeds
    @patch("setup_lab.http_request")
    def test_01_initial_admin_bootstrap_succeeds(self, mock_http):
        mock_http.side_effect = [
            # 1. POST /api/v1/auths/signup
            {"status_code": 200, "data": {"token": "admin-mock-token", "id": "admin-id-1", "role": "admin"}, "error": None},
            # 2. GET /api/v1/auths/ (verify_session)
            {"status_code": 200, "data": {"id": "admin-id-1", "email": self.admin_email, "name": "Admin", "role": "admin"}, "error": None},
        ]
        admin = setup_lab.bootstrap_admin(self.base_url, "Admin", self.admin_email, self.admin_pass)
        self.assertEqual(admin["user_id"], "admin-id-1")
        self.assertEqual(admin["role"], "admin")
        self.assertEqual(admin["email"], self.admin_email)
        self.assertEqual(admin["token"], "admin-mock-token")

    # 2. Existing administrator signin succeeds when public signup is disabled
    @patch("setup_lab.http_request")
    def test_02_existing_admin_signin_succeeds_when_signup_disabled(self, mock_http):
        mock_http.side_effect = [
            # 1. POST /api/v1/auths/signup returns 403 Forbidden
            {"status_code": 403, "data": {"detail": "Sign up is disabled."}, "error": "HTTP Error 403: Forbidden"},
            # 2. POST /api/v1/auths/signin returns 200
            {"status_code": 200, "data": {"token": "admin-mock-token", "id": "admin-id-1", "role": "admin"}, "error": None},
            # 3. GET /api/v1/auths/ verifies role admin
            {"status_code": 200, "data": {"id": "admin-id-1", "email": self.admin_email, "name": "Admin", "role": "admin"}, "error": None},
        ]
        admin = setup_lab.bootstrap_admin(self.base_url, "Admin", self.admin_email, self.admin_pass)
        self.assertEqual(admin["user_id"], "admin-id-1")
        self.assertEqual(admin["role"], "admin")

    # 3. Alice is created through the admin-only endpoint
    @patch("setup_lab.http_request")
    def test_03_alice_created_through_admin_only_endpoint(self, mock_http):
        recorded_calls = []

        def side_effect(url, method="GET", headers=None, data=None, timeout=15):
            call_info = {"url": url, "method": method, "headers": headers or {}}
            if data:
                try:
                    call_info["payload"] = json.loads(data.decode("utf-8"))
                except Exception:
                    call_info["payload"] = data
            recorded_calls.append(call_info)

            if "/api/v1/auths/add" in url:
                return {
                    "status_code": 200,
                    "data": {"id": "alice-id-1", "name": "Alice Victim", "email": self.alice_email, "role": "user", "token": "alice-mock-token"},
                    "error": None,
                }
            elif "/api/v1/auths/" in url:
                return {
                    "status_code": 200,
                    "data": {"id": "alice-id-1", "name": "Alice Victim", "email": self.alice_email, "role": "user"},
                    "error": None,
                }
            return {"status_code": 404, "data": None, "error": "Not Found"}

        mock_http.side_effect = side_effect
        alice = setup_lab.provision_user(self.base_url, "admin-mock-token", "Alice Victim", self.alice_email, self.alice_pass, role="user")

        # Verify endpoint invoked was POST /api/v1/auths/add with Bearer admin-mock-token
        add_calls = [c for c in recorded_calls if "/api/v1/auths/add" in c["url"]]
        self.assertEqual(len(add_calls), 1)
        self.assertEqual(add_calls[0]["method"], "POST")
        self.assertEqual(add_calls[0]["headers"].get("Authorization"), "Bearer admin-mock-token")
        self.assertEqual(add_calls[0]["payload"]["email"], self.alice_email)
        self.assertEqual(add_calls[0]["payload"]["role"], "user")
        self.assertEqual(alice["user_id"], "alice-id-1")
        self.assertEqual(alice["role"], "user")

    # 4. Bob is created through the admin-only endpoint
    @patch("setup_lab.http_request")
    def test_04_bob_created_through_admin_only_endpoint(self, mock_http):
        recorded_calls = []

        def side_effect(url, method="GET", headers=None, data=None, timeout=15):
            call_info = {"url": url, "method": method, "headers": headers or {}}
            if data:
                try:
                    call_info["payload"] = json.loads(data.decode("utf-8"))
                except Exception:
                    call_info["payload"] = data
            recorded_calls.append(call_info)

            if "/api/v1/auths/add" in url:
                return {
                    "status_code": 200,
                    "data": {"id": "bob-id-1", "name": "Bob Attacker", "email": self.bob_email, "role": "user", "token": "bob-mock-token"},
                    "error": None,
                }
            elif "/api/v1/auths/" in url:
                return {
                    "status_code": 200,
                    "data": {"id": "bob-id-1", "name": "Bob Attacker", "email": self.bob_email, "role": "user"},
                    "error": None,
                }
            return {"status_code": 404, "data": None, "error": "Not Found"}

        mock_http.side_effect = side_effect
        bob = setup_lab.provision_user(self.base_url, "admin-mock-token", "Bob Attacker", self.bob_email, self.bob_pass, role="user")

        add_calls = [c for c in recorded_calls if "/api/v1/auths/add" in c["url"]]
        self.assertEqual(len(add_calls), 1)
        self.assertEqual(add_calls[0]["headers"].get("Authorization"), "Bearer admin-mock-token")
        self.assertEqual(add_calls[0]["payload"]["email"], self.bob_email)
        self.assertEqual(add_calls[0]["payload"]["role"], "user")
        self.assertEqual(bob["user_id"], "bob-id-1")
        self.assertEqual(bob["role"], "user")

    # 5. Alice and Bob receive the user role
    @patch("setup_lab.http_request")
    def test_05_alice_and_bob_receive_user_role(self, mock_http):
        mock_http.side_effect = [
            # Alice add & verify
            {"status_code": 200, "data": {"id": "alice-id", "email": self.alice_email, "role": "user", "token": "alice-tok"}, "error": None},
            {"status_code": 200, "data": {"id": "alice-id", "email": self.alice_email, "name": "Alice", "role": "user"}, "error": None},
            # Bob add & verify
            {"status_code": 200, "data": {"id": "bob-id", "email": self.bob_email, "role": "user", "token": "bob-tok"}, "error": None},
            {"status_code": 200, "data": {"id": "bob-id", "email": self.bob_email, "name": "Bob", "role": "user"}, "error": None},
        ]
        alice = setup_lab.provision_user(self.base_url, "admin-token", "Alice", self.alice_email, self.alice_pass, role="user")
        bob = setup_lab.provision_user(self.base_url, "admin-token", "Bob", self.bob_email, self.bob_pass, role="user")
        self.assertEqual(alice["role"], "user")
        self.assertEqual(bob["role"], "user")

    # 6. A 403 from public signup does not prevent successful admin provisioning
    @patch("setup_lab.http_request")
    def test_06_signup_403_does_not_prevent_admin_provisioning(self, mock_http):
        mock_http.side_effect = [
            {"status_code": 403, "data": {"detail": "Sign up is disabled."}, "error": "HTTP Error 403: Forbidden"},
            {"status_code": 200, "data": {"token": "valid-admin-token", "id": "admin-uuid", "role": "admin"}, "error": None},
            {"status_code": 200, "data": {"id": "admin-uuid", "email": self.admin_email, "name": "Admin", "role": "admin"}, "error": None},
        ]
        admin = setup_lab.bootstrap_admin(self.base_url, "Admin", self.admin_email, self.admin_pass)
        self.assertEqual(admin["role"], "admin")
        self.assertEqual(admin["user_id"], "admin-uuid")

    # 7. Invalid administrator credentials cause provisioning to fail safely
    @patch("setup_lab.http_request")
    def test_07_invalid_admin_credentials_fail_safely(self, mock_http):
        mock_http.side_effect = [
            # Signup disabled
            {"status_code": 403, "data": {"detail": "Sign up is disabled."}, "error": "Forbidden"},
            # Signin fails with 400 invalid credentials
            {"status_code": 400, "data": {"detail": "Invalid email or password"}, "error": "Bad Request"},
        ]
        with self.assertRaises(RuntimeError) as ctx:
            setup_lab.bootstrap_admin(self.base_url, "Admin", self.admin_email, "WrongPassword")
        self.assertIn("Administrator bootstrap failed", str(ctx.exception))

    # 8. Existing accounts are handled without duplicate creation
    @patch("setup_lab.http_request")
    def test_08_existing_accounts_handled_without_duplicate_creation(self, mock_http):
        mock_http.side_effect = [
            # POST /api/v1/auths/add fails with 400 (email registered)
            {"status_code": 400, "data": {"detail": "Uh-oh! This email is already registered."}, "error": "Bad Request"},
            # POST /api/v1/auths/signin succeeds
            {"status_code": 200, "data": {"token": "alice-existing-token", "id": "alice-existing-id", "role": "user"}, "error": None},
            # GET /api/v1/auths/ confirms role user
            {"status_code": 200, "data": {"id": "alice-existing-id", "email": self.alice_email, "name": "Alice Victim", "role": "user"}, "error": None},
        ]
        user = setup_lab.provision_user(self.base_url, "admin-token", "Alice Victim", self.alice_email, self.alice_pass, role="user")
        self.assertEqual(user["user_id"], "alice-existing-id")
        self.assertEqual(user["role"], "user")

    # 9. Existing accounts with unexpected roles are rejected
    @patch("setup_lab.http_request")
    def test_09_existing_account_with_unexpected_role_rejected(self, mock_http):
        mock_http.side_effect = [
            # POST /api/v1/auths/add returns 400
            {"status_code": 400, "data": {"detail": "Email already exists"}, "error": "Bad Request"},
            # POST /api/v1/auths/signin succeeds
            {"status_code": 200, "data": {"token": "compromised-token", "id": "user-1", "role": "admin"}, "error": None},
            # GET /api/v1/auths/ reports role 'admin' instead of expected 'user'!
            {"status_code": 200, "data": {"id": "user-1", "email": self.alice_email, "name": "Alice", "role": "admin"}, "error": None},
        ]
        with self.assertRaises(RuntimeError) as ctx:
            setup_lab.provision_user(self.base_url, "admin-token", "Alice", self.alice_email, self.alice_pass, role="user")
        self.assertIn("role mismatch", str(ctx.exception).lower())

    # 10. No password or token is printed in logs
    @patch("setup_lab.http_request")
    def test_10_no_password_or_token_printed_in_logs(self, mock_http):
        mock_http.side_effect = [
            # 0. Verify pinned local target version before any admin operation
            {"status_code": 200, "data": {"version": "0.8.5"}, "error": None},
            # 1. Admin signup
            {"status_code": 200, "data": {"token": "SECRET_ADMIN_TOKEN_999", "id": "admin-1", "role": "admin"}, "error": None},
            # 2. Admin verify
            {"status_code": 200, "data": {"id": "admin-1", "email": self.admin_email, "name": "Admin", "role": "admin"}, "error": None},
            # 3. Default permissions GET
            {"status_code": 200, "data": {"workspace": {"knowledge": True}}, "error": None},
            # 4. Retrieval config GET
            {"status_code": 200, "data": {"BYPASS_EMBEDDING_AND_RETRIEVAL": True}, "error": None},
            # 5. Alice add
            {"status_code": 200, "data": {"token": "SECRET_ALICE_TOKEN_888", "id": "alice-1", "role": "user"}, "error": None},
            # 6. Alice verify
            {"status_code": 200, "data": {"id": "alice-1", "email": self.alice_email, "name": "Alice Victim", "role": "user"}, "error": None},
            # 7. Bob add
            {"status_code": 200, "data": {"token": "SECRET_BOB_TOKEN_777", "id": "bob-1", "role": "user"}, "error": None},
            # 8. Bob verify
            {"status_code": 200, "data": {"id": "bob-1", "email": self.bob_email, "name": "Bob Attacker", "role": "user"}, "error": None},
            # 9. Alice creates a uniquely named disposable KB (no existing KB is listed/reused)
            {"status_code": 200, "data": {"id": "kb-1", "name": "Alice Shared Knowledge - firedamp-unique"}, "error": None},
            # 10. Alice upload file
            {"status_code": 200, "data": {"id": "file-1", "filename": "alice_disposable.txt"}, "error": None},
            # 11. Link file to KB
            {"status_code": 200, "data": {"status": True}, "error": None},
            # 12. Grant read access
            {"status_code": 200, "data": {"status": True}, "error": None},
        ]

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        with patch("sys.stdout", stdout_capture), patch("sys.stderr", stderr_capture):
            setup_lab.setup_target(
                self.base_url,
                "owui-vulnerable",
                output_path=None,
                admin_password="SECRET_ADMIN_PASSWORD_XYZ",
                alice_password="SECRET_ALICE_PASSWORD_XYZ",
                bob_password="SECRET_BOB_PASSWORD_XYZ",
                custom_content="TEST FILE CONTENT",
            )

        captured_stdout = stdout_capture.getvalue()
        captured_stderr = stderr_capture.getvalue()
        combined_logs = captured_stdout + "\n" + captured_stderr

        # Assert no password appeared
        self.assertNotIn("SECRET_ADMIN_PASSWORD_XYZ", combined_logs)
        self.assertNotIn("SECRET_ALICE_PASSWORD_XYZ", combined_logs)
        self.assertNotIn("SECRET_BOB_PASSWORD_XYZ", combined_logs)

        # Assert no token appeared
        self.assertNotIn("SECRET_ADMIN_TOKEN_999", combined_logs)
        self.assertNotIn("SECRET_ALICE_TOKEN_888", combined_logs)
        self.assertNotIn("SECRET_BOB_TOKEN_777", combined_logs)

    # 11. Both v0.8.5 and v0.8.6 use the same correct provisioning behavior
    @patch("setup_lab.http_request")
    def test_11_both_v085_and_v086_same_provisioning_behavior(self, mock_http):
        for version_port, target_name in [(13085, "owui-vulnerable"), (13086, "owui-patched")]:
            recorded_endpoints = []

            def side_effect(url, method="GET", headers=None, data=None, timeout=15):
                auth_hdr = (headers or {}).get("Authorization", "")
                recorded_endpoints.append((method, url, auth_hdr))
                if "/api/version" in url:
                    return {"status_code": 200, "data": {"version": "0.8.5" if version_port == 13085 else "0.8.6"}, "error": None}
                if "/api/v1/auths/signup" in url:
                    return {"status_code": 403, "data": {"detail": "Disabled"}, "error": "Forbidden"}
                elif "/api/v1/auths/signin" in url:
                    return {"status_code": 200, "data": {"token": f"{target_name}-admin-token", "id": "admin-id", "role": "admin"}, "error": None}
                elif "/api/v1/users/default/permissions" in url:
                    return {"status_code": 200, "data": {"workspace": {"knowledge": True}}, "error": None}
                elif "/api/v1/retrieval/config" in url:
                    return {"status_code": 200, "data": {"BYPASS_EMBEDDING_AND_RETRIEVAL": True}, "error": None}
                elif "/api/v1/auths/add" in url:
                    user_tag = "bob" if (data and b"bob" in data.lower()) else "alice"
                    return {"status_code": 200, "data": {"token": f"{target_name}-{user_tag}-token", "id": f"{user_tag}-id", "role": "user"}, "error": None}
                elif "/api/v1/auths/" in url:
                    if "admin" in auth_hdr:
                        return {"status_code": 200, "data": {"id": "admin-id", "email": self.admin_email, "name": "Admin", "role": "admin"}, "error": None}
                    else:
                        is_bob = "bob" in auth_hdr
                        email = self.bob_email if is_bob else self.alice_email
                        user_id = "bob-id" if is_bob else "alice-id"
                        return {"status_code": 200, "data": {"id": user_id, "email": email, "name": "User", "role": "user"}, "error": None}
                elif "/api/v1/knowledge/" in url and method == "GET":
                    return {"status_code": 200, "data": {"items": []}, "error": None}
                elif "/api/v1/knowledge/create" in url:
                    return {"status_code": 200, "data": {"id": "kb-1", "name": "Alice Shared Knowledge"}, "error": None}
                elif "/api/v1/files/" in url:
                    return {"status_code": 200, "data": {"id": "file-1"}, "error": None}
                elif "/file/add" in url:
                    return {"status_code": 200, "data": {"status": True}, "error": None}
                elif "/access/update" in url:
                    return {"status_code": 200, "data": {"status": True}, "error": None}
                return {"status_code": 404, "data": None, "error": "Not Found"}

            mock_http.side_effect = side_effect
            setup = setup_lab.setup_target(
                f"http://127.0.0.1:{version_port}",
                target_name,
                custom_content="SAMPLE CONTENT",
            )
            # Verify admin route POST /api/v1/auths/add was called for both targets
            add_calls = [ep for ep in recorded_endpoints if ep[0] == "POST" and "/api/v1/auths/add" in ep[1]]
            self.assertEqual(len(add_calls), 2, f"Failed for {target_name}: expected 2 /api/v1/auths/add calls")
            self.assertEqual(setup["target_name"], target_name)
            self.assertNotEqual(setup["alice"]["user_id"], setup["bob"]["user_id"])
            self.assertNotEqual(setup["alice"]["token"], setup["bob"]["token"])

    @patch("setup_lab.create_disposable_knowledge_base")
    @patch("setup_lab.provision_user")
    @patch("setup_lab.ensure_lab_environment")
    @patch("setup_lab.bootstrap_admin")
    @patch("setup_lab.verify_target_version", return_value="0.8.5")
    def test_setup_rejects_same_server_identity_before_creating_disposable_resources(
        self, _mock_version, mock_admin, _mock_environment, mock_provision, mock_create_kb
    ):
        mock_admin.return_value = {"token": "admin-token", "user_id": "admin-id", "email": self.admin_email, "name": "Admin", "role": "admin"}
        mock_provision.side_effect = [
            {"token": "alice-token", "user_id": "shared-user-id", "email": self.alice_email, "name": "Alice", "role": "user"},
            {"token": "bob-token", "user_id": "shared-user-id", "email": self.bob_email, "name": "Bob", "role": "user"},
        ]

        with self.assertRaisesRegex(RuntimeError, "identical server identities or credentials"):
            setup_lab.setup_target(self.base_url, "owui-vulnerable", custom_content="fixture")

        mock_create_kb.assert_not_called()

    @patch("setup_lab.http_request")
    def test_disposable_kb_creation_never_lists_or_reuses_existing_kbs(self, mock_http):
        def create_response(url, method="GET", headers=None, data=None, timeout=15):
            payload = json.loads(data.decode("utf-8"))
            return {"status_code": 200, "data": {"id": f"new-kb-{mock_http.call_count}", **payload}, "error": None}
        mock_http.side_effect = create_response
        first = setup_lab.create_disposable_knowledge_base(
            self.base_url, "alice-token", "Alice Lab", "Disposable test KB"
        )
        second = setup_lab.create_disposable_knowledge_base(
            self.base_url, "alice-token", "Alice Lab", "Disposable test KB"
        )
        self.assertNotEqual(first["name"], second["name"])
        self.assertEqual(mock_http.call_count, 2)
        self.assertTrue(all(call.kwargs["method"] == "POST" for call in mock_http.call_args_list))
        self.assertTrue(all("/api/v1/knowledge/create" in call.args[0] for call in mock_http.call_args_list))


    # 12. Temporary setup JSON files have restrictive permissions (0600)
    def test_12_temporary_setup_json_permissions_0600(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "setup-test.json")
            sample_data = {"test": "data", "admin": {"user_id": "123"}}
            setup_lab.write_secure_json(sample_data, out_file)

            self.assertTrue(os.path.exists(out_file))
            file_stat = os.stat(out_file)
            file_mode = stat.S_IMODE(file_stat.st_mode)
            self.assertEqual(
                file_mode,
                0o600,
                f"Expected file mode 0600, got: {oct(file_mode)}",
            )
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, sample_data)


if __name__ == "__main__":
    unittest.main()
