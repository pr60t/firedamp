#!/usr/bin/env python3
"""
CVE-2026-28788 Lab Setup Script.
Configures Admin, Alice (victim), Bob (attacker), shared KB, and disposable target file
on an Open WebUI instance (v0.8.5 or v0.8.6).

Enforces:
- Administrator bootstrap (signup -> signin fallback when public signup is disabled)
- Independent verification of administrator identity and role 'admin'
- User provisioning via administrator endpoint POST /api/v1/auths/add with explicit role 'user'
- Idempotent existing account authentication with strict role verification
- Restrictive filesystem permissions (0600) on setup output
- Strict credential redaction (no passwords or tokens printed in stdout/stderr)
"""

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

from lab_safety import LAB_NAME, LAB_SCHEMA_VERSION, verify_target_version, validate_target_url


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            status_code = resp.status
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {"raw": body}
            return {"status_code": status_code, "data": parsed, "error": None}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return {"status_code": e.code, "data": parsed, "error": str(e)}
    except Exception as e:
        return {"status_code": 0, "data": None, "error": str(e)}


def wait_for_health(base_url: str, max_retries: int = 30, interval: int = 2) -> bool:
    print(f"Waiting for Open WebUI at {base_url}/health to be ready...")
    for i in range(max_retries):
        res = http_request(f"{base_url}/health")
        if res["status_code"] == 200:
            print(f"  ✓ Open WebUI healthy after {i+1} checks.")
            return True
        time.sleep(interval)
    print(f"  ✗ Open WebUI failed to become healthy at {base_url}")
    return False


def verify_session(
    base_url: str,
    token: str,
    expected_role: Optional[str] = None,
    expected_email: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Independently verifies session identity and role via GET /api/v1/auths/.
    Fails closed if token is invalid or role/identity mismatches.
    """
    res = http_request(
        f"{base_url}/api/v1/auths/",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
    )
    if res["status_code"] != 200 or not isinstance(res["data"], dict):
        raise RuntimeError(
            f"Failed to verify session identity: HTTP {res['status_code']}"
        )

    user_id = res["data"].get("id")
    email = res["data"].get("email")
    name = res["data"].get("name")
    role = res["data"].get("role")

    if not user_id or not isinstance(user_id, str):
        raise RuntimeError("Session verification failed: invalid or missing user ID in response")

    if expected_role is not None and role != expected_role:
        raise RuntimeError(
            f"Session verification failed: role mismatch (expected '{expected_role}', got '{role}')"
        )

    if expected_email is not None and email.lower() != expected_email.lower():
        raise RuntimeError(
            f"Session verification failed: email mismatch (expected '{expected_email}', got '{email}')"
        )

    return {
        "user_id": str(user_id),
        "email": str(email),
        "name": str(name or ""),
        "role": str(role or ""),
    }


def bootstrap_admin(
    base_url: str, name: str, email: str, password: str
) -> Dict[str, Any]:
    """
    Bootstraps the administrator account.
    1. Attempts signup as the initial bootstrap.
    2. If signup is disabled (HTTP 403) or account already exists (HTTP 400),
       falls back to signin.
    3. Independently verifies that the resulting identity has role 'admin'.
    """
    print(f"Bootstrapping administrator '{name}' ({email})...")

    # 1. Attempt admin signup
    signup_payload = json.dumps({
        "name": name,
        "email": email,
        "password": password,
    }).encode("utf-8")
    signup_res = http_request(
        f"{base_url}/api/v1/auths/signup",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=signup_payload,
    )

    token: Optional[str] = None
    if signup_res["status_code"] == 200 and isinstance(signup_res["data"], dict):
        token = signup_res["data"].get("token")

    if not token:
        # 2. Signup failed or disabled, fall back to signin
        signin_payload = json.dumps({"email": email, "password": password}).encode("utf-8")
        signin_res = http_request(
            f"{base_url}/api/v1/auths/signin",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=signin_payload,
        )
        if signin_res["status_code"] == 200 and isinstance(signin_res["data"], dict):
            token = signin_res["data"].get("token")
        else:
            raise RuntimeError(
                f"Administrator bootstrap failed: signup returned {signup_res['status_code']} "
                f"and signin returned {signin_res['status_code']}. Inaccessible or invalid credentials."
            )

    if not token or not isinstance(token, str):
        raise RuntimeError("Administrator bootstrap failed: missing bearer token")

    # 3. Independently verify administrator identity and role
    verified = verify_session(base_url, token, expected_role="admin", expected_email=email)
    print(f"  ✓ Administrator authenticated and verified (ID: {verified['user_id']}, Role: {verified['role']})")

    return {
        "token": token,
        "user_id": verified["user_id"],
        "email": verified["email"],
        "name": verified["name"],
        "role": verified["role"],
    }


def ensure_lab_environment(base_url: str, admin_token: str) -> None:
    """
    Ensures standard users have permission to create knowledge bases
    and ensures embedding bypass is active when running in headless lab without models.
    """
    # 1. Enable workspace.knowledge permissions for standard users
    perms_res = http_request(
        f"{base_url}/api/v1/users/default/permissions",
        method="GET",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if perms_res["status_code"] == 200 and isinstance(perms_res["data"], dict):
        perms = perms_res["data"]
        workspace = perms.get("workspace", {})
        if not workspace.get("knowledge"):
            workspace["knowledge"] = True
            perms["workspace"] = workspace
            http_request(
                f"{base_url}/api/v1/users/default/permissions",
                method="POST",
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
                data=json.dumps(perms).encode("utf-8"),
            )
            print("  ✓ Enabled user workspace knowledge permissions via administrator.")

    # 2. Enable BYPASS_EMBEDDING_AND_RETRIEVAL for lab file processing
    cfg_res = http_request(
        f"{base_url}/api/v1/retrieval/config",
        method="GET",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if cfg_res["status_code"] == 200 and isinstance(cfg_res["data"], dict):
        cfg = cfg_res["data"]
        if not cfg.get("BYPASS_EMBEDDING_AND_RETRIEVAL"):
            cfg["BYPASS_EMBEDDING_AND_RETRIEVAL"] = True
            http_request(
                f"{base_url}/api/v1/retrieval/config/update",
                method="POST",
                headers={
                    "Authorization": f"Bearer {admin_token}",
                    "Content-Type": "application/json",
                },
                data=json.dumps(cfg).encode("utf-8"),
            )
            print("  ✓ Configured BYPASS_EMBEDDING_AND_RETRIEVAL for headless lab.")


def provision_user(
    base_url: str,
    admin_token: str,
    name: str,
    email: str,
    password: str,
    role: str = "user",
) -> Dict[str, Any]:
    """
    Provisions a non-admin user (Alice or Bob).
    1. Calls admin-only endpoint POST /api/v1/auths/add.
    2. Explicitly specifies role 'user'.
    3. If user already exists (HTTP 400), authenticates via signin.
    4. Independently verifies identity and role 'user' via GET /api/v1/auths/.
    5. Fails closed if unexpected role is encountered (e.g. if accidentally admin).
    """
    if role != "user":
        raise ValueError(f"provision_user strictly requires role 'user', got: {role}")

    print(f"Provisioning user '{name}' ({email}) with role '{role}'...")

    # Attempt creation via administrator route
    add_payload = json.dumps({
        "name": name,
        "email": email,
        "password": password,
        "role": role,
        "profile_image_url": "/user.png",
    }).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }
    add_res = http_request(
        f"{base_url}/api/v1/auths/add",
        method="POST",
        headers=headers,
        data=add_payload,
    )

    user_token: Optional[str] = None
    if add_res["status_code"] == 200 and isinstance(add_res["data"], dict):
        user_token = add_res["data"].get("token")

    if not user_token:
        # If add returned 400 (already exists) or did not supply token, authenticate via signin
        if add_res["status_code"] in (401, 403):
            raise RuntimeError(
                f"Administrator token unauthorized to create user {email}: HTTP {add_res['status_code']}"
            )

        signin_payload = json.dumps({"email": email, "password": password}).encode("utf-8")
        signin_res = http_request(
            f"{base_url}/api/v1/auths/signin",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=signin_payload,
        )
        if signin_res["status_code"] == 200 and isinstance(signin_res["data"], dict):
            user_token = signin_res["data"].get("token")
        else:
            raise RuntimeError(
                f"Failed to authenticate user {email}: add returned {add_res['status_code']}, "
                f"signin returned {signin_res['status_code']}"
            )

    if not user_token or not isinstance(user_token, str):
        raise RuntimeError(f"Failed to obtain bearer token for user {email}")

    # Independently verify session identity and role 'user'
    verified = verify_session(base_url, user_token, expected_role=role, expected_email=email)
    print(f"  ✓ User '{name}' authenticated and verified (ID: {verified['user_id']}, Role: {verified['role']})")

    return {
        "token": user_token,
        "user_id": verified["user_id"],
        "email": verified["email"],
        "name": verified["name"],
        "role": verified["role"],
    }


def create_disposable_knowledge_base(
    base_url: str, token: str, name: str, description: str
) -> Dict[str, Any]:
    """Create a uniquely named KB for this lab run; never reuse user data."""
    disposable_name = f"{name} - firedamp-{uuid.uuid4().hex[:12]}"
    print(f"Creating isolated disposable knowledge base '{disposable_name}'...")
    payload = json.dumps({"name": disposable_name, "description": description}).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    res = http_request(
        f"{base_url}/api/v1/knowledge/create",
        method="POST",
        headers=headers,
        data=payload,
    )
    if res["status_code"] == 200 and isinstance(res["data"], dict):
        kb_id = res["data"].get("id")
        if not isinstance(kb_id, str) or not kb_id.strip():
            raise RuntimeError("Knowledge-base creation returned no valid ID")
        print(f"  ✓ Disposable KB created successfully (ID: {kb_id})")
        return res["data"]
    raise RuntimeError(f"Failed to create KB: HTTP {res['status_code']}")


def upload_disposable_file(
    base_url: str, token: str, filename: str, content: str
) -> Dict[str, Any]:
    print(f"Uploading disposable file '{filename}'...")
    boundary = "----FiredampLabBoundary" + hex(int(time.time() * 1000))[2:]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    res = http_request(f"{base_url}/api/v1/files/", method="POST", headers=headers, data=body)
    if res["status_code"] == 200 and isinstance(res["data"], dict):
        file_id = res["data"].get("id")
        print(f"  ✓ File uploaded successfully (File ID: {file_id})")
        return res["data"]
    raise RuntimeError(f"Failed to upload file: HTTP {res['status_code']}")


def add_file_to_knowledge_base(
    base_url: str, token: str, kb_id: str, file_id: str
) -> None:
    print(f"Linking file {file_id} to KB {kb_id}...")
    payload = json.dumps({"file_id": file_id}).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    res = http_request(
        f"{base_url}/api/v1/knowledge/{kb_id}/file/add",
        method="POST",
        headers=headers,
        data=payload,
    )
    if res["status_code"] != 200:
        raise RuntimeError(f"Failed to add file to KB: HTTP {res['status_code']}")
    print(f"  ✓ File linked to KB.")


def grant_kb_read_access(
    base_url: str, token: str, kb_id: str, reader_user_id: str
) -> None:
    print(f"Granting user {reader_user_id} read access to KB {kb_id}...")
    payload = json.dumps({
        "access_grants": [
            {
                "principal_type": "user",
                "principal_id": reader_user_id,
                "permission": "read",
            }
        ]
    }).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    res = http_request(
        f"{base_url}/api/v1/knowledge/{kb_id}/access/update",
        method="POST",
        headers=headers,
        data=payload,
    )
    if res["status_code"] != 200:
        raise RuntimeError(f"Failed to update KB access: HTTP {res['status_code']}")
    print(f"  ✓ Read access granted to {reader_user_id}.")


def write_secure_json(data: Dict[str, Any], output_path: str) -> None:
    """
    Writes JSON data to file with strict filesystem permissions (0600).
    Uses os.open to avoid race condition where file is briefly world-readable.
    """
    out_path = Path(output_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, indent=2)

    fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(serialized)
    os.chmod(str(out_path), 0o600)


def setup_target(
    url: str,
    target_name: str,
    output_path: Optional[str] = None,
    admin_name: str = "Admin",
    admin_email: str = "admin@lab.local",
    admin_password: str = "AdminLabPass123!",
    alice_name: str = "Alice Victim",
    alice_email: str = "alice@lab.local",
    alice_password: str = "AliceLabPass123!",
    bob_name: str = "Bob Attacker",
    bob_email: str = "bob@lab.local",
    bob_password: str = "BobLabPass123!",
    custom_content: Optional[str] = None,
    allow_non_loopback: bool = False,
    expected_version: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Full target setup pipeline.
    """
    verified_version = verify_target_version(
        url,
        http_request,
        allow_non_loopback=allow_non_loopback,
        expected_version=expected_version,
    )
    script_dir = Path(__file__).resolve().parent
    lab_dir = script_dir.parent
    fixtures_dir = lab_dir / "fixtures"

    if custom_content is not None:
        alice_content = custom_content
    else:
        alice_content_path = fixtures_dir / "alice_original.txt"
        if not alice_content_path.exists():
            alice_content = "CONFIDENTIAL TENANT DATA - ALICE DISPOSABLE LAB FILE"
        else:
            alice_content = alice_content_path.read_text(encoding="utf-8")

    # 1. Admin setup & verification
    admin = bootstrap_admin(url, admin_name, admin_email, admin_password)

    # 2. Configure environment permissions via admin
    ensure_lab_environment(url, admin["token"])

    # 3. Alice setup & verification (victim) via admin endpoint
    alice = provision_user(
        url, admin["token"], alice_name, alice_email, alice_password, role="user"
    )

    # 4. Bob setup & verification (attacker) via admin endpoint
    bob = provision_user(
        url, admin["token"], bob_name, bob_email, bob_password, role="user"
    )

    # Refuse to create any disposable resources unless the two personas resolve
    # to distinct server-side identities and credentials. The later preflight
    # repeats this validation before destructive probes, but setup must not claim
    # success or create a fixture for a collapsed Alice/Bob identity.
    if alice["user_id"] == bob["user_id"] or alice["token"] == bob["token"]:
        raise RuntimeError(
            "Alice and Bob provisioning returned identical server identities or credentials; "
            "refusing to create disposable lab resources"
        )

    # 5. Alice creates or retrieves KB
    kb = create_disposable_knowledge_base(
        url, alice["token"], "Alice Shared Knowledge", "CVE-2026-28788 disposable lab KB"
    )

    # 6. Alice uploads disposable file
    file_info = upload_disposable_file(
        url, alice["token"], "alice_disposable.txt", alice_content
    )
    file_id = file_info["id"]

    # 7. Alice adds file to KB
    add_file_to_knowledge_base(url, alice["token"], kb["id"], file_id)

    # 8. Alice grants Bob read access
    grant_kb_read_access(url, alice["token"], kb["id"], bob["user_id"])

    setup_data = {
        "target_name": target_name,
        "base_url": url,
        "lab_identity": {"name": LAB_NAME, "schema_version": LAB_SCHEMA_VERSION, "expected_version": verified_version},
        "admin": {
            "user_id": admin["user_id"],
            "email": admin["email"],
            "name": admin["name"],
            "role": admin["role"],
        },
        "alice": {
            "user_id": alice["user_id"],
            "email": alice["email"],
            "name": alice["name"],
            "role": alice["role"],
            "token": alice["token"],
        },
        "bob": {
            "user_id": bob["user_id"],
            "email": bob["email"],
            "name": bob["name"],
            "role": bob["role"],
            "token": bob["token"],
        },
        "knowledge_base": {"id": kb["id"], "name": kb["name"]},
        "disposable_file": {
            "id": file_id,
            "filename": "alice_disposable.txt",
            "original_content_length": len(alice_content),
            "original_content_sha256": hashlib.sha256(alice_content.encode("utf-8")).hexdigest(),
        },
    }

    # Redacted summary for stdout (no credentials/tokens printed)
    summary_data = {
        "target_name": setup_data["target_name"],
        "base_url": setup_data["base_url"],
        "lab_identity": setup_data["lab_identity"],
        "admin": setup_data["admin"],
        "alice": {
            "user_id": alice["user_id"],
            "email": alice["email"],
            "name": alice["name"],
            "role": alice["role"],
        },
        "bob": {
            "user_id": bob["user_id"],
            "email": bob["email"],
            "name": bob["name"],
            "role": bob["role"],
        },
        "knowledge_base": setup_data["knowledge_base"],
        "disposable_file": setup_data["disposable_file"],
    }

    print("\n✓ Lab setup complete!")
    print(json.dumps(summary_data, indent=2))

    if output_path:
        write_secure_json(setup_data, output_path)
        print(f"Setup state written securely to: {output_path} (mode: 0600)")

    return setup_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Setup CVE-2026-28788 Lab Environment")
    parser.add_argument("--url", default="http://127.0.0.1:13085", help="Target Open WebUI base URL")
    parser.add_argument("--target-name", default="owui-vulnerable", help="Target label (e.g. owui-vulnerable)")
    parser.add_argument("--output", default=None, help="Output JSON path")
    parser.add_argument(
        "--allow-non-loopback", action="store_true",
        help="DANGEROUS: explicitly permit setup against a non-loopback target",
    )
    parser.add_argument(
        "--expected-version", choices=("0.8.5", "0.8.6"), default=None,
        help="Required when --allow-non-loopback is used",
    )
    args = parser.parse_args()

    try:
        validate_target_url(args.url, allow_non_loopback=args.allow_non_loopback, expected_version=args.expected_version)
    except Exception as exc:
        parser.error(str(exc))
    if args.allow_non_loopback:
        print("\n!!! DESTRUCTIVE LAB SETUP ON A NON-LOOPBACK TARGET ENABLED !!!", file=sys.stderr)
        print("Only continue against an explicitly authorized disposable instance.\n", file=sys.stderr)

    if not wait_for_health(args.url):
        sys.exit(1)

    try:
        setup_target(args.url, args.target_name, args.output, allow_non_loopback=args.allow_non_loopback, expected_version=args.expected_version)
    except Exception as e:
        print(f"\n✗ Setup failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
