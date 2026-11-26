"""
Open WebUI User Management Mixin.
Handles administrative user provisioning, deletion, and lifecycle checks.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional, List

from core.engine import sanitize_sensitive_text

logger = logging.getLogger("firedamp.adapters.openwebui.user_mgmt")


class OpenWebUIUserManagementMixin:
    """Administrative user management methods for Open WebUI."""

    def check_admin_permissions(self, base_url: str, admin_token: str) -> bool:
        """
        Verify that admin_token has administrative access on Open WebUI.
        Calls GET /api/v1/users/ with the Bearer token.
        Returns True ONLY if server responds with a list of users or role="admin" from GET /api/v1/auths/.
        Fails closed on 401/403 or errors.
        """
        if not admin_token or not admin_token.strip():
            return False

        base = base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {admin_token.strip()}"}

        try:
            # 1. Primary check: GET /api/v1/users/ (admin-only endpoint)
            res = self._json_request(f"{base}/api/v1/users/", method="GET", headers=headers)
            if isinstance(res, list):
                return True
            if isinstance(res, dict) and isinstance(res.get("data"), list):
                return True

            # 2. Secondary check: GET /api/v1/auths/ returning role=="admin"
            auth_res = self._json_request(f"{base}/api/v1/auths/", method="GET", headers=headers)
            if isinstance(auth_res, dict) and auth_res.get("role") == "admin":
                return True

            return False
        except Exception as exc:
            logger.debug(f"Admin permission check failed: {sanitize_sensitive_text(exc)}")
            return False

    def provision_user(
        self,
        base_url: str,
        admin_token: str,
        username: str,
        password: str,
        role: str = "user",
    ) -> Dict[str, Any]:
        """
        Provision a test user persona with standard user role using admin credentials.
        Refuses to provision admin-privileged accounts.
        Calls POST /api/v1/users/create (or fallback POST /api/v1/auths/admin/users/create).
        Returns dict with {"user_id": str, "username": str, "email": str, "role": str}.
        """
        if not username or not username.strip():
            raise ValueError("Provisioning requires a non-empty username.")
        if not password or not password.strip():
            raise ValueError("Provisioning requires a non-empty password.")
        if role.lower() == "admin":
            raise ValueError("Refusing to provision test persona with 'admin' role.")

        base = base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {admin_token.strip()}"}
        email = f"{username.strip().lower()}@firedamp-audit.internal"

        payload = {
            "name": username.strip().capitalize(),
            "email": email,
            "password": password.strip(),
            "role": role.strip(),
        }

        # Try POST /api/v1/users/create
        res = self._json_request(
            f"{base}/api/v1/users/create",
            method="POST",
            data=payload,
            headers=headers,
        )

        # Fallback to POST /api/v1/auths/admin/users/create if 404 or unsupported
        if isinstance(res, dict) and (res.get("code") == 404 or "error" in res):
            res_fallback = self._json_request(
                f"{base}/api/v1/auths/admin/users/create",
                method="POST",
                data=payload,
                headers=headers,
            )
            if isinstance(res_fallback, dict) and res_fallback.get("id"):
                res = res_fallback

        if not isinstance(res, dict) or not res.get("id"):
            err_msg = res.get("error", "No user ID returned") if isinstance(res, dict) else "Invalid response"
            logger.warning(f"Provisioning failed for {username}: {sanitize_sensitive_text(str(err_msg))}")
            return {"error": sanitize_sensitive_text(str(err_msg)), "code": res.get("code") if isinstance(res, dict) else 500}

        return {
            "user_id": str(res["id"]).strip(),
            "username": username.strip(),
            "email": email,
            "role": role.strip(),
        }

    def delete_user(self, base_url: str, admin_token: str, user_id: str) -> bool:
        """
        Delete a user account by exact server-side ID using admin credentials.
        Calls DELETE /api/v1/users/{user_id}.
        Returns True if deletion succeeded or was confirmed.
        """
        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            return False

        base = base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {admin_token.strip()}"}

        try:
            res = self._json_request(
                f"{base}/api/v1/users/{user_id.strip()}",
                method="DELETE",
                headers=headers,
            )
            if isinstance(res, dict):
                if res.get("code") in (401, 403, 500):
                    return False
                msg = res.get("message")
                if isinstance(msg, str) and "deleted" in msg.lower():
                    return True
                if res.get("status") is True:
                    return True
                # If 404, it's already gone
                if res.get("code") == 404:
                    return True
            # Also consider empty dict with 200/204 as success
            return True
        except Exception as exc:
            logger.debug(f"User deletion failed for ID {user_id}: {sanitize_sensitive_text(exc)}")
            return False

    def verify_user_deleted(self, base_url: str, admin_token: str, user_id: str) -> bool:
        """
        Verify that a user account has been deleted server-side.
        Calls GET /api/v1/users/{user_id} (expects 404/error)
        or checks GET /api/v1/users/ for absence of user_id.
        """
        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            return False

        base = base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {admin_token.strip()}"}
        uid = user_id.strip()

        try:
            # 1. Direct user lookup: GET /api/v1/users/{user_id}
            res = self._json_request(
                f"{base}/api/v1/users/{uid}",
                method="GET",
                headers=headers,
            )
            if isinstance(res, dict):
                # 404 indicates user does not exist -> verified deleted
                if res.get("code") == 404 or "not found" in str(res.get("error", "")).lower():
                    return True
                # If it returns user details with matching ID -> user still exists!
                if res.get("id") == uid:
                    return False

            # 2. List check: GET /api/v1/users/
            users = self._json_request(
                f"{base}/api/v1/users/",
                method="GET",
                headers=headers,
            )
            if isinstance(users, list):
                existing_ids = {str(u.get("id")) for u in users if isinstance(u, dict) and u.get("id")}
                return uid not in existing_ids

            return False
        except Exception as exc:
            logger.debug(f"Verify user deleted check failed for {uid}: {sanitize_sensitive_text(exc)}")
            return False
