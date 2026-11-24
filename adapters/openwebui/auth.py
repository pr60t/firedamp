"""
Open WebUI Authentication Mixin.
Handles signup, signin, and JWT session initialization.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

from adapters.base import UserSession

logger = logging.getLogger("firedamp.adapters.openwebui.auth")


class OpenWebUIAuthMixin:
    """Authentication and session management for Open WebUI test personas."""

    def authenticate_user(
        self,
        base_url: str,
        username: str,
        password: str,
        role: str = "user",
    ) -> UserSession:
        """Sign up or sign in a test persona. Returns session with Bearer token."""
        base = base_url.rstrip("/")
        email = f"{username.lower()}@firedamp-audit.internal"

        # Try signup first
        res = self._json_request(
            f"{base}/api/v1/auths/signup",
            method="POST",
            data={"name": username.capitalize(), "email": email, "password": password},
        )
        token = res.get("token")

        # Fall back to signin
        if not token:
            res = self._json_request(
                f"{base}/api/v1/auths/signin",
                method="POST",
                data={"email": email, "password": password},
            )
            token = res.get("token")

        if not token:
            logger.warning(f"Auth for {username} returned no token: {res}")

        auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

        # Upstream Open WebUI v0.8.5 and v0.8.6 return authenticated user ID at top-level 'id' in auth response
        user_id: Optional[str] = None
        if isinstance(res, dict):
            raw_id = res.get("id")
            if isinstance(raw_id, str) and raw_id.strip():
                user_id = raw_id.strip()
            else:
                logger.debug(f"Auth response for {username} missing or invalid top-level 'id': {raw_id}")

        return UserSession(
            username=username,
            role=role,
            token=token,
            headers=auth_headers,
            metadata={
                "email": email,
                "user_id": user_id,
                "file_ids": [],          # track for cleanup
                "knowledge_ids": [],     # track for cleanup
                "chat_ids": [],          # track for cleanup
            },
        )

    def get_authenticated_user_id(
        self,
        base_url: str,
        session: UserSession,
    ) -> Optional[str]:
        """
        Obtains the authenticated server-side user ID from GET /api/v1/auths/.
        Requires a non-empty string 'id' in the server response.
        Fails closed on unauthenticated tokens, HTTP 401/403, missing 'id', malformed
        responses, and transport errors. Does not treat email, name, or role alone as proof.
        """
        if not session or not session.token:
            return None
        base = base_url.rstrip("/")
        try:
            res = self._json_request(
                f"{base}/api/v1/auths/",
                method="GET",
                headers=session.headers,
            )
            if not isinstance(res, dict):
                return None
            if "error" in res or res.get("code") in (401, 403):
                return None
            raw_id = res.get("id")
            if isinstance(raw_id, str) and raw_id.strip():
                return raw_id.strip()
            return None
        except Exception as exc:
            logger.debug(f"Failed to get authenticated user ID: {exc}")
            return None

    def validate_session(self, base_url: str, session: UserSession) -> bool:
        """
        Explicitly validates whether the session holds a genuinely authenticated token.
        Distinguishes authenticated success from HTTP 401/403 errors and transport failures.
        Returns True ONLY when authentication is positively confirmed.
        """
        uid = self.get_authenticated_user_id(base_url, session)
        if uid is not None:
            return True
        if not session or not session.token:
            return False
        base = base_url.rstrip("/")
        try:
            # Secondary check: GET /api/v1/files/
            files_res = self._json_request(
                f"{base}/api/v1/files/",
                method="GET",
                headers=session.headers,
            )
            if isinstance(files_res, list):
                # Valid HTTP 200 list (even if empty, server accepted token)
                return True
            if isinstance(files_res, dict):
                if files_res.get("code") in (401, 403) or "error" in files_res:
                    return False
                if "data" in files_res and isinstance(files_res["data"], list):
                    return True
            return False
        except Exception as exc:
            logger.debug(f"Session validation failed: {exc}")
            return False

