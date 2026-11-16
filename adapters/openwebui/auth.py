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
        return UserSession(
            username=username,
            role=role,
            token=token,
            headers=auth_headers,
            metadata={
                "email": email,
                "file_ids": [],          # track for cleanup
                "knowledge_ids": [],     # track for cleanup
                "chat_ids": [],          # track for cleanup
            },
        )

