"""
Open WebUI Ingestion Mixin.
Handles multipart file uploads, knowledge collection creation, and file-to-knowledge linkage.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from adapters.base import UserSession
try:
    from firedamp.core.engine import DecoyDocument
except ImportError:
    from core.engine import DecoyDocument

logger = logging.getLogger("firedamp.adapters.openwebui.ingest")


class OpenWebUIIngestMixin:
    """Document upload, indexing, and collection management for Open WebUI."""

    def _multipart_upload(
        self,
        url: str,
        filename: str,
        content: bytes,
        content_type: str = "text/markdown",
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Multipart/form-data file upload via stdlib."""
        boundary = "----FiredampBoundary9f3e"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")

        req_headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            logger.debug(f"Upload HTTP {e.code}: {err_body[:200]}")
            return {"error": err_body, "code": e.code}
        except Exception as e:
            logger.warning(f"Upload failed: {e}")
            return {"error": str(e)}

    def ingest_document(
        self,
        base_url: str,
        session: UserSession,
        document: DecoyDocument,
    ) -> str:
        """
        Full ingestion pipeline:
        1. Upload document as file via multipart POST.
        2. Create a private knowledge collection (one per document).
        3. Link the uploaded file to the collection.
        4. Wait for file processing/indexing to complete.
        Returns the knowledge collection ID.
        """
        base = base_url.rstrip("/")

        # 1. Upload file
        filename = document.title.replace(" ", "_") + ".md"
        file_content = document.content.encode("utf-8")

        upload_res = self._multipart_upload(
            f"{base}/api/v1/files/",
            filename=filename,
            content=file_content,
            headers=session.headers,
        )
        file_id = upload_res.get("id")
        if not file_id:
            logger.error(f"File upload failed for '{document.title}': {upload_res}")
            return f"upload-failed-{document.category}"

        session.metadata["file_ids"].append(file_id)
        logger.info(f"Uploaded file '{filename}' → {file_id}")

        # 2. Create knowledge collection
        kb_res = self._json_request(
            f"{base}/api/v1/knowledge/create",
            method="POST",
            data={
                "name": f"firedamp-canary-{document.category}-{file_id[:8]}",
                "description": f"Firedamp canary collection ({document.category})",
                "data": {},
                "access_control": None,
            },
            headers=session.headers,
        )
        kb_id = kb_res.get("id")
        if not kb_id:
            logger.error(f"Knowledge creation failed: {kb_res}")
            return f"kb-failed-{document.category}"

        session.metadata["knowledge_ids"].append(kb_id)
        logger.info(f"Created knowledge collection → {kb_id}")

        # 3. Wait for file processing before linking
        self._wait_for_file_ready(base, session, file_id)

        # 4. Link file to knowledge collection
        link_res = self._json_request(
            f"{base}/api/v1/knowledge/{kb_id}/file/add",
            method="POST",
            data={"file_id": file_id},
            headers=session.headers,
        )
        if "error" in link_res and "code" in link_res:
            logger.warning(f"File-to-knowledge link may have failed: {link_res}")
        else:
            logger.info(f"Linked file {file_id} → knowledge {kb_id}")

        return kb_id

    def _wait_for_file_ready(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
        timeout: int = 60,
        poll_interval: float = 2.0,
    ) -> bool:
        """Poll GET /api/v1/files/{id} until processing is done or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self._json_request(
                f"{base_url}/api/v1/files/{file_id}",
                headers=session.headers,
            )
            # shortcut: Open WebUI marks status in meta.status or data.status
            meta = res.get("meta", res.get("data", {}))
            status = meta.get("status", "")
            if isinstance(status, str) and status.lower() in ("completed", "ready", ""):
                # Empty status on older versions means ready
                return True
            if isinstance(status, str) and status.lower() in ("error", "failed"):
                logger.warning(f"File {file_id} processing failed: {status}")
                return False
            time.sleep(poll_interval)
        logger.warning(f"File {file_id} processing timed out after {timeout}s")
        return False

