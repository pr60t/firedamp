"""
Open WebUI Target Adapter.
Simulates multi-tenant user personas (Alice & Bob) against Open WebUI REST APIs.

API surface used:
  POST /api/v1/auths/signup, /signin    — user auth
  POST /api/v1/files/                   — multipart file upload
  POST /api/v1/knowledge/create         — create knowledge collection
  POST /api/v1/knowledge/{id}/file/add  — link file to collection
  GET  /api/v1/files/{id}               — poll file processing status
  POST /api/chat/completions            — RAG-aware chat (with files[])
  DELETE /api/v1/files/{id}             — teardown
  DELETE /api/v1/knowledge/{id}/delete  — teardown
"""

from __future__ import annotations

import io
import json
import logging
import time
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple

from . import TargetAdapter, UserSession, register_adapter
try:
    from firedamp.core.engine import DecoyDocument
except ImportError:
    from core.engine import DecoyDocument

logger = logging.getLogger("firedamp.adapters.openwebui")


@register_adapter
class OpenWebUIAdapter(TargetAdapter):
    """
    Open WebUI adapter using real REST endpoints.
    Workflow: signup/signin → create knowledge collection → upload files →
    link files to collection → wait for indexing → query via chat completions → cleanup.
    """

    DEFAULT_MODEL = "llama3:8b"

    @property
    def target_name(self) -> str:
        return "openwebui"

    # ── HTTP helpers ──────────────────────────────────────────────────────

    def _json_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """JSON request via stdlib. Returns parsed body or error dict."""
        req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        payload = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            logger.debug(f"HTTP {e.code} on {method} {url}: {err_body[:200]}")
            try:
                return {"error": json.loads(err_body), "code": e.code}
            except Exception:
                return {"error": err_body, "code": e.code}
        except Exception as e:
            logger.warning(f"Request failed {method} {url}: {e}")
            return {"error": str(e)}

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

    # ── Auth ──────────────────────────────────────────────────────────────

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

    # ── Ingestion: file upload → knowledge collection → link ─────────────

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

    # ── RAG Query via chat completions ────────────────────────────────────

    def query_rag(
        self,
        base_url: str,
        session: UserSession,
        prompt: str,
        model: Optional[str] = None,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Query via POST /api/chat/completions with knowledge collection references.
        Returns (assistant_text, list_of_retrieved_context_strings, raw_response_dict).
        """
        base = base_url.rstrip("/")

        # Build files[] from the session's knowledge collections
        files_payload: List[Dict[str, str]] = []
        for kb_id in session.metadata.get("knowledge_ids", []):
            files_payload.append({"type": "collection", "id": kb_id})

        payload: Dict[str, Any] = {
            "model": model or self.DEFAULT_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        if files_payload:
            payload["files"] = files_payload

        res = self._json_request(
            f"{base}/api/chat/completions",
            method="POST",
            data=payload,
            headers=session.headers,
            timeout=120,  # LLM generation can be slow
        )

        assistant_text, retrieved_contexts = self._parse_chat_response(res)
        return assistant_text, retrieved_contexts, res

    @staticmethod
    def _parse_chat_response(res: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Extract assistant text and context chunks from all known response shapes."""
        assistant_text = ""
        retrieved_contexts: List[str] = []

        choices = res.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            assistant_text = message.get("content", "")

            # Sources attached to message (varies by Open WebUI version)
            for key in ("sources", "citations", "context"):
                raw = message.get(key)
                if raw:
                    OpenWebUIAdapter._extract_contexts(raw, retrieved_contexts)

            # Top-level context field (some versions)
            ctx_field = choices[0].get("context")
            if isinstance(ctx_field, str) and ctx_field:
                retrieved_contexts.append(ctx_field)
        else:
            # Non-standard response shape fallback
            assistant_text = (
                res.get("response", "") or
                res.get("content", "") or
                res.get("message", {}).get("content", "")
            )

        # Top-level sources/citations (outside choices)
        for key in ("sources", "citations"):
            raw = res.get(key)
            if raw:
                OpenWebUIAdapter._extract_contexts(raw, retrieved_contexts)

        return assistant_text, retrieved_contexts

    @staticmethod
    def _extract_contexts(raw: Any, out: List[str]) -> None:
        """Recursively pull text from sources/citations in various nested shapes."""
        if isinstance(raw, str):
            if raw:
                out.append(raw)
            return
        if isinstance(raw, list):
            for item in raw:
                OpenWebUIAdapter._extract_contexts(item, out)
            return
        if isinstance(raw, dict):
            # Try common content fields
            for field in ("content", "text", "snippet"):
                val = raw.get(field)
                if isinstance(val, str) and val:
                    out.append(val)
            # Nested document object
            doc = raw.get("document")
            if isinstance(doc, dict):
                OpenWebUIAdapter._extract_contexts(doc, out)
            # Nested metadata.source
            meta = raw.get("metadata")
            if isinstance(meta, dict):
                src = meta.get("source")
                if isinstance(src, str) and src:
                    out.append(src)

    # ── Cleanup ───────────────────────────────────────────────────────────

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
