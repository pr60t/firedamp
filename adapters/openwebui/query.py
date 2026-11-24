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
        files: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Query via POST /api/chat/completions with knowledge collection or file references.
        Returns (assistant_text, list_of_retrieved_context_strings, raw_response_dict).
        """
        base = base_url.rstrip("/")

        # Build files[] from explicit parameter or from the session's knowledge collections
        if files is not None:
            files_payload = files
        else:
            files_payload = []
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

    def query_collection(
        self,
        base_url: str,
        session: UserSession,
        collection_names: List[str],
        query: str = "anything",
        k: int = 10,
        hybrid: bool = False,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Executes query against vector collection endpoint: POST /api/v1/retrieval/query/collection.
        Target endpoint for GHSA-p5cp-r7rg-qpxc (CVE-2026-54019) and GHSA-4g37-7p2c-38r9 (CVE-2026-45398).
        """
        base = base_url.rstrip("/")
        payload: Dict[str, Any] = {
            "collection_names": collection_names,
            "query": query,
            "k": k,
            "hybrid": hybrid,
        }
        res = self._json_request(
            f"{base}/api/v1/retrieval/query/collection",
            method="POST",
            data=payload,
            headers=session.headers,
            timeout=30,
        )
        retrieved_contexts = self._extract_documents_from_retrieval(res)
        return "", retrieved_contexts, res

    def query_doc(
        self,
        base_url: str,
        session: UserSession,
        collection_name: str,
        query: str = "anything",
        k: int = 10,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Executes query against document retrieval endpoint: POST /api/v1/retrieval/query/doc.
        Target endpoint for GHSA-p5cp-r7rg-qpxc (CVE-2026-54019) and GHSA-4g37-7p2c-38r9 (CVE-2026-45398).
        """
        base = base_url.rstrip("/")
        payload: Dict[str, Any] = {
            "collection_name": collection_name,
            "query": query,
            "k": k,
        }
        res = self._json_request(
            f"{base}/api/v1/retrieval/query/doc",
            method="POST",
            data=payload,
            headers=session.headers,
            timeout=30,
        )
        retrieved_contexts = self._extract_documents_from_retrieval(res)
        return "", retrieved_contexts, res

    def query_resource_direct(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        k: int = 50,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Calls collection retrieval endpoint referencing an unauthorized collection or UUID.
        Targets POST /api/v1/retrieval/query/collection without unverified fallback routes.
        """
        return self.query_collection(
            base_url=base_url,
            session=session,
            collection_names=[resource_ref],
            query="canary confidential secret token document summary",
            k=k,
            hybrid=False,
        )

    @staticmethod
    def _extract_documents_from_retrieval(res: Dict[str, Any]) -> List[str]:
        """Extract text chunks from retrieval endpoints (/query/collection, /query/doc)."""
        retrieved_contexts: List[str] = []
        documents = res.get("documents", [])
        if isinstance(documents, list):
            for doc in documents:
                if isinstance(doc, list):
                    for chunk in doc:
                        if isinstance(chunk, str) and chunk:
                            retrieved_contexts.append(chunk)
                elif isinstance(doc, str) and doc:
                    retrieved_contexts.append(doc)
        return retrieved_contexts

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

        # Top-level sources/citations/context (outside choices)
        for key in ("sources", "citations", "context"):
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

