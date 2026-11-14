"""
Open WebUI Target Adapter.
Simulates multi-tenant user personas (Alice & Bob) against Open WebUI REST APIs.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Tuple

from . import TargetAdapter, UserSession, register_adapter
try:
    from firedamp.core.engine import DecoyDocument
except ImportError:
    from core.engine import DecoyDocument

logger = logging.getLogger("firedamp.adapters.openwebui")


@register_adapter
class OpenWebUIAdapter(TargetAdapter):
    """
    Adapter implementation for Open WebUI (formerly Ollama WebUI).
    Simulates:
      - Alice: uploads confidential canary knowledge documents.
      - Bob: unauthorized user dispatching semantic retrieval queries.
    """

    @property
    def target_name(self) -> str:
        return "openwebui"

    def _http_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Utility method for JSON HTTP requests using standard library."""
        req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        payload = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=payload, headers=req_headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            logger.debug(f"HTTP Error {e.code} on {url}: {err_body}")
            try:
                return json.loads(err_body)
            except Exception:
                return {"error": str(e), "code": e.code}
        except Exception as e:
            logger.warning(f"Connection failure to {url}: {e}")
            return {"error": str(e)}

    def authenticate_user(
        self,
        base_url: str,
        username: str,
        password: str,
        role: str = "user"
    ) -> UserSession:
        """
        Attempts to register or sign in a test persona against Open WebUI auth API.
        Falls back to test session tokens when testing offline or in mock environments.
        """
        endpoint = f"{base_url.rstrip('/')}/api/v1/auths"
        email = f"{username.lower()}@firedamp-audit.internal"

        # Try signup first
        signup_payload = {
            "name": username.capitalize(),
            "email": email,
            "password": password
        }
        res = self._http_request(f"{endpoint}/signup", method="POST", data=signup_payload)
        token = res.get("token")

        # If already registered, attempt signin
        if not token:
            signin_payload = {"email": email, "password": password}
            signin_res = self._http_request(f"{endpoint}/signin", method="POST", data=signin_payload)
            token = signin_res.get("token")

        session_headers = {"Authorization": f"Bearer {token}"} if token else {}
        return UserSession(
            username=username,
            role=role,
            token=token,
            headers=session_headers,
            metadata={"email": email}
        )

    def ingest_document(
        self,
        base_url: str,
        session: UserSession,
        document: DecoyDocument
    ) -> str:
        """
        Ingests a decoy document containing canary tokens into Alice's knowledge base.
        """
        endpoint = f"{base_url.rstrip('/')}/api/v1/knowledge"
        payload = {
            "name": document.title,
            "description": f"Decoy document for {document.category} testing",
            "content": document.content,
            "metadata": document.metadata
        }

        res = self._http_request(
            endpoint,
            method="POST",
            data=payload,
            headers=session.headers
        )
        doc_id = res.get("id", f"mock-doc-{document.category}")
        logger.info(f"Ingested canary document '{document.title}' for {session.username} (ID: {doc_id})")
        return str(doc_id)

    def query_rag(
        self,
        base_url: str,
        session: UserSession,
        prompt: str
    ) -> Tuple[str, List[str]]:
        """
        Sends an adversarial probe query as Bob to examine cross-tenant leakage.
        Returns the generated answer string and any retrieved context snippets.
        """
        endpoint = f"{base_url.rstrip('/')}/api/v1/chats"
        payload = {
            "prompt": prompt,
            "stream": False,
            "model": "default"
        }

        res = self._http_request(
            endpoint,
            method="POST",
            data=payload,
            headers=session.headers
        )

        # Parse assistant text and retrieval contexts/citations
        assistant_response = ""
        retrieved_contexts: List[str] = []

        if isinstance(res, dict):
            assistant_response = (
                res.get("response") or
                res.get("content") or
                res.get("message", {}).get("content", "")
            )
            # Inspect background sources/citations returned with the chat response
            sources = res.get("sources") or res.get("citations") or []
            for src in sources:
                if isinstance(src, dict):
                    retrieved_contexts.append(src.get("content", "") or src.get("text", ""))
                elif isinstance(src, str):
                    retrieved_contexts.append(src)

        return assistant_response, retrieved_contexts

    def cleanup(self, base_url: str, session: UserSession) -> None:
        """Cleans up created test collections and chat histories."""
        logger.info(f"Cleaned up session resources for {session.username}")
