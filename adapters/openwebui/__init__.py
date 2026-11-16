"""
Open WebUI Adapter Package.
Composes modular auth, ingest, query, and lifecycle mixins into a unified TargetAdapter.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from adapters.base import TargetAdapter, UserSession, register_adapter
from .auth import OpenWebUIAuthMixin
from .ingest import OpenWebUIIngestMixin
from .query import OpenWebUIQueryMixin
from .lifecycle import OpenWebUILifecycleMixin

logger = logging.getLogger("firedamp.adapters.openwebui")


@register_adapter
class OpenWebUIAdapter(
    OpenWebUIAuthMixin,
    OpenWebUIIngestMixin,
    OpenWebUIQueryMixin,
    OpenWebUILifecycleMixin,
    TargetAdapter,
):
    """
    Open WebUI adapter composed from modular mixins.
    Provides full lifecycle operations: auth, ingestion, query, lifecycle, and teardown.
    """

    DEFAULT_MODEL = "llama3:8b"

    @property
    def target_name(self) -> str:
        return "openwebui"

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


__all__ = ["OpenWebUIAdapter"]

