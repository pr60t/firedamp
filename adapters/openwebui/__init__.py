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
from core.engine import sanitize_sensitive_text
from .auth import OpenWebUIAuthMixin
from .ingest import OpenWebUIIngestMixin
from .query import OpenWebUIQueryMixin
from .lifecycle import OpenWebUILifecycleMixin
from .user_mgmt import OpenWebUIUserManagementMixin

logger = logging.getLogger("firedamp.adapters.openwebui")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject HTTP redirects so Authorization Bearer headers are never forwarded across origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"HTTP redirect refused to prevent credential forwarding ({code})",
            headers,
            fp,
        )


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


@register_adapter
class OpenWebUIAdapter(
    OpenWebUIAuthMixin,
    OpenWebUIIngestMixin,
    OpenWebUIQueryMixin,
    OpenWebUILifecycleMixin,
    OpenWebUIUserManagementMixin,
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
            with _NO_REDIRECT_OPENER.open(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.debug(f"HTTP {e.code} on {method} {url}: {sanitize_sensitive_text(err_body[:200])}")
            try:
                return {"error": json.loads(err_body), "code": e.code}
            except Exception:
                return {"error": sanitize_sensitive_text(err_body), "code": e.code}
        except Exception as e:
            safe_err = sanitize_sensitive_text(e)
            logger.warning(f"Request failed {method} {url}: {safe_err}")
            return {"error": safe_err}


__all__ = ["OpenWebUIAdapter"]

