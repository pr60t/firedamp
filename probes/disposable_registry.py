"""Trusted scan-scoped registry for disposable resources.

Only resources registered by the active scan under an explicit owner may be
used by destructive probes. Mutable UserSession metadata is never sufficient
proof of disposability.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple


class TrustedScanDisposableRegistry:
    """In-memory provenance registry scoped to one Firedamp scan run."""

    def __init__(self) -> None:
        self._entries: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def register(
        self,
        run_id: str,
        resource_id: str,
        owner: str,
        provisioning_status: str = "provisioned",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("Trusted disposable registration requires a non-empty run_id")
        if not isinstance(resource_id, str) or not resource_id.strip():
            raise ValueError("Trusted disposable registration requires a non-empty resource_id")
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("Trusted disposable registration requires a non-empty owner")
        if provisioning_status != "provisioned":
            raise ValueError("Only newly provisioned resources can be registered as disposable")
        key = (run_id.strip(), resource_id.strip())
        self._entries[key] = {
            "run_id": key[0],
            "resource_id": key[1],
            "owner": owner.strip(),
            "provisioning_status": provisioning_status,
            "metadata": dict(metadata or {}),
            "timestamp": time.time(),
        }

    def is_registered(self, run_id: str, resource_id: str, owner: str) -> bool:
        if not all(isinstance(v, str) and v.strip() for v in (run_id, resource_id, owner)):
            return False
        record = self._entries.get((run_id.strip(), resource_id.strip()))
        return bool(
            record
            and record.get("run_id") == run_id.strip()
            and record.get("resource_id") == resource_id.strip()
            and record.get("owner") == owner.strip()
            and record.get("provisioning_status") == "provisioned"
        )

    def get_metadata(self, run_id: str, resource_id: str, owner: str) -> Optional[Dict[str, Any]]:
        if not self.is_registered(run_id, resource_id, owner):
            return None
        record = self._entries.get((run_id.strip(), resource_id.strip()), {})
        metadata = record.get("metadata")
        return dict(metadata) if isinstance(metadata, dict) else None

    def mark_cleaned_up(self, run_id: str, resource_id: str) -> None:
        record = self._entries.get((run_id, resource_id))
        if record:
            record["provisioning_status"] = "cleaned_up"

    def is_cleaned_up(self, run_id: str, resource_id: str, owner: Optional[str] = None) -> bool:
        record = self._entries.get((run_id, resource_id))
        if not record or record.get("provisioning_status") != "cleaned_up":
            return False
        return owner is None or record.get("owner") == owner

    def clear(self) -> None:
        self._entries.clear()


_TRUSTED_SCAN_REGISTRY = TrustedScanDisposableRegistry()


def register_trusted_disposable_resource(
    run_id: str,
    resource_id: str,
    owner: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    _TRUSTED_SCAN_REGISTRY.register(run_id, resource_id, owner, metadata=metadata)


def clear_trusted_registry() -> None:
    _TRUSTED_SCAN_REGISTRY.clear()
