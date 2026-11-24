"""
Firedamp CVE Registry Loader, Model Definition, and Automated Schema Validation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any

from probes.schemas.bug_classes import BugClass, ProbeChannel


class CVEStatus(str, Enum):
    """Execution and verification status of a CVE catalogue entry."""
    DOCUMENTED = "documented"                      # Verified reference, but no executable probe exists
    IMPLEMENTED = "implemented"                    # Probe code exists, tested via simulation/unit tests
    VALIDATED_VULNERABLE = "validated_vulnerable"  # Confirmed on live vulnerable target
    VALIDATED_PATCHED = "validated_patched"        # Confirmed blocked on live patched target
    DISPUTED = "disputed"                          # Authoritative records conflict or disagree
    REJECTED = "rejected"                          # Misattributed, unrelated to target scope, or invalid


@dataclass
class CVEProbe:
    """Represents a curated behavioral CVE regression probe specification."""
    cve_id: str
    title: str
    platform: str
    bug_class: BugClass
    cwe_id: str
    fixed_version: str
    precondition: Optional[str]
    probe_channel: ProbeChannel
    attack_strategy: str
    behavioral_verification: str
    defensive_remediation: str

    # Extended Schema Attributes (Pillars 1.2 & 7)
    vendor: str = ""
    product: str = ""
    component: str = ""
    description: str = ""
    vulnerability_type: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    attack_surface: str = ""
    attack_preconditions: List[str] = field(default_factory=list)
    official_references: List[str] = field(default_factory=list)
    ghsa_id: Optional[str] = None
    probe_implemented: bool = False
    probe_path: Optional[str] = None
    probe_status: str = "documented"
    validation: Dict[str, Any] = field(default_factory=dict)
    advisory_verification: Dict[str, Any] = field(default_factory=dict)
    live_probe_validation: Dict[str, Any] = field(default_factory=dict)
    rejection_reason: Optional[str] = None
    last_verified: Optional[str] = None
    vulnerable_behavior: str = ""
    patched_behavior: str = ""

    @property
    def is_active(self) -> bool:
        """True if the CVE is active and not marked rejected."""
        return self.probe_status != CVEStatus.REJECTED.value

    @property
    def has_executable_probe(self) -> bool:
        """True if an executable probe script is registered."""
        return self.probe_implemented and bool(self.probe_path)


_CATALOG_PATH = Path(__file__).parent / "cves" / "cve_catalog.json"
_REPO_ROOT = Path(__file__).parent.parent


def validate_cve_catalog(catalog_path: Optional[Path] = None) -> List[str]:
    """
    Automated validation gate for the CVE catalogue schema (Phase 7).
    Enforces:
    - Unique CVE IDs conforming to official format (^CVE-\\d{4}-\\d{4,}$)
    - Non-empty mandatory metadata (cve_id, vendor, product, title, description, cwe_id)
    - Valid reference URLs starting with http:// or https://
    - Valid status restricted to CVEStatus enum
    - Probe paths resolve to existing Python source files if probe.implemented is True
    Returns list of error messages (empty list if perfectly valid).
    """
    target_path = catalog_path or _CATALOG_PATH
    if not target_path.exists():
        return [f"Catalogue file does not exist: {target_path}"]

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return [f"Malformed JSON in catalogue: {e}"]

    if not isinstance(data, list):
        return ["Catalogue root must be a JSON array of CVE records."]

    errors: List[str] = []
    seen_ids = set()
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")

    valid_statuses = {s.value for s in CVEStatus}

    for idx, entry in enumerate(data):
        cve_id = entry.get("cve_id", "")
        prefix = f"Entry #{idx + 1} ({cve_id or 'UNKNOWN'}):"

        # 1. CVE ID validation & uniqueness
        if not cve_id or not cve_pattern.match(cve_id):
            errors.append(f"{prefix} Missing or invalid CVE ID format.")
        elif cve_id in seen_ids:
            errors.append(f"{prefix} Duplicate CVE ID '{cve_id}'.")
        else:
            seen_ids.add(cve_id)

        # 2. Mandatory string fields
        for req in ("vendor", "product", "title", "description", "cwe_id"):
            val = entry.get(req)
            if not val or not isinstance(val, str) or not val.strip():
                errors.append(f"{prefix} Field '{req}' must be a non-empty string.")

        # 3. Reference URLs
        refs = entry.get("official_references", [])
        if not isinstance(refs, list) or len(refs) == 0:
            errors.append(f"{prefix} Field 'official_references' must be a non-empty list.")
        else:
            for r in refs:
                if not isinstance(r, str) or not (r.startswith("http://") or r.startswith("https://")):
                    errors.append(f"{prefix} Invalid official reference URL: {r}")

        # 4. Probe object schema
        probe_info = entry.get("probe", {})
        if not isinstance(probe_info, dict):
            errors.append(f"{prefix} 'probe' must be a dictionary.")
        else:
            status = probe_info.get("status")
            if status not in valid_statuses:
                errors.append(f"{prefix} Invalid probe status '{status}'. Must be one of {valid_statuses}.")

            implemented = probe_info.get("implemented", False)
            probe_path = probe_info.get("path")
            if implemented:
                if not probe_path or not isinstance(probe_path, str):
                    errors.append(f"{prefix} Probe is marked implemented but has no valid 'path'.")
                else:
                    resolved_file = _REPO_ROOT / probe_path
                    if not resolved_file.is_file():
                        errors.append(f"{prefix} Probe file not found at '{resolved_file}'.")

        # 5. Rejection reason required if status is rejected
        if probe_info.get("status") == CVEStatus.REJECTED.value:
            if not entry.get("rejection_reason"):
                errors.append(f"{prefix} Rejected records must specify 'rejection_reason'.")

    return errors


def load_cve_catalog(
    platform: Optional[str] = None,
    bug_class: Optional[BugClass] = None,
    status: Optional[str] = None,
    include_rejected: bool = True,
    catalog_path: Optional[Path] = None,
) -> List[CVEProbe]:
    """
    Load curated CVEs from JSON catalog with optional filtering by platform, bug class, and status.
    By default loads all entries. Set include_rejected=False to filter out rejected misattributions.
    """
    target_path = catalog_path or _CATALOG_PATH
    if not target_path.exists():
        return []

    with open(target_path, "r", encoding="utf-8") as f:
        data: List[Dict[str, Any]] = json.load(f)

    results: List[CVEProbe] = []
    for entry in data:
        # Check rejection filter
        probe_meta = entry.get("probe", {})
        p_status = probe_meta.get("status", "documented")
        if not include_rejected and p_status == CVEStatus.REJECTED.value:
            continue

        if status and p_status != status:
            continue

        entry_platform = entry.get("product") or entry.get("platform", "")
        if platform and entry_platform.lower() != platform.lower():
            continue

        entry_bug_class = entry.get("bug_class")
        if bug_class and entry_bug_class != bug_class.value:
            continue

        # Parse bug_class enum gracefully
        try:
            b_class = BugClass(entry_bug_class) if entry_bug_class else BugClass.NOT_APPLICABLE
        except ValueError:
            b_class = BugClass.NOT_APPLICABLE

        # Parse probe_channel enum gracefully
        channel_str = entry.get("probe_channel", "direct_api")
        try:
            p_channel = ProbeChannel(channel_str)
        except ValueError:
            p_channel = ProbeChannel.DIRECT_API

        results.append(
            CVEProbe(
                cve_id=entry["cve_id"],
                title=entry["title"],
                platform=entry_platform,
                bug_class=b_class,
                cwe_id=entry["cwe_id"],
                fixed_version=entry.get("fixed_version") or (entry.get("fixed_versions", [""])[0] if entry.get("fixed_versions") else ""),
                precondition=entry.get("precondition") or (entry.get("attack_preconditions", [None])[0] if entry.get("attack_preconditions") else None),
                probe_channel=p_channel,
                attack_strategy=entry.get("attack_strategy", entry.get("description", "")),
                behavioral_verification=entry.get("behavioral_verification", ""),
                defensive_remediation=entry.get("defensive_remediation", ""),
                vendor=entry.get("vendor", ""),
                product=entry.get("product", ""),
                component=entry.get("component", ""),
                description=entry.get("description", ""),
                vulnerability_type=entry.get("vulnerability_type", ""),
                affected_versions=entry.get("affected_versions", []),
                fixed_versions=entry.get("fixed_versions", []),
                attack_surface=entry.get("attack_surface", ""),
                attack_preconditions=entry.get("attack_preconditions", []),
                official_references=entry.get("official_references", []),
                ghsa_id=entry.get("ghsa_id"),
                probe_implemented=probe_meta.get("implemented", False),
                probe_path=probe_meta.get("path"),
                probe_status=p_status,
                validation=entry.get("validation", {}),
                advisory_verification=entry.get("advisory_verification", {}),
                live_probe_validation=entry.get("live_probe_validation", {}),
                rejection_reason=entry.get("rejection_reason"),
                last_verified=entry.get("last_verified"),
                vulnerable_behavior=entry.get("vulnerable_behavior", ""),
                patched_behavior=entry.get("patched_behavior", ""),
            )
        )
    return results
