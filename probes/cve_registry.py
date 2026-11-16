"""
Firedamp CVE Registry Loader and Model Definition.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any

from probes.schemas.bug_classes import BugClass, ProbeChannel


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


_CATALOG_PATH = Path(__file__).parent / "cves" / "cve_catalog.json"


def load_cve_catalog(
    platform: Optional[str] = None,
    bug_class: Optional[BugClass] = None,
    catalog_path: Optional[Path] = None,
) -> List[CVEProbe]:
    """
    Load curated CVEs from JSON catalog with optional filtering by platform and bug class.
    """
    target_path = catalog_path or _CATALOG_PATH
    if not target_path.exists():
        return []

    with open(target_path, "r", encoding="utf-8") as f:
        data: List[Dict[str, Any]] = json.load(f)

    results: List[CVEProbe] = []
    for entry in data:
        if platform and entry.get("platform", "").lower() != platform.lower():
            continue
        if bug_class and entry.get("bug_class") != bug_class.value:
            continue

        results.append(
            CVEProbe(
                cve_id=entry["cve_id"],
                title=entry["title"],
                platform=entry["platform"],
                bug_class=BugClass(entry["bug_class"]),
                cwe_id=entry["cwe_id"],
                fixed_version=entry["fixed_version"],
                precondition=entry.get("precondition"),
                probe_channel=ProbeChannel(entry["probe_channel"]),
                attack_strategy=entry["attack_strategy"],
                behavioral_verification=entry["behavioral_verification"],
                defensive_remediation=entry["defensive_remediation"],
            )
        )
    return results

