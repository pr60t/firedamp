"""
Firedamp Probes Package.
Houses the 8-pillar threat taxonomy, curated CVE regression probes,
and multi-scenario isolation auditing suites.
"""

from probes.cve_registry import (
    CVEProbe,
    CVEStatus,
    load_cve_catalog,
    validate_cve_catalog,
)

__all__ = [
    "CVEProbe",
    "CVEStatus",
    "load_cve_catalog",
    "validate_cve_catalog",
]
