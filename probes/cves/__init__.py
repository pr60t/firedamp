"""
Tier-1 CVE Behavioral Regression Probes Suite.
"""

from typing import List, Optional

from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult

from . import cve_2026_44560
from . import cve_2026_45398
from . import cve_2026_28788
from . import cve_2026_54019

TIER1_CVE_PROBES = [
    cve_2026_44560,
    cve_2026_45398,
    cve_2026_28788,
    cve_2026_54019,
]


def run_cve_suite(
    adapter: TargetAdapter,
    base_url: str,
    alice: UserSession,
    bob: UserSession,
    planted_canaries: List[CanaryToken],
    engine: ProbingEngine,
    dry_run: bool = False,
    preconditions: Optional[List[str]] = None,
) -> List[ProbeResult]:
    """
    Executes the Tier-1 CVE behavioral regression probes.
    Skips probes requiring specific preconditions (e.g. milvus_multitenancy)
    unless explicitly present in the preconditions list.
    """
    preconditions = preconditions or []
    results: List[ProbeResult] = []

    for probe_module in TIER1_CVE_PROBES:
        # Check precondition
        if probe_module.PRECONDITION and probe_module.PRECONDITION not in preconditions:
            # Skip if precondition is not active in current target environment
            continue

        res = probe_module.run(
            adapter=adapter,
            base_url=base_url,
            alice=alice,
            bob=bob,
            planted_canaries=planted_canaries,
            engine=engine,
            dry_run=dry_run,
        )
        results.append(res)

    return results


__all__ = [
    "cve_2026_44560",
    "cve_2026_45398",
    "cve_2026_28788",
    "cve_2026_54019",
    "TIER1_CVE_PROBES",
    "run_cve_suite",
]

