"""
Tier-1 CVE Behavioral Regression Probes Suite.
"""

from typing import List, Optional

from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, LeakSeverity, ProbingEngine, ProbeResult, ProbeStatus

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
    include_skipped: bool = False,
) -> List[ProbeResult]:
    """
    Executes the Tier-1 CVE behavioral regression probes.
    Skips probes requiring specific preconditions (e.g. milvus_multitenancy)
    unless explicitly present in the preconditions list.
    When include_skipped=True, emits explicit SKIPPED ProbeResult entries
    explaining the missing prerequisite.
    """
    preconditions = preconditions or []
    results: List[ProbeResult] = []

    for probe_module in TIER1_CVE_PROBES:
        # Check precondition
        if probe_module.PRECONDITION and probe_module.PRECONDITION not in preconditions:
            if include_skipped:
                cve_id = getattr(probe_module, "CVE_ID", probe_module.__name__.split(".")[-1].upper().replace("_", "-"))
                results.append(
                    ProbeResult(
                        probe_id=f"skip-{cve_id}",
                        probe_prompt=f"CVE regression check: {cve_id}",
                        probe_category=f"cve_regression:{cve_id}",
                        target_response=f"SKIPPED: Missing required precondition '{probe_module.PRECONDITION}'",
                        retrieved_contexts=[],
                        leaked_canaries=[],
                        severity=LeakSeverity.NONE,
                        channel="cve_regression",
                        skipped=True,
                        status=ProbeStatus.SKIPPED,
                    )
                )
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

