"""
Scenario vectors package for Firedamp.
Covers advanced sequence, poisoning, and indirect channel scenarios.
"""

from .lifecycle import (
    run_lifecycle_scenarios,
    test_delete_while_indexing,
    test_post_revocation_staleness,
    test_revocation_in_flight,
)
from .write_poisoning import (
    run_write_poisoning_scenarios,
    test_cross_tenant_collection_injection,
    test_cross_tenant_file_overwrite,
)

__all__ = [
    "run_lifecycle_scenarios",
    "test_revocation_in_flight",
    "test_post_revocation_staleness",
    "test_delete_while_indexing",
    "run_write_poisoning_scenarios",
    "test_cross_tenant_collection_injection",
    "test_cross_tenant_file_overwrite",
]

