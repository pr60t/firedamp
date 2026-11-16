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
from .agent_memory import (
    run_agent_memory_scenarios,
    test_tool_cache_isolation,
    test_user_memory_route_isolation,
)

__all__ = [
    "run_lifecycle_scenarios",
    "test_revocation_in_flight",
    "test_post_revocation_staleness",
    "test_delete_while_indexing",
    "run_write_poisoning_scenarios",
    "test_cross_tenant_collection_injection",
    "test_cross_tenant_file_overwrite",
    "run_agent_memory_scenarios",
    "test_user_memory_route_isolation",
    "test_tool_cache_isolation",
]

