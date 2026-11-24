"""
Firedamp Bug Class and Channel Taxonomy for Multi-Tenant RAG Authorization.
"""

from enum import Enum


class BugClass(str, Enum):
    """The 8 canonical authorization & isolation bug classes in multi-tenant RAG."""
    IDOR_ROUTE = "missing_authorization_on_route"          # BOLA / IDOR on direct endpoints
    ROLE_LEVEL = "role_or_function_authorization"         # User vs Admin, unauthorized privilege escalation
    LIFECYCLE_STALENESS = "revocation_and_lifecycle_staleness"  # Stale token, cached session, post-revocation query
    VECTOR_INJECTION = "vector_store_filter_injection"    # Filter expression / boolean injection in vector DB
    SHARED_STORE_SCOPING = "shared_store_scoping"          # Partition leakage in shared multi-tenant stores
    CROSS_TENANT_MEMORY = "cross_tenant_cache_and_memory"  # Semantic cache bleed, cross-user agent scratchpad
    INDIRECT_CHANNELS = "indirect_channels"               # Citations, exports, forged links, tool call bleed
    WRITE_SIDE_ACCESS = "write_side_access_poisoning"      # Cross-user overwriting, document injection into other KB
    NOT_APPLICABLE = "not_applicable"                     # Non-RAG / rejected catalog entries (misattributions)


class ProbeChannel(str, Enum):
    """The transmission medium through which data leakage or authorization bypass is verified."""
    DIRECT_API = "direct_api"                  # Direct REST/RPC calls without prompt orchestration
    LLM_PROMPT = "llm_prompt"                  # Adversarial extraction queries sent to the LLM
    CITATION_METADATA = "citation_metadata"    # Leaks in chunk metadata, document source IDs, headers
    LIFECYCLE_EVENT = "lifecycle_event"        # Sequence events (grant -> revoke -> query)
    VECTOR_PAYLOAD = "vector_payload"          # Direct interaction with vector database collections
    WRITE_MUTATION = "write_mutation"          # Ingestion / batch mutation payload attempting overwrite

