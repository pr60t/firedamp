"""
Target Adapter Interfaces and Registry.
Defines the uniform protocol required to interact with diverse RAG architectures.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Type

try:
    from firedamp.core.engine import DecoyDocument
except ImportError:
    from core.engine import DecoyDocument


@dataclass
class UserSession:
    """Represents an authenticated persona session on the target platform."""
    username: str
    role: str  # e.g., 'owner', 'attacker', 'analyst'
    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class TargetAdapter(ABC):
    """
    Abstract protocol for all platform-specific adapters.
    Normalizes authentication, ingestion, query dispatch, lifecycle, and teardown.
    """

    @property
    @abstractmethod
    def target_name(self) -> str:
        """Identifier for the target platform (e.g. 'openwebui', 'dify')."""
        pass

    @abstractmethod
    def authenticate_user(
        self,
        base_url: str,
        username: str,
        password: str,
        role: str = "user"
    ) -> UserSession:
        """Authenticates or signs up a test persona and returns their session."""
        pass

    @abstractmethod
    def ingest_document(
        self,
        base_url: str,
        session: UserSession,
        document: DecoyDocument
    ) -> str:
        """Uploads and indexes a decoy document containing canary tokens into the user's scope."""
        pass

    @abstractmethod
    def query_rag(
        self,
        base_url: str,
        session: UserSession,
        prompt: str,
        files: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Executes an exfiltration or probing query under the persona's credentials.
        Returns:
            Tuple[str, List[str], Dict[str, Any]]: (Generated response text, List of retrieved context chunks, Raw response dict)
        """
        pass

    @abstractmethod
    def query_resource_direct(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        k: int = 50
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Calls direct retrieval or vector query endpoints referencing a resource ID Bob shouldn't access.
        Used for IDOR/BOLA regression checks without prompting the LLM.
        """
        pass

    def query_collection(
        self,
        base_url: str,
        session: UserSession,
        collection_names: List[str],
        query: str = "anything",
        k: int = 10,
        hybrid: bool = False,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Executes query against vector collection endpoint: POST /api/v1/retrieval/query/collection.
        Target endpoint for GHSA-p5cp-r7rg-qpxc (CVE-2026-54019) and GHSA-4g37-7p2c-38r9 (CVE-2026-45398).
        """
        first_ref = collection_names[0] if collection_names else ""
        return self.query_resource_direct(base_url, session, first_ref, k=k)

    def query_doc(
        self,
        base_url: str,
        session: UserSession,
        collection_name: str,
        query: str = "anything",
        k: int = 10,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Executes query against document retrieval endpoint: POST /api/v1/retrieval/query/doc.
        Target endpoint for GHSA-p5cp-r7rg-qpxc (CVE-2026-54019) and GHSA-4g37-7p2c-38r9 (CVE-2026-45398).
        """
        return self.query_resource_direct(base_url, session, collection_name, k=k)

    def read_file_content(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
    ) -> Optional[str]:
        """
        Reads back an authorized user's file content through a legitimate path to independently
        verify whether write-poisoning / unauthorized mutations took effect (CVE-2026-28788).
        """
        return None

    @abstractmethod
    def overwrite_resource(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        payload: str,
        collection_name: Optional[str] = None,
        file_model: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Attempts to overwrite or mutate a resource owned by another tenant.
        Used for write-side integrity and poisoning checks (e.g. CVE-2026-28788).
        """
        pass

    def get_knowledge_base_files(
        self,
        base_url: str,
        session: UserSession,
        knowledge_id: str,
    ) -> Optional[List[str]]:
        """
        Retrieves the verified list of file IDs belonging to the given knowledge collection.
        Returns None if membership cannot be verified (e.g. error, unsupported, or incomplete enumeration).
        Returns an empty list (List[str]) if the knowledge collection is verified to contain zero files.
        Default implementation returns None.
        """
        return None

    def get_accessible_knowledge_bases(
        self,
        base_url: str,
        session: UserSession,
    ) -> Optional[List[str]]:
        """
        Retrieves the list of accessible knowledge base IDs for the given user session.
        Returns None if enumeration is unsupported or fails.
        Returns an empty list (List[str]) if the user session has zero accessible knowledge bases.
        Default implementation returns None.
        """
        return None

    def get_knowledge_base_metadata(
        self,
        base_url: str,
        session: UserSession,
        knowledge_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Return authoritative server-side metadata for one knowledge base, or None."""
        return None

    def inject_into_collection(
        self,
        base_url: str,
        session: UserSession,
        target_collection_id: str,
        document: DecoyDocument,
    ) -> Dict[str, Any]:
        """
        Attempts to inject an unauthorized document directly into another tenant's collection.
        Default implementation fails closed. Platform-specific adapters must implement a dedicated
        collection injection operation only using a verified upstream API contract.
        """
        return {
            "error": "Unsupported operation: direct collection injection is not supported by this adapter",
            "code": 501,
        }

    def create_user_memory(
        self,
        base_url: str,
        session: UserSession,
        content: str,
    ) -> Dict[str, Any]:
        """
        Creates a persistent user memory / agent scratchpad entry.
        Default implementation returns empty dict.
        """
        return {}

    def get_user_memories(
        self,
        base_url: str,
        session: UserSession,
        target_user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves user memory / agent scratchpad entries.
        Default implementation returns empty list.
        """
        return []

    def execute_tool_action(
        self,
        base_url: str,
        session: UserSession,
        tool_name: str,
        tool_input: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Executes an agent tool or MCP action under session credentials.
        Default implementation returns empty dict.
        """
        return {}

    @abstractmethod
    def enumerate_resources(
        self,
        base_url: str,
        session: UserSession
    ) -> List[str]:
        """
        Lists all resource IDs returned by the target platform to this session.
        Used to detect cross-tenant resource enumeration leaks.
        """
        pass

    @abstractmethod
    def share_resource(
        self,
        base_url: str,
        owner: UserSession,
        resource_ref: str,
        grantee: UserSession
    ) -> Dict[str, Any]:
        """Grants access to a resource to another session."""
        pass

    @abstractmethod
    def revoke_resource(
        self,
        base_url: str,
        owner: UserSession,
        resource_ref: str,
        grantee: UserSession
    ) -> Dict[str, Any]:
        """Revokes access to a resource from another session."""
        pass

    @abstractmethod
    def cleanup(self, base_url: str, session: UserSession) -> None:
        """Removes test documents, chats, and artifacts created during the audit."""
        pass

    def validate_session(self, base_url: str, session: UserSession) -> bool:
        """
        Explicitly validates whether the session holds a genuinely authenticated token.
        Distinguishes authenticated success from HTTP 401/403 errors and transport failures.
        Returns True ONLY when authentication is positively confirmed.
        """
        if not session or not session.token:
            return False
        return False

    def get_authenticated_user_id(
        self,
        base_url: str,
        session: UserSession,
    ) -> Optional[str]:
        """
        Retrieves the authenticated server-side user ID from the backend (e.g. via GET /api/v1/auths/).
        Returns a non-empty string user ID if positively authenticated and verified, or None.
        Fails closed on unauthenticated tokens, HTTP 401/403, errors, or missing ID.
        """
        return None

    def get_file_metadata(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves authoritative server-side metadata for a file (e.g. user_id, filename).
        Returns metadata dict if accessible, None if inaccessible or unverified.
        """
        return None

    def delete_file(
        self,
        base_url: str,
        session: UserSession,
        file_id: str,
    ) -> bool:
        """
        Deletes a specific single file resource by its ID.
        Returns True if deletion succeeded, False otherwise.
        """
        return False


# Global adapter registry
ADAPTER_REGISTRY: Dict[str, Type[TargetAdapter]] = {}


def register_adapter(adapter_cls: Type[TargetAdapter]) -> Type[TargetAdapter]:
    """Decorator to register a target adapter."""
    instance = adapter_cls()
    ADAPTER_REGISTRY[instance.target_name.lower()] = adapter_cls
    return adapter_cls


def get_adapter(name: str) -> TargetAdapter:
    """Retrieves an instantiated adapter by target name."""
    clean_name = name.lower()
    if clean_name not in ADAPTER_REGISTRY:
        # Attempt deferred import of built-in adapters
        if clean_name == "openwebui":
            from .openwebui import OpenWebUIAdapter
            return OpenWebUIAdapter()
        raise ValueError(
            f"Unknown adapter '{name}'. Available adapters: {list(ADAPTER_REGISTRY.keys())}"
        )
    return ADAPTER_REGISTRY[clean_name]()

