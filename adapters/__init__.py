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
    Normalizes authentication, ingestion, query dispatch, and teardown.
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
        prompt: str
    ) -> Tuple[str, List[str]]:
        """
        Executes an exfiltration or probing query under the persona's credentials.
        Returns:
            Tuple[str, List[str]]: (Generated response text, List of retrieved context chunks/citations)
        """
        pass

    @abstractmethod
    def cleanup(self, base_url: str, session: UserSession) -> None:
        """Removes test documents, chats, and artifacts created during the audit."""
        pass


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
        raise KeyError(
            f"Unknown adapter '{name}'. Available adapters: {list(ADAPTER_REGISTRY.keys())}"
        )
    return ADAPTER_REGISTRY[clean_name]()
