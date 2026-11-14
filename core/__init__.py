"""
Firedamp: Canaries for your RAG stack.
Automated cross-tenant data leakage detection and isolation auditing.
"""

__version__ = "0.1.0"

from .engine import CanaryToken, DecoyDocument, ProbingEngine, ProbeResult, LeakSeverity
from .target import TargetEnvironment, BaseTargetManager, OpenWebUIContainerManager, DockerTargetManager
from .reporter import FiredampReporter, AuditSummary

__all__ = [
    "__version__",
    "CanaryToken",
    "DecoyDocument",
    "ProbingEngine",
    "ProbeResult",
    "LeakSeverity",
    "TargetEnvironment",
    "BaseTargetManager",
    "OpenWebUIContainerManager",
    "DockerTargetManager",
    "FiredampReporter",
    "AuditSummary",
]

