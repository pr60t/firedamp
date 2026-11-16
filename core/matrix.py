"""
Authorization Matrix Replay Engine (RAG Autorize).
Captures Owner requests across RAG endpoints and replays them across Intruder,
Ex-Member, and Anonymous personas to evaluate structural diffs and canary leakage.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple, Set

from adapters.base import TargetAdapter, UserSession
from core.engine import CanaryToken, ProbingEngine, ProbeResult, LeakSeverity

logger = logging.getLogger("firedamp.core.matrix")


class ActorRole(str, Enum):
    """The persona executing an authorization probe."""
    OWNER = "Owner (Alice)"
    INTRUDER = "Intruder (Bob)"
    EX_MEMBER = "Ex-Member (Charlie)"
    ANONYMOUS = "Anonymous"


class AuthorizationStatus(str, Enum):
    """Result status of replaying an authorized operation under a different persona."""
    ENFORCED = "ENFORCED"            # Blocked (401/403/404 or empty clean response)
    BYPASS_LEAK = "BYPASS_LEAK"      # Canary leaked across boundary
    BYPASS_STRUCTURAL = "BYPASS"     # 200 OK with identical response structure/data
    ANOMALY = "ANOMALY"              # Unexpected status or partial mismatch


@dataclass
class RecordedOperation:
    """A standard RAG API operation recorded under Owner credentials."""
    op_id: str
    name: str
    method: str
    path: str
    payload: Optional[Dict[str, Any]] = None
    expected_status: int = 200
    owner_status: int = 200
    owner_response: Dict[str, Any] = field(default_factory=dict)
    owner_contexts: List[str] = field(default_factory=list)


@dataclass
class CellEvaluation:
    """Outcome of replaying one operation as a specific actor persona."""
    op_id: str
    op_name: str
    actor_role: ActorRole
    http_status: int
    auth_status: AuthorizationStatus
    canaries_leaked: List[str] = field(default_factory=list)
    key_overlap_ratio: float = 0.0
    details: str = ""

    @property
    def is_violation(self) -> bool:
        return self.auth_status in (AuthorizationStatus.BYPASS_LEAK, AuthorizationStatus.BYPASS_STRUCTURAL)


@dataclass
class MatrixReport:
    """Complete authorization matrix evaluation report."""
    target_name: str
    target_url: str
    operations: List[str]
    actors: List[ActorRole]
    grid: List[CellEvaluation]
    total_violations: int = 0
    passed: bool = True


class StructuralDiffComparator:
    """
    Compares owner response vs replayed response structurally:
    - Status code enforcement (401/403 vs 200)
    - JSON key set similarity (Jaccard index)
    - Canary token presence
    """

    @staticmethod
    def evaluate(
        owner_resp: Dict[str, Any],
        replayed_status: int,
        replayed_resp: Dict[str, Any],
        replayed_contexts: List[str],
        planted_canaries: List[CanaryToken],
        engine: ProbingEngine,
    ) -> Tuple[AuthorizationStatus, List[str], float, str]:
        known_tokens = {c.token for c in planted_canaries} if planted_canaries else set()

        # 1. Check for canary token leaks (Hard Fail)
        resp_str = json.dumps(replayed_resp, default=str)
        leaked = set()
        matches = engine.canary_regex.findall(resp_str)
        for m in matches:
            if not known_tokens or m in known_tokens:
                leaked.add(m)

        for ctx in replayed_contexts:
            ctx_matches = engine.canary_regex.findall(ctx)
            for m in ctx_matches:
                if not known_tokens or m in known_tokens:
                    leaked.add(m)

        if leaked:
            return AuthorizationStatus.BYPASS_LEAK, list(leaked), 1.0, "Canary leaked in response body"

        # 2. Check HTTP status code
        if replayed_status in (401, 403):
            return AuthorizationStatus.ENFORCED, [], 0.0, f"Access blocked (HTTP {replayed_status})"

        if replayed_status == 404:
            return AuthorizationStatus.ENFORCED, [], 0.0, "Resource hidden / not found (HTTP 404)"

        # Check for error dict
        if "error" in replayed_resp:
            err = replayed_resp.get("error")
            code = replayed_resp.get("code")
            if code in (401, 403, 404) or "detail" in str(err).lower():
                return AuthorizationStatus.ENFORCED, [], 0.0, "Access denied via error body"

        # 3. Calculate structural key overlap
        owner_keys = StructuralDiffComparator._extract_keys(owner_resp)
        replayed_keys = StructuralDiffComparator._extract_keys(replayed_resp)

        if not owner_keys and not replayed_keys:
            key_overlap = 0.0
        elif not owner_keys or not replayed_keys:
            key_overlap = 0.0
        else:
            intersection = owner_keys.intersection(replayed_keys)
            union = owner_keys.union(replayed_keys)
            key_overlap = round(len(intersection) / len(union), 2)

        # 4. If status is 200 with high key overlap on sensitive data, it's a structural bypass
        if replayed_status == 200:
            if key_overlap > 0.7:
                return (
                    AuthorizationStatus.BYPASS_STRUCTURAL,
                    [],
                    key_overlap,
                    f"Structural bypass: HTTP 200 with {int(key_overlap * 100)}% key overlap",
                )
            return (
                AuthorizationStatus.ANOMALY,
                [],
                key_overlap,
                f"HTTP 200 returned with distinct response shape ({int(key_overlap * 100)}% overlap)",
            )

        return AuthorizationStatus.ENFORCED, [], key_overlap, f"Status code {replayed_status}"

    @staticmethod
    def _extract_keys(obj: Any, prefix: str = "") -> Set[str]:
        keys = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                keys.update(StructuralDiffComparator._extract_keys(v, full_key))
        elif isinstance(obj, list):
            for item in obj:
                keys.update(StructuralDiffComparator._extract_keys(item, prefix))
        return keys


class AuthorizationMatrixRunner:
    """
    Orchestrates the Actor x Resource x Operation permission replay matrix.
    """

    def __init__(self, engine: Optional[ProbingEngine] = None):
        self.engine = engine or ProbingEngine()

    def run_matrix(
        self,
        adapter: TargetAdapter,
        base_url: str,
        alice: UserSession,
        bob: UserSession,
        charlie: Optional[UserSession] = None,
        planted_canaries: Optional[List[CanaryToken]] = None,
        dry_run: bool = False,
    ) -> MatrixReport:
        """
        Executes the authorization matrix across Owner, Intruder, Ex-Member, and Anonymous.
        """
        base = base_url.rstrip("/")
        canaries = planted_canaries or []

        # Build anonymous session (no tokens, no auth headers)
        anon_session = UserSession(username="anonymous", role="anonymous", token=None, headers={})

        # Build ex-member session if not supplied
        if not charlie:
            charlie = UserSession(
                username="charlie_exmember",
                role="exmember",
                token="charlie-revoked-token" if dry_run else None,
                headers={"Authorization": "Bearer charlie-revoked-token"} if dry_run else {},
            )

        alice_file_ids = alice.metadata.get("file_ids", [])
        alice_kb_ids = alice.metadata.get("knowledge_ids", [])
        file_id = alice_file_ids[0] if alice_file_ids else "file-alice-target"
        kb_id = alice_kb_ids[0] if alice_kb_ids else "kb-alice-uuid"

        # 1. Define standard operations across the RAG attack surface
        operations: List[RecordedOperation] = [
            RecordedOperation(
                op_id="op_file_inspect",
                name="File Metadata (GET /api/v1/files/{id})",
                method="GET",
                path=f"/api/v1/files/{file_id}",
            ),
            RecordedOperation(
                op_id="op_file_content",
                name="File Raw Content (GET /api/v1/files/{id}/content)",
                method="GET",
                path=f"/api/v1/files/{file_id}/content",
            ),
            RecordedOperation(
                op_id="op_kb_inspect",
                name="Knowledge Base (GET /api/v1/knowledge/{id})",
                method="GET",
                path=f"/api/v1/knowledge/{kb_id}",
            ),
            RecordedOperation(
                op_id="op_vector_query",
                name="Vector Retrieval Query (POST /api/v1/retrieval/query)",
                method="POST",
                path="/api/v1/retrieval/query",
                payload={"collection_names": [kb_id], "query": "canary confidential summary", "k": 10},
            ),
            RecordedOperation(
                op_id="op_chat_completions",
                name="Chat Completions Context (POST /api/chat/completions)",
                method="POST",
                path="/api/chat/completions",
                payload={
                    "model": getattr(adapter, "DEFAULT_MODEL", "llama3:8b"),
                    "messages": [{"role": "user", "content": "Summarize private files."}],
                    "files": [{"type": "collection", "id": kb_id}],
                },
            ),
            RecordedOperation(
                op_id="op_batch_overwrite",
                name="Batch File Overwrite (POST /api/v1/files/batch/process)",
                method="POST",
                path="/api/v1/files/batch/process",
                payload={"file_id": file_id, "content": "POISON_TEST"},
            ),
            RecordedOperation(
                op_id="op_file_delete",
                name="File Deletion (DELETE /api/v1/files/{id})",
                method="DELETE",
                path=f"/api/v1/files/{file_id}",
            ),
        ]

        # In dry run, simulate realistic authorized owner responses and enforced non-owner responses
        replayed_actors = [
            (ActorRole.INTRUDER, bob),
            (ActorRole.EX_MEMBER, charlie),
            (ActorRole.ANONYMOUS, anon_session),
        ]

        grid_results: List[CellEvaluation] = []
        violations_count = 0

        for op in operations:
            owner_resp = {"id": file_id, "name": "canary.md", "status": "completed"} if dry_run else {}

            for role, actor_session in replayed_actors:
                if dry_run:
                    # Simulation behavior: Enforce 401 for Anonymous, 403 for Intruder & Ex-Member
                    sim_status = 401 if role == ActorRole.ANONYMOUS else 403
                    sim_resp = {"error": "Unauthorized", "code": sim_status}
                    auth_status = AuthorizationStatus.ENFORCED
                    details = f"Blocked with HTTP {sim_status}"
                    cell = CellEvaluation(
                        op_id=op.op_id,
                        op_name=op.name,
                        actor_role=role,
                        http_status=sim_status,
                        auth_status=auth_status,
                        canaries_leaked=[],
                        key_overlap_ratio=0.0,
                        details=details,
                    )
                else:
                    # Live execution: execute HTTP call using actor_session headers
                    url = f"{base}{op.path}"
                    res = adapter._json_request(
                        url=url,
                        method=op.method,
                        data=op.payload,
                        headers=actor_session.headers,
                        timeout=30,
                    )
                    status_code = res.get("code", 200 if "error" not in res else 400)
                    auth_status, leaked, overlap, details = StructuralDiffComparator.evaluate(
                        owner_resp=owner_resp,
                        replayed_status=status_code,
                        replayed_resp=res,
                        replayed_contexts=[],
                        planted_canaries=canaries,
                        engine=self.engine,
                    )
                    cell = CellEvaluation(
                        op_id=op.op_id,
                        op_name=op.name,
                        actor_role=role,
                        http_status=status_code,
                        auth_status=auth_status,
                        canaries_leaked=leaked,
                        key_overlap_ratio=overlap,
                        details=details,
                    )

                if cell.is_violation:
                    violations_count += 1

                grid_results.append(cell)

        return MatrixReport(
            target_name=getattr(adapter, "target_name", "target"),
            target_url=base_url,
            operations=[op.name for op in operations],
            actors=[r[0] for r in replayed_actors],
            grid=grid_results,
            total_violations=violations_count,
            passed=(violations_count == 0),
        )

