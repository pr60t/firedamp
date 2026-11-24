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
    INCONCLUSIVE = "INCONCLUSIVE"    # Owner baseline or required target could not be verified


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

    @property
    def is_inconclusive(self) -> bool:
        return self.auth_status == AuthorizationStatus.INCONCLUSIVE


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
    inconclusive_count: int = 0


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
        """Run read-only authorization checks after capturing an owner baseline.

        Destructive overwrite and DELETE operations are intentionally excluded from
        this matrix. They require a dedicated disposable-resource lifecycle and are
        exercised by separately guarded probes.
        """
        base = base_url.rstrip("/")
        canaries = planted_canaries or []
        anon_session = UserSession(username="anonymous", role="anonymous", token=None, headers={})
        if not charlie:
            charlie = UserSession(
                username="charlie_exmember",
                role="exmember",
                token="charlie-revoked-token" if dry_run else None,
                headers={"Authorization": "Bearer charlie-revoked-token"} if dry_run else {},
            )

        alice_metadata = alice.metadata if isinstance(alice.metadata, dict) else {}
        alice_file_ids = alice_metadata.get("file_ids", [])
        alice_kb_ids = alice_metadata.get("knowledge_ids", [])
        file_id = alice_file_ids[0] if isinstance(alice_file_ids, list) and alice_file_ids else None
        kb_id = alice_kb_ids[0] if isinstance(alice_kb_ids, list) and alice_kb_ids else None

        replayed_actors = [
            (ActorRole.INTRUDER, bob),
            (ActorRole.EX_MEMBER, charlie),
            (ActorRole.ANONYMOUS, anon_session),
        ]

        def inconclusive_report(reason: str) -> MatrixReport:
            cells = [
                CellEvaluation(
                    op_id="matrix_precondition",
                    op_name="Read-only matrix precondition",
                    actor_role=role,
                    http_status=0,
                    auth_status=AuthorizationStatus.INCONCLUSIVE,
                    details=reason,
                )
                for role, _ in replayed_actors
            ]
            return MatrixReport(
                target_name=getattr(adapter, "target_name", "target"),
                target_url=base_url,
                operations=["Read-only matrix precondition"],
                actors=[role for role, _ in replayed_actors],
                grid=cells,
                total_violations=0,
                passed=False,
                inconclusive_count=len(cells),
            )

        if not dry_run:
            if not isinstance(file_id, str) or not file_id.strip():
                return inconclusive_report("INCONCLUSIVE: Alice has no verified file ID; no placeholder target will be used.")
            file_id = file_id.strip()
            # Resolve the exact KB containing this file. A first-KB heuristic can compare
            # the file against an unrelated collection and create misleading baselines.
            try:
                from probes.knowledge_membership import resolve_file_knowledge_base
                resolved_kb, resolution_error = resolve_file_knowledge_base(
                    adapter=adapter,
                    base_url=base,
                    session=alice,
                    target_file_id=file_id,
                )
            except Exception as exc:
                resolved_kb, resolution_error = None, str(exc)
            if not resolved_kb:
                return inconclusive_report(
                    f"INCONCLUSIVE: Exact file-to-KB membership could not be established: {resolution_error}"
                )
            kb_id = resolved_kb
        else:
            file_id = file_id if isinstance(file_id, str) and file_id else "dry-run-file"
            kb_id = kb_id if isinstance(kb_id, str) and kb_id else "dry-run-kb"

        # Only read-only operations are included. The vector retrieval endpoint
        # uses POST but performs a query; chat/completion and all mutation routes are excluded.
        operations: List[RecordedOperation] = [
            RecordedOperation(
                op_id="op_file_inspect",
                name="File Metadata (GET /api/v1/files/{id})",
                method="GET",
                path=f"/api/v1/files/{file_id}",
            ),
            RecordedOperation(
                op_id="op_file_content",
                name="Indexed File Content (GET /api/v1/files/{id}/data/content)",
                method="GET",
                path=f"/api/v1/files/{file_id}/data/content",
            ),
            RecordedOperation(
                op_id="op_kb_inspect",
                name="Knowledge Base (GET /api/v1/knowledge/{id})",
                method="GET",
                path=f"/api/v1/knowledge/{kb_id}",
            ),
            RecordedOperation(
                op_id="op_vector_query",
                name="Vector Retrieval Query (POST /api/v1/retrieval/query/collection)",
                method="POST",
                path="/api/v1/retrieval/query/collection",
                payload={"collection_names": [kb_id], "query": "canary confidential summary", "k": 10},
            ),
        ]

        grid_results: List[CellEvaluation] = []
        violations_count = 0
        inconclusive_count = 0

        for op in operations:
            if dry_run:
                owner_resp = {"id": file_id, "name": "canary.md", "status": "completed"}
                owner_status = 200
            else:
                # Capture a positive, authorized baseline for this exact operation.
                try:
                    owner_raw = adapter._json_request(
                        url=f"{base}{op.path}",
                        method=op.method,
                        data=op.payload,
                        headers=alice.headers,
                        timeout=30,
                    )
                except Exception as exc:
                    owner_raw = {"error": str(exc), "code": 0}
                if isinstance(owner_raw, dict) and "error" not in owner_raw:
                    owner_resp = owner_raw
                    owner_status = owner_raw.get("code", 200)
                else:
                    # Malformed/non-dict owner responses cannot establish a usable baseline.
                    owner_resp = owner_raw if isinstance(owner_raw, dict) else {"error": "Malformed owner baseline response"}
                    owner_status = owner_raw.get("code", 400) if isinstance(owner_raw, dict) else 0

                if not isinstance(owner_status, int) or owner_status < 200 or owner_status >= 300 or "error" in owner_resp:
                    for role, _actor_session in replayed_actors:
                        grid_results.append(CellEvaluation(
                            op_id=op.op_id,
                            op_name=op.name,
                            actor_role=role,
                            http_status=owner_status if isinstance(owner_status, int) else 0,
                            auth_status=AuthorizationStatus.INCONCLUSIVE,
                            details=f"INCONCLUSIVE: Owner baseline could not be established for this operation: {owner_resp.get('error', 'unexpected owner response')}",
                        ))
                        inconclusive_count += 1
                    continue

            for role, actor_session in replayed_actors:
                if dry_run:
                    sim_status = 401 if role == ActorRole.ANONYMOUS else 403
                    sim_resp = {"error": "Unauthorized", "code": sim_status}
                    auth_status = AuthorizationStatus.ENFORCED
                    leaked: List[str] = []
                    overlap = 0.0
                    details = f"Blocked with HTTP {sim_status}"
                    status_code = sim_status
                else:
                    try:
                        replayed_raw = adapter._json_request(
                            url=f"{base}{op.path}",
                            method=op.method,
                            data=op.payload,
                            headers=actor_session.headers,
                            timeout=30,
                        )
                    except Exception as exc:
                        replayed_raw = {"error": str(exc), "code": 0}
                    if isinstance(replayed_raw, dict):
                        sim_resp = replayed_raw
                        status_code = replayed_raw.get("code", 400 if "error" in replayed_raw else 200)
                    else:
                        sim_resp = {"response": replayed_raw}
                        status_code = 200
                    if not isinstance(status_code, int):
                        status_code = 0
                    auth_status, leaked, overlap, details = StructuralDiffComparator.evaluate(
                        owner_resp=owner_resp,
                        replayed_status=status_code,
                        replayed_resp=sim_resp,
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
                if cell.is_inconclusive:
                    inconclusive_count += 1
                grid_results.append(cell)

        passed = violations_count == 0 and inconclusive_count == 0 and all(
            cell.auth_status == AuthorizationStatus.ENFORCED for cell in grid_results
        )
        return MatrixReport(
            target_name=getattr(adapter, "target_name", "target"),
            target_url=base_url,
            operations=[op.name for op in operations],
            actors=[role for role, _ in replayed_actors],
            grid=grid_results,
            total_violations=violations_count,
            passed=passed,
            inconclusive_count=inconclusive_count,
        )

