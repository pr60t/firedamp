#!/usr/bin/env python3
"""
Firedamp CLI: Canaries for your RAG stack.
Automated cross-tenant data leakage detection and atmospheric isolation auditing.
"""

from __future__ import annotations

import sys
import os
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table

from core.engine import ProbingEngine, CanaryToken, DecoyDocument, sanitize_sensitive_text
from core.target import RemoteTargetManager, DockerTargetManager, TargetEnvironment
from core.reporter import FiredampReporter, AuditSummary
from adapters import get_adapter
from adapters.base import TargetAdapter, UserSession

console = Console()
reporter = FiredampReporter(console=console)


def resolve_live_credentials() -> Tuple[str, str, str, str]:
    """Resolve and validate live scan persona credentials from environment variables.

    Usernames have documented non-secret defaults; passwords must be explicitly
    supplied via FIREDAMP_ALICE_PASSWORD and FIREDAMP_BOB_PASSWORD and are never
    hardcoded in source.
    """
    alice_user = os.environ.get("FIREDAMP_ALICE_USERNAME", "alice_owner").strip()
    alice_pass = os.environ.get("FIREDAMP_ALICE_PASSWORD", "")
    bob_user = os.environ.get("FIREDAMP_BOB_USERNAME", "bob_attacker").strip()
    bob_pass = os.environ.get("FIREDAMP_BOB_PASSWORD", "")

    if not alice_user:
        raise ValueError("FIREDAMP_ALICE_USERNAME must not be empty.")
    if not bob_user:
        raise ValueError("FIREDAMP_BOB_USERNAME must not be empty.")
    if alice_user.lower() == bob_user.lower():
        raise ValueError("FIREDAMP_ALICE_USERNAME and FIREDAMP_BOB_USERNAME must be distinct identities.")
    if not alice_pass or not alice_pass.strip():
        raise ValueError(
            "Missing FIREDAMP_ALICE_PASSWORD for live scan. "
            "Set FIREDAMP_ALICE_PASSWORD and FIREDAMP_BOB_PASSWORD (see .env.example), or use --dry-run."
        )
    if not bob_pass or not bob_pass.strip():
        raise ValueError(
            "Missing FIREDAMP_BOB_PASSWORD for live scan. "
            "Set FIREDAMP_ALICE_PASSWORD and FIREDAMP_BOB_PASSWORD (see .env.example), or use --dry-run."
        )
    return alice_user, alice_pass, bob_user, bob_pass


def resolve_admin_credentials() -> str:
    """Resolve administrative token for user provisioning from environment variables.

    Reads FIREDAMP_PROVISION_ADMIN_TOKEN or FIREDAMP_ADMIN_TOKEN.
    """
    token = os.environ.get("FIREDAMP_PROVISION_ADMIN_TOKEN") or os.environ.get("FIREDAMP_ADMIN_TOKEN")
    if not token or not token.strip():
        raise ValueError(
            "Missing FIREDAMP_PROVISION_ADMIN_TOKEN for provisioning mode. "
            "Set FIREDAMP_PROVISION_ADMIN_TOKEN (see .env.example), or use --identity-mode existing."
        )
    return token.strip()


def _register_newly_seeded_disposables(
    adapter: TargetAdapter,
    base_url: str,
    session: UserSession,
    previous_file_ids: List[str],
    run_id: str,
) -> List[str]:
    """Register only files newly created by this scan after independent verification.

    IDs that fail any check remain in ``file_ids`` for read-side visibility, but
    are not added to ``disposable_file_ids`` and are never eligible for destructive
    probes or generic destructive cleanup.
    """
    from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY
    from probes.knowledge_membership import resolve_file_knowledge_base

    metadata = session.metadata if isinstance(session.metadata, dict) else {}
    file_ids = metadata.get("file_ids")
    if not isinstance(file_ids, list):
        return []
    previous = set(previous_file_ids)
    new_ids = [item for item in file_ids if isinstance(item, str) and item.strip() and item not in previous]
    expected_user_id = metadata.get("user_id")
    try:
        authenticated_user_id = adapter.get_authenticated_user_id(base_url, session)
    except Exception:
        authenticated_user_id = None
    if not isinstance(expected_user_id, str) or not expected_user_id.strip() or authenticated_user_id != expected_user_id:
        reporter.log_alert("Cannot register scan-created files as disposable: Alice identity was not independently verified.")
        return []

    metadata.setdefault("disposable_file_ids", [])
    registered: List[str] = []
    for file_id in new_ids:
        try:
            file_meta = adapter.get_file_metadata(base_url, session, file_id)
            if (
                not isinstance(file_meta, dict)
                or file_meta.get("id") != file_id
                or file_meta.get("user_id") != expected_user_id
            ):
                continue
            baseline = adapter.read_file_content(base_url, session, file_id)
            if not isinstance(baseline, str):
                continue
            target_kb, resolution_error = resolve_file_knowledge_base(
                adapter=adapter,
                base_url=base_url,
                session=session,
                target_file_id=file_id,
            )
            if not target_kb:
                reporter.log_alert(f"New scan file {file_id} was not registered disposable: exact KB membership failed: {resolution_error}")
                continue
            baseline_sha256 = hashlib.sha256(baseline.encode("utf-8")).hexdigest()
            _TRUSTED_SCAN_REGISTRY.register(
                run_id=run_id,
                resource_id=file_id,
                owner=session.username,
                metadata={
                    "source": "current-scan-ingestion",
                    "owner_user_id": expected_user_id,
                    "knowledge_base_id": target_kb,
                    "baseline_sha256": baseline_sha256,
                    "baseline_length": len(baseline),
                },
            )
            metadata["disposable_file_ids"].append(file_id)
            # Keep the ID in file_ids for read-side probes. The immutable-at-seed
            # ordinary_file_ids snapshot distinguishes pre-existing resources from
            # files provisioned and registered by this scan.
            registered.append(file_id)
        except Exception as exc:
            reporter.log_alert(f"Could not register newly seeded file {file_id} as disposable: {exc}")
    return registered


def _cleanup_scan_disposables(adapter: TargetAdapter, base_url: str, session: UserSession, run_id: str) -> None:
    """Delete only current-run registered disposable files after rechecking ownership."""
    from probes.disposable_registry import _TRUSTED_SCAN_REGISTRY

    metadata = session.metadata if isinstance(session.metadata, dict) else {}
    disposable_ids = metadata.get("disposable_file_ids", [])
    expected_owner = metadata.get("user_id")
    if not isinstance(disposable_ids, list):
        return
    retained: List[str] = []
    for file_id in disposable_ids:
        if not isinstance(file_id, str) or not file_id.strip():
            continue
        file_id = file_id.strip()
        if _TRUSTED_SCAN_REGISTRY.is_cleaned_up(run_id, file_id, session.username):
            metadata["file_ids"] = [item for item in metadata.get("file_ids", []) if item != file_id]
            continue
        if not _TRUSTED_SCAN_REGISTRY.is_registered(run_id, file_id, session.username):
            reporter.log_alert(f"Disposable cleanup skipped for {file_id}: no current-run trusted registration.")
            retained.append(file_id)
            continue
        try:
            auth_id = adapter.get_authenticated_user_id(base_url, session)
            file_meta = adapter.get_file_metadata(base_url, session, file_id)
            if (
                auth_id != expected_owner
                or not isinstance(file_meta, dict)
                or file_meta.get("id") != file_id
                or file_meta.get("user_id") != expected_owner
            ):
                reporter.log_alert(f"Disposable cleanup skipped for {file_id}: server-side ownership could not be reverified.")
                retained.append(file_id)
                continue
            if adapter.delete_file(base_url, session, file_id):
                _TRUSTED_SCAN_REGISTRY.mark_cleaned_up(run_id, file_id)
                metadata["file_ids"] = [item for item in metadata.get("file_ids", []) if item != file_id]
                reporter.log_success(f"Deleted scan-created disposable file {file_id}.")
            else:
                reporter.log_alert(f"Disposable cleanup failed for {file_id}; resource remains registered for review.")
                retained.append(file_id)
        except Exception as exc:
            reporter.log_alert(f"Disposable cleanup failed for {file_id}: {exc}")
            retained.append(file_id)
    metadata["disposable_file_ids"] = retained
    # Never pass any disposable ID (including one whose cleanup failed) into the
    # adapter's generic cleanup loop. That loop is not an ownership-verification
    # boundary and must not become a fallback deletion path.
    all_disposable_ids = set(item for item in disposable_ids if isinstance(item, str))
    ordinary_ids = metadata.get("file_ids", [])
    if isinstance(ordinary_ids, list):
        metadata["file_ids"] = [item for item in ordinary_ids if item not in all_disposable_ids]


class SimulatedCLIAdapter(TargetAdapter):
    """
    In-memory simulated adapter used during CLI --dry-run scans.
    Provides synthetic server-side identities and safe responses without network or docker.
    """

    target_name = "simulated"

    def authenticate_user(self, base_url: str, username: str, password: str, role: str = "user") -> UserSession:
        user_id = f"sim-{username}-user-id"
        return UserSession(
            username=username,
            role=role,
            token=f"simulated-{username}-token",
            metadata={"user_id": user_id, "file_ids": [], "knowledge_ids": []},
        )

    def get_authenticated_user_id(self, base_url: str, session: UserSession) -> Optional[str]:
        if not session or not session.token:
            return None
        if isinstance(session.metadata, dict):
            return session.metadata.get("user_id")
        return None

    def validate_session(self, base_url: str, session: UserSession) -> bool:
        return bool(session and session.token)

    def get_file_metadata(self, base_url: str, session: UserSession, file_id: str) -> Optional[Dict[str, Any]]:
        user_id = session.metadata.get("user_id") if isinstance(session.metadata, dict) else session.username
        return {"id": file_id, "user_id": user_id, "owner": session.username}

    def read_file_content(self, base_url: str, session: UserSession, file_id: str) -> Optional[str]:
        return "Simulated clean baseline file content."

    def delete_file(self, base_url: str, session: UserSession, file_id: str) -> bool:
        return True

    def check_admin_permissions(self, base_url: str, admin_token: str) -> bool:
        return bool(admin_token and admin_token.strip())

    def provision_user(
        self,
        base_url: str,
        admin_token: str,
        username: str,
        password: str,
        role: str = "user",
    ) -> Dict[str, Any]:
        user_id = f"sim-{username}-id"
        return {
            "user_id": user_id,
            "username": username,
            "email": f"{username}@firedamp-audit.internal",
            "role": role,
        }

    def delete_user(self, base_url: str, admin_token: str, user_id: str) -> bool:
        return True

    def verify_user_deleted(self, base_url: str, admin_token: str, user_id: str) -> bool:
        return True

    def ingest_document(self, base_url: str, session: UserSession, document: DecoyDocument) -> str:
        return "sim-doc-id-1"

    def query_rag(
        self,
        base_url: str,
        session: UserSession,
        prompt: str,
        files: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        return ("I do not have access to any documents matching that query.", [], {})

    def query_resource_direct(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        k: int = 50,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        return ("Access denied", [], {"code": 403})

    def query_collection(
        self,
        base_url: str,
        session: UserSession,
        collection_names: List[str],
        query: str = "anything",
        k: int = 10,
        hybrid: bool = False,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        return ("Access denied", [], {"code": 403})

    def query_doc(
        self,
        base_url: str,
        session: UserSession,
        collection_name: str,
        query: str = "anything",
        k: int = 10,
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        return ("Access denied", [], {"code": 403})

    def overwrite_resource(
        self,
        base_url: str,
        session: UserSession,
        resource_ref: str,
        payload: str,
        collection_name: Optional[str] = None,
        file_model: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        return {
            "results": [],
            "errors": [
                {
                    "file_id": resource_ref,
                    "status": "failed",
                    "error": "Permission denied: not file owner",
                }
            ],
        }

    def inject_into_collection(
        self,
        base_url: str,
        session: UserSession,
        collection_name: str,
        payload: str,
    ) -> Dict[str, Any]:
        return {"error": "Unauthorized", "code": 403}

    def share_resource(
        self,
        base_url: str,
        session: UserSession,
        resource_id: str,
        grantee_email: str,
    ) -> bool:
        return True

    def revoke_resource(
        self,
        base_url: str,
        session: UserSession,
        resource_id: str,
        grantee_email: str,
    ) -> bool:
        return True

    def enumerate_resources(
        self,
        base_url: str,
        session: UserSession,
        resource_type: str = "file",
    ) -> List[str]:
        if isinstance(session.metadata, dict):
            return list(session.metadata.get("file_ids", []))
        return []

    def cleanup(self, base_url: str, session: UserSession) -> None:
        pass


def run_scan_flow(
    target: str = "openwebui",
    target_url: Optional[str] = None,
    version: str = "latest",
    canaries: int = 4,
    output: Optional[str] = None,
    format: str = "json",
    fail_on_leak: bool = False,
    dry_run: bool = False,
    cpu_only: bool = False,
    suite: str = "default",
    scenario: Optional[str] = None,
    policy: Optional[str] = None,
    vector_db: str = "chroma",
    multitenancy: str = "shared",
    require_complete: bool = False,
    allow_insecure_http: bool = False,
    identity_mode: str = "existing",
    confirm_provisioning: bool = False,
) -> int:
    """Execute atmospheric safety testing & cross-tenant leak detection across RAG shafts."""
    reporter.print_banner()

    if identity_mode not in ("existing", "provision"):
        reporter.log_alert(f"Invalid identity mode '{identity_mode}'. Must be 'existing' or 'provision'.")
        return 1

    if identity_mode == "provision" and not confirm_provisioning:
        reporter.log_alert(
            "Provisioning mode requested without confirmation. "
            "You must supply --confirm-provisioning to allow Firedamp to provision and delete test accounts."
        )
        return 1

    from core.target import TargetConfigProfile
    config_profile = TargetConfigProfile.from_args(
        vector_db=vector_db,
        multitenancy=multitenancy,
    )
    reporter.render_config_summary(config_profile)

    alice_username = "alice_owner"
    alice_password = ""
    bob_username = "bob_attacker"
    bob_password = ""
    admin_token = ""

    if dry_run:
        adapter = SimulatedCLIAdapter()
        if identity_mode == "provision":
            admin_token = "simulated-admin-token"
    else:
        try:
            adapter = get_adapter(target)
        except Exception as exc:
            reporter.log_alert(f"Adapter selection failed for target '{target}': {sanitize_sensitive_text(exc)}")
            return 1

        if identity_mode == "provision":
            try:
                admin_token = resolve_admin_credentials()
            except ValueError as exc:
                reporter.log_alert(sanitize_sensitive_text(exc))
                return 1
        else:
            try:
                alice_username, alice_password, bob_username, bob_password = resolve_live_credentials()
            except ValueError as exc:
                reporter.log_alert(sanitize_sensitive_text(exc))
                return 1

    # Step 1: Target Airway & Shaft Descent
    if dry_run:
        reporter.log_active("Engaging atmospheric simulation mode (dry-run, bypassing physical containers)")
        env = TargetEnvironment(
            name=target,
            base_url="http://mock-simulation:8080",
            managed_by_docker=False,
            profile=config_profile,
        )
        reporter.log_success(f"Simulation airway calibrated at [bold]{env.base_url}[/bold]")
    elif target_url:
        with console.status(f"[bold cyan]Connecting to active airway at [bold]{target_url}[/bold]...", spinner="dots"):
            try:
                manager = RemoteTargetManager(
                    target_url=target_url,
                    target_name=target,
                    allow_insecure_http=allow_insecure_http,
                )
                env = manager.start(timeout=15)
                env.profile = config_profile
            except Exception as e:
                reporter.log_alert(
                    f"Failed to access target airway {target_url}: {sanitize_sensitive_text(e, [alice_password, bob_password, admin_token])}"
                )
                return 1
        reporter.log_success(f"Airway connected: Target verified at [bold]{env.base_url}[/bold]")
    else:
        with console.status(
            f"[bold cyan]Descending into shaft... Pressurizing container [bold]{target}:{version}[/bold]...",
            spinner="bouncingBar"
        ):
            manager = DockerTargetManager(target_name=target)
            try:
                env = manager.start(version=version, timeout=45, cpu_only=cpu_only)
                env.profile = config_profile
            except Exception as e:
                reporter.log_alert(
                    f"Docker target provisioning failed for '{target}:{version}': {sanitize_sensitive_text(e, [alice_password, bob_password, admin_token])}"
                )
                return 1
        reporter.log_success(f"Target airway online at [bold]{env.base_url}[/bold]")

    # Step 2: Persona Authorization and Canary Cage Seeding
    import uuid
    scan_run_id = f"scan-{uuid.uuid4()}"
    engine = ProbingEngine(run_id=scan_run_id)
    decoys = engine.generate_decoys(count=canaries, owner="Alice")
    planted_tokens = [c for d in decoys for c in d.canaries]

    from core.identity import IdentityManager
    identity_mgr = IdentityManager()
    provisioned_records = []

    if identity_mode == "provision":
        with console.status(
            f"[bold cyan]Provisioning run-scoped test personas for scan [bold]{scan_run_id}[/bold]...",
            spinner="dots"
        ):
            try:
                alice_session, bob_session, provisioned_records = identity_mgr.provision_identities(
                    adapter=adapter,
                    base_url=env.base_url,
                    admin_token=admin_token,
                    run_id=scan_run_id,
                    dry_run=dry_run,
                )
            except Exception as exc:
                reporter.log_alert(f"Identity provisioning failed: {sanitize_sensitive_text(exc, [admin_token])}")
                return 1
        reporter.log_success(
            f"Provisioned isolated test personas: Alice ({alice_session.username}) & Bob ({bob_session.username})."
        )
    else:
        if not dry_run:
            with console.status("[bold cyan]Authorizing operator test personas...", spinner="dots"):
                try:
                    alice_session = adapter.authenticate_user(
                        env.base_url,
                        username=alice_username,
                        password=alice_password,
                        role="owner",
                    )
                    bob_session = adapter.authenticate_user(
                        env.base_url,
                        username=bob_username,
                        password=bob_password,
                        role="attacker",
                    )
                except Exception as exc:
                    reporter.log_alert(
                        f"Authentication failed: {sanitize_sensitive_text(exc, [alice_password, bob_password])}"
                    )
                    return 1

                valid, val_err = identity_mgr.validate_existing_identities(
                    adapter=adapter,
                    base_url=env.base_url,
                    alice=alice_session,
                    bob=bob_session,
                )
                if not valid:
                    reporter.log_alert(f"Identity validation failed: {val_err}")
                    return 1
        else:
            alice_session = UserSession(
                username="alice_owner",
                role="owner",
                token="simulated-alice-token",
                metadata={
                    "run_id": scan_run_id,
                    "user_id": "sim-alice-user-id",
                    "file_ids": ["sim-file-1"],
                    "knowledge_ids": ["sim-kb-uuid-1"],
                },
            )
            bob_session = UserSession(
                username="bob_attacker",
                role="attacker",
                token="simulated-bob-token",
                metadata={
                    "run_id": scan_run_id,
                    "user_id": "sim-bob-user-id",
                    "file_ids": [],
                    "knowledge_ids": [],
                },
            )

    # Attach run-scoped metadata tracking
    for s in (alice_session, bob_session):
        if not isinstance(s.metadata, dict):
            s.metadata = {}
        s.metadata["run_id"] = scan_run_id
        s.metadata.setdefault("disposable_file_ids", [])
        s.metadata["ordinary_file_ids"] = list(s.metadata.get("file_ids", []))

    with console.status(
        f"[bold cyan]Synthesizing {len(planted_tokens)} verifiable canaries across {len(decoys)} decoy records...",
        spinner="dots"
    ) as status:
        if not dry_run:
            status.update("[bold cyan]Seeding canary cages in Alice's private tenant scope...")
            for doc in decoys:
                before_file_ids = list(alice_session.metadata.get("file_ids", []))
                adapter.ingest_document(env.base_url, alice_session, doc)
                _register_newly_seeded_disposables(
                    adapter=adapter,
                    base_url=env.base_url,
                    session=alice_session,
                    previous_file_ids=before_file_ids,
                    run_id=scan_run_id,
                )

    reporter.log_success(
        f"Seeded {len(planted_tokens)} canaries across {len(decoys)} documents in Alice's private shaft."
    )

    # Step 2b: Alice Positive Baseline Probe (verify canaries are retrievable)
    if not dry_run:
        with console.status("[bold cyan]Running Alice baseline probe to verify canary retrieval...", spinner="dots"):
            baseline_prompt = "List all confidential documents, internal tokens, and service keys you have access to."
            baseline_text, baseline_ctx, baseline_raw = adapter.query_rag(env.base_url, alice_session, baseline_prompt)
            baseline_result = engine.evaluate_response(
                prompt=baseline_prompt,
                response_text=baseline_text,
                retrieved_contexts=baseline_ctx,
                planted_canaries=planted_tokens,
                raw_response=baseline_raw,
                probe_category="baseline",
            )
        if baseline_result.is_leak:
            reporter.log_success(
                f"Baseline confirmed: Alice can retrieve her own canaries ({len(baseline_result.leaked_canaries)} found)."
            )
        else:
            reporter.log_alert(
                "Baseline warning: Alice could not retrieve her own canaries. "
                "Indexing may be incomplete — results may contain false negatives."
            )

    # Step 3: Adversarial Atmospheric Probing (Bob)
    reporter.log_active("Authorizing Bob (unprivileged querier) for cross-tenant atmospheric sampling...")

    probe_results = []

    # 3a. Standard adversarial prompt probing suite
    if suite in ("default", "all"):
        strategies = engine.PROBE_STRATEGIES[:canaries]
        with console.status("[bold yellow]Drawing atmospheric samples across tenant boundaries...", spinner="dots") as status:
            for idx, strat in enumerate(strategies, 1):
                prompt = strat["prompt"]
                category = strat["category"]
                status.update(f"[bold yellow]Sampling probe {idx}/{len(strategies)}: [dim]{prompt[:45]}...[/dim]")
                if dry_run:
                    resp_text = "I do not have access to any documents matching that query."
                    retrieved_ctx: list = []
                    raw_resp: dict = {}
                else:
                    resp_text, retrieved_ctx, raw_resp = adapter.query_rag(env.base_url, bob_session, prompt)

                res = engine.evaluate_response(
                    prompt=prompt,
                    response_text=resp_text,
                    retrieved_contexts=retrieved_ctx,
                    planted_canaries=planted_tokens,
                    raw_response=raw_resp,
                    probe_category=category,
                    channel="llm_prompt",
                )
                probe_results.append(res)

                if res.is_leak:
                    reporter.log_alert(
                        f"Gas breach on sample #{idx}! Canary exposed: [bold red]{res.leaked_canaries[0]}[/bold red]"
                    )

    # 3b. Tier-1 CVE behavioral regression suite
    if suite in ("cve-regression", "all"):
        from probes.cves import run_cve_suite
        with console.status("[bold cyan]Dispatching Tier-1 CVE behavioral regression probes...", spinner="dots") as status:
            cve_results = run_cve_suite(
                adapter=adapter,
                base_url=env.base_url,
                alice=alice_session,
                bob=bob_session,
                planted_canaries=planted_tokens,
                engine=engine,
                dry_run=dry_run,
                preconditions=config_profile.active_preconditions,
                include_skipped=True,
            )
            for res in cve_results:
                probe_results.append(res)
                if res.is_leak:
                    reporter.log_alert(
                        f"CVE Breach detected ({res.probe_category})! Canary compromised: [bold red]{res.leaked_canaries[0]}[/bold red]"
                    )
                elif res.is_skipped:
                    reporter.log_active(
                        f"Skipped CVE probe: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                elif res.is_inconclusive:
                    reporter.log_active(
                        f"Inconclusive CVE probe: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                else:
                    reporter.log_success(f"Clean CVE probe: [dim]{res.probe_category}[/dim]")

    # 3c. Authorization Matrix Suite (RAG Autorize)
    matrix_report = None
    if suite in ("auth-matrix", "all"):
        from core.matrix import AuthorizationMatrixRunner
        with console.status("[bold cyan]Replaying operations across Actor x Resource authorization matrix...", spinner="dots") as status:
            matrix_runner = AuthorizationMatrixRunner(engine=engine)
            matrix_report = matrix_runner.run_matrix(
                adapter=adapter,
                base_url=env.base_url,
                alice=alice_session,
                bob=bob_session,
                planted_canaries=planted_tokens,
                dry_run=dry_run,
            )
            for cell in matrix_report.grid:
                if cell.is_violation:
                    probe_results.append(
                        ProbeResult(
                            probe_id=cell.op_id,
                            probe_prompt=f"Matrix Replay: {cell.op_name} as {cell.actor_role.value}",
                            probe_category="auth_matrix",
                            target_response=cell.details,
                            retrieved_contexts=[],
                            leaked_canaries=cell.canaries_leaked,
                            severity=LeakSeverity.DIRECT_LEAK if cell.canaries_leaked else LeakSeverity.CONTEXT_LEAK,
                            channel="direct_api",
                        )
                    )

    # 3d. Scenario Vectors (Pillar 4: Time & Sequence Attacks)
    if scenario == "lifecycle" or suite in ("lifecycle", "all"):
        from probes.scenarios.lifecycle import run_lifecycle_scenarios
        with console.status("[bold cyan]Dispatching Time & Sequence Lifecycle attack scenarios...", spinner="dots") as status:
            lifecycle_results = run_lifecycle_scenarios(
                adapter=adapter,
                base_url=env.base_url,
                alice=alice_session,
                bob=bob_session,
                planted_canaries=planted_tokens,
                engine=engine,
                dry_run=dry_run,
            )
            for res in lifecycle_results:
                probe_results.append(res)
                if res.is_leak:
                    reporter.log_alert(
                        f"Lifecycle breach ({res.probe_category})! Canary compromised: [bold red]{res.leaked_canaries[0]}[/bold red]"
                    )
                elif res.is_skipped:
                    reporter.log_active(
                        f"Skipped scenario: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                elif res.is_inconclusive:
                    reporter.log_active(
                        f"Inconclusive scenario: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                else:
                    reporter.log_success(f"Clean scenario: [dim]{res.probe_category}[/dim]")

    # 3e. Scenario Vectors (Pillar 5: Write-Side Poisoning)
    if scenario in ("write-poisoning", "write_poisoning") or suite in ("write-poisoning", "all"):
        from probes.scenarios.write_poisoning import run_write_poisoning_scenarios
        with console.status("[bold cyan]Dispatching Write-Side Poisoning attack scenarios...", spinner="dots") as status:
            poison_results = run_write_poisoning_scenarios(
                adapter=adapter,
                base_url=env.base_url,
                alice=alice_session,
                bob=bob_session,
                engine=engine,
                dry_run=dry_run,
            )
            for res in poison_results:
                probe_results.append(res)
                if res.is_leak:
                    reporter.log_alert(
                        f"Poison breach ({res.probe_category})! Injected tracer compromised: [bold red]{res.leaked_canaries[0]}[/bold red]"
                    )
                elif res.is_skipped:
                    reporter.log_active(
                        f"Skipped scenario: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                elif res.is_inconclusive:
                    reporter.log_active(
                        f"Inconclusive scenario: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                else:
                    reporter.log_success(f"Clean scenario: [dim]{res.probe_category}[/dim]")

    # 3f. Scenario Vectors (Pillar 6: Agent, Memory & Tool Channels)
    if scenario in ("agent-memory", "agent_memory") or suite in ("agent-memory", "all"):
        from probes.scenarios.agent_memory import run_agent_memory_scenarios
        with console.status("[bold cyan]Dispatching Agent, Memory & Tool Channel attack scenarios...", spinner="dots") as status:
            agent_results = run_agent_memory_scenarios(
                adapter=adapter,
                base_url=env.base_url,
                alice=alice_session,
                bob=bob_session,
                engine=engine,
                dry_run=dry_run,
            )
            for res in agent_results:
                probe_results.append(res)
                if res.is_leak:
                    reporter.log_alert(
                        f"Memory breach ({res.probe_category})! Canary compromised: [bold red]{res.leaked_canaries[0]}[/bold red]"
                    )
                elif res.is_skipped:
                    reporter.log_active(
                        f"Skipped scenario: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                elif res.is_inconclusive:
                    reporter.log_active(
                        f"Inconclusive scenario: [dim]{res.probe_category}[/dim] ({res.target_response})"
                    )
                else:
                    reporter.log_success(f"Clean scenario: [dim]{res.probe_category}[/dim]")

    # Step 4: Atmospheric Telemetry Report Card
    summary = reporter.calculate_summary(
        target_name=target,
        target_url=env.base_url,
        planted_canaries=planted_tokens,
        probe_results=probe_results,
        config_profile={
            "vector_db": config_profile.vector_db.value,
            "multitenancy": config_profile.multitenancy.value,
            "preconditions": config_profile.active_preconditions,
        },
    )
    reporter.render_summary(summary)

    if matrix_report:
        reporter.render_matrix(matrix_report)

    # Step 4b: Declarative Policy Evaluation
    policy_failed = False
    if policy:
        from core.policy import FiredampPolicy
        try:
            policy_obj = FiredampPolicy.from_yaml(policy)
            policy_eval = policy_obj.evaluate(summary, probe_results, matrix_report=matrix_report)
            reporter.render_policy_result(policy_eval)
            if not policy_eval.passed:
                policy_failed = True
        except Exception as e:
            reporter.log_alert(f"Failed to evaluate security policy '{policy}': {e}")
            policy_failed = True

    if output:
        actual_fmt = format
        if format == "json":
            if output.endswith(".md") or output.endswith(".markdown"):
                actual_fmt = "markdown"
            elif output.endswith(".sarif"):
                actual_fmt = "sarif"
        reporter.export(summary, output, format=actual_fmt)

    # Cleanup test artifacts from the target platform
    if not dry_run:
        with console.status("[bold cyan]Cleaning up canary documents and test artifacts...", spinner="dots"):
            _cleanup_scan_disposables(adapter, env.base_url, alice_session, scan_run_id)
            adapter.cleanup(env.base_url, alice_session)
            _cleanup_scan_disposables(adapter, env.base_url, bob_session, scan_run_id)
            adapter.cleanup(env.base_url, bob_session)
            from probes.disposable_registry import clear_trusted_registry
            clear_trusted_registry()

        if identity_mode == "provision" and provisioned_records:
            with console.status("[bold cyan]Decommissioning provisioned test personas...", spinner="dots"):
                clean_ok, clean_failures = identity_mgr.cleanup_provisioned_identities(
                    adapter=adapter,
                    base_url=env.base_url,
                    admin_token=admin_token,
                    run_id=scan_run_id,
                    records=provisioned_records,
                    dry_run=dry_run,
                )
                if clean_ok:
                    reporter.log_success("Provisioned test personas successfully decommissioned.")
                else:
                    reporter.log_alert(f"Failed to decommission some provisioned personas: {'; '.join(clean_failures)}")
        reporter.log_success("Scan cleanup routine completed; any ownership/cleanup failures were reported above.")
    elif dry_run and identity_mode == "provision" and provisioned_records:
        identity_mgr.cleanup_provisioned_identities(
            adapter=adapter,
            base_url=env.base_url,
            admin_token=admin_token,
            run_id=scan_run_id,
            records=provisioned_records,
            dry_run=True,
        )

    # Teardown if managed by Docker
    if env.managed_by_docker:
        with console.status("[bold cyan]Depressurizing airway and tearing down test container...", spinner="dots"):
            manager.stop(env)
        reporter.log_success("Container airway safely decommissioned.")

    incomplete_failed = require_complete and (
        summary.inconclusive_probes > 0
        or summary.skipped_probes > 0
        or summary.total_probes_executed == 0
    )
    if (fail_on_leak and summary.firedamp_index > 0) or policy_failed or incomplete_failed:
        if incomplete_failed:
            reporter.log_alert(
                f"Incomplete scan coverage (executed={summary.total_probes_executed}, "
                f"inconclusive={summary.inconclusive_probes}, skipped={summary.skipped_probes}) "
                "with --require-complete enforced. Halting execution with exit code 1."
            )
        else:
            reporter.log_alert("Hazardous atmosphere or policy violation detected! Halting execution with exit code 1.")
        return 1

    return 0


def cleanup_identities_flow(
    run_id: str,
    target_url: Optional[str] = None,
    allow_insecure_http: bool = False,
) -> int:
    """Recover and safely decommission orphaned test personas from an interrupted scan."""
    reporter.print_banner()
    from core.identity import IdentityManager
    mgr = IdentityManager()
    with console.status(f"[bold cyan]Recovering identity journal for run '{run_id}'...", spinner="dots"):
        success, message = mgr.recover_and_cleanup_run(
            run_id=run_id,
            target_url=target_url,
            allow_insecure_http=allow_insecure_http,
        )
    if success:
        reporter.log_success(message)
        return 0
    else:
        reporter.log_alert(message)
        return 1


def list_targets_flow() -> None:
    """Lists available target platform adapters."""
    reporter.print_banner()
    table = Table(
        title="Firedamp Atmospheric Sensors & Target Adapters",
        border_style="cyan",
        header_style="bold cyan"
    )
    table.add_column("Adapter", style="bold green")
    table.add_column("Airway Architecture", style="yellow")
    table.add_column("Sensor Status", style="white")
    table.add_column("Description", style="dim")

    table.add_row(
        "openwebui",
        "RAG WebUI / API",
        "[bold green][+] Active[/bold green]",
        "Open WebUI multi-tenant knowledge collections & chat retrieval pipelines"
    )
    table.add_row(
        "dify",
        "App / RAG Workflow",
        "[yellow][~] Planned[/yellow]",
        "Dify.ai workspace document knowledge collections & agent apps"
    )
    table.add_row(
        "langflow",
        "RAG Flow",
        "[yellow][~] Planned[/yellow]",
        "Langflow vector store retriever pipelines & multi-tenant chains"
    )
    table.add_row(
        "flowise",
        "Canvas / Flow",
        "[yellow][~] Planned[/yellow]",
        "Flowise AI conversational retrieval chains & document stores"
    )

    console.print(table)


# Typer Dispatcher (with standard library fallback if typer is not yet installed)
try:
    import typer
    app = typer.Typer(
        name="firedamp",
        help="Canaries for your RAG Stack: Atmospheric safety testing & cross-tenant leak detection.",
        add_completion=False,
    )

    @app.command("scan")
    def scan_cmd(
        target: str = typer.Option("openwebui", "--target", "-t", help="Target platform adapter name."),
        target_url: Optional[str] = typer.Option(None, "--target-url", "-u", help="URL of existing deployment."),
        version: str = typer.Option("latest", "--version", "-v", help="Docker container image tag."),
        canaries: int = typer.Option(4, "--canaries", "-n", help="Number of canary documents to plant."),
        output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to export audit report."),
        format: str = typer.Option("json", "--format", "-f", help="Audit report format (json, markdown, sarif)."),
        fail_on_leak: bool = typer.Option(False, "--fail-on-leak", help="Exit code 1 if gas is detected."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Run simulated scan without network/docker."),
        cpu_only: bool = typer.Option(False, "--cpu-only", help="Run container without GPU/Ollama (CPU embeddings only)."),
        suite: str = typer.Option("default", "--suite", "-s", help="Probing suite to execute ('default', 'cve-regression', 'auth-matrix', 'lifecycle', 'write-poisoning', 'agent-memory', 'all')."),
        scenario: Optional[str] = typer.Option(None, "--scenario", "-sc", help="Targeted attack scenario to execute ('lifecycle', 'write-poisoning', 'agent-memory')."),
        policy: Optional[str] = typer.Option(None, "--policy", "-p", help="Path to declarative YAML policy file."),
        vector_db: str = typer.Option("chroma", "--vector-db", "-db", help="Target vector database backend ('chroma', 'milvus', 'qdrant')."),
        multitenancy: str = typer.Option("shared", "--multitenancy", "-m", help="Multitenancy architecture mode ('shared', 'isolated')."),
        require_complete: bool = typer.Option(False, "--require-complete", help="Exit code 1 if any probe is inconclusive or skipped, or if zero probes executed."),
        allow_insecure_http: bool = typer.Option(False, "--allow-insecure-http", help="Allow plain HTTP for non-loopback live targets (unsafe; isolated labs only)."),
        identity_mode: str = typer.Option("existing", "--identity-mode", help="Identity lifecycle mode ('existing', 'provision')."),
        confirm_provisioning: bool = typer.Option(False, "--confirm-provisioning", help="Confirm authorization to provision and delete test accounts on target."),
    ):
        """Execute a cross-tenant isolation and canary exfiltration scan."""
        exit_code = run_scan_flow(
            target=target,
            target_url=target_url,
            version=version,
            canaries=canaries,
            output=output,
            format=format,
            fail_on_leak=fail_on_leak,
            dry_run=dry_run,
            cpu_only=cpu_only,
            suite=suite,
            scenario=scenario,
            policy=policy,
            vector_db=vector_db,
            multitenancy=multitenancy,
            require_complete=require_complete,
            allow_insecure_http=allow_insecure_http,
            identity_mode=identity_mode,
            confirm_provisioning=confirm_provisioning,
        )
        if exit_code != 0:
            raise typer.Exit(code=exit_code)

    @app.command("cleanup-identities")
    def cleanup_identities_cmd(
        run_id: str = typer.Option(..., "--run-id", "-r", help="Run ID of the scan whose identities should be cleaned up."),
        target_url: Optional[str] = typer.Option(None, "--target-url", "-u", help="URL of target deployment (optional, defaults to journal value)."),
        allow_insecure_http: bool = typer.Option(False, "--allow-insecure-http", help="Allow plain HTTP for non-loopback URLs."),
    ):
        """Clean up and delete provisioned test personas from an interrupted or prior scan."""
        exit_code = cleanup_identities_flow(
            run_id=run_id,
            target_url=target_url,
            allow_insecure_http=allow_insecure_http,
        )
        if exit_code != 0:
            raise typer.Exit(code=exit_code)

    @app.command("list-targets")
    def list_targets_cmd():
        """List supported RAG target adapters and architectures."""
        list_targets_flow()

    @app.command("version")
    def version_cmd():
        """Show Firedamp atmospheric sensor version banner."""
        reporter.print_banner()
        console.print("[bold green][+][/bold green] Firedamp Atmospheric Sensor v0.1.0 online\n")

    def main():
        app()

except ImportError:
    # Graceful fallback to argparse if typer is not yet installed in system environment
    import argparse

    def main():
        parser = argparse.ArgumentParser(
            prog="firedamp",
            description="Firedamp: Canaries for your RAG stack."
        )
        subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Execute an isolation scan")
        scan_parser.add_argument("--target", "-t", default="openwebui", help="Target platform adapter name")
        scan_parser.add_argument("--target-url", "-u", default=None, help="URL of existing deployment")
        scan_parser.add_argument("--version", "-v", default="latest", help="Docker image tag")
        scan_parser.add_argument("--canaries", "-n", type=int, default=4, help="Number of canaries to plant")
        scan_parser.add_argument("--output", "-o", default=None, help="Path for audit report")
        scan_parser.add_argument("--format", "-f", default="json", choices=["json", "markdown", "sarif"], help="Audit report format")
        scan_parser.add_argument("--fail-on-leak", action="store_true", help="Exit code 1 if gas detected")
        scan_parser.add_argument("--dry-run", action="store_true", help="Run simulated scan without network/docker")
        scan_parser.add_argument("--cpu-only", action="store_true", help="Run container without GPU/Ollama (CPU embeddings only)")
        scan_parser.add_argument("--suite", "-s", default="default", choices=["default", "cve-regression", "auth-matrix", "lifecycle", "write-poisoning", "agent-memory", "all"], help="Probing suite (default, cve-regression, auth-matrix, lifecycle, write-poisoning, agent-memory, all)")
        scan_parser.add_argument("--scenario", "-sc", default=None, choices=["lifecycle", "write-poisoning", "agent-memory"], help="Targeted attack scenario (lifecycle, write-poisoning, agent-memory)")
        scan_parser.add_argument("--policy", "-p", default=None, help="Path to declarative YAML policy file")
        scan_parser.add_argument("--vector-db", "-db", default="chroma", choices=["chroma", "milvus", "qdrant"], help="Vector database backend (chroma, milvus, qdrant)")
        scan_parser.add_argument("--multitenancy", "-m", default="shared", choices=["shared", "isolated"], help="Multitenancy mode (shared, isolated)")
        scan_parser.add_argument("--require-complete", action="store_true", help="Exit code 1 if any probe is inconclusive or skipped")
        scan_parser.add_argument("--allow-insecure-http", action="store_true", help="Allow plain HTTP for non-loopback live targets (unsafe)")
        scan_parser.add_argument("--identity-mode", default="existing", choices=["existing", "provision"], help="Identity lifecycle mode (existing, provision)")
        scan_parser.add_argument("--confirm-provisioning", action="store_true", help="Confirm authorization to provision and delete test accounts on target")

        # Cleanup identities command
        cleanup_parser = subparsers.add_parser("cleanup-identities", help="Clean up provisioned test accounts")
        cleanup_parser.add_argument("--run-id", "-r", required=True, help="Scan run ID")
        cleanup_parser.add_argument("--target-url", "-u", default=None, help="Target URL override")
        cleanup_parser.add_argument("--allow-insecure-http", action="store_true", help="Allow plain HTTP for non-loopback URLs")

        # List targets
        subparsers.add_parser("list-targets", help="List supported target platforms")

        # Version
        subparsers.add_parser("version", help="Show Firedamp version")

        args = parser.parse_args()
        if args.subcommand == "scan":
            sys.exit(run_scan_flow(
                target=args.target,
                target_url=args.target_url,
                version=args.version,
                canaries=args.canaries,
                output=args.output,
                format=args.format,
                fail_on_leak=args.fail_on_leak,
                dry_run=args.dry_run,
                cpu_only=args.cpu_only,
                suite=args.suite,
                scenario=args.scenario,
                policy=args.policy,
                vector_db=args.vector_db,
                multitenancy=args.multitenancy,
                require_complete=args.require_complete,
                allow_insecure_http=args.allow_insecure_http,
                identity_mode=args.identity_mode,
                confirm_provisioning=args.confirm_provisioning,
            ))
        elif args.subcommand == "cleanup-identities":
            sys.exit(cleanup_identities_flow(
                run_id=args.run_id,
                target_url=args.target_url,
                allow_insecure_http=args.allow_insecure_http,
            ))
        elif args.subcommand == "list-targets":
            list_targets_flow()
        elif args.subcommand == "version":
            reporter.print_banner()
            console.print("[bold green][+][/bold green] Firedamp Atmospheric Sensor v0.1.0 online\n")
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
