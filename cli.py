#!/usr/bin/env python3
"""
Firedamp CLI: Canaries for your RAG stack.
Automated cross-tenant data leakage detection and atmospheric isolation auditing.
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table

from core.engine import ProbingEngine, CanaryToken
from core.target import RemoteTargetManager, DockerTargetManager, TargetEnvironment
from core.reporter import FiredampReporter, AuditSummary
from adapters import get_adapter

console = Console()
reporter = FiredampReporter(console=console)


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
) -> int:
    """Execute atmospheric safety testing & cross-tenant leak detection across RAG shafts."""
    reporter.print_banner()

    from core.target import TargetConfigProfile
    config_profile = TargetConfigProfile.from_args(
        vector_db=vector_db,
        multitenancy=multitenancy,
    )
    reporter.render_config_summary(config_profile)

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
            manager = RemoteTargetManager(target_url=target_url, target_name=target)
            try:
                env = manager.start(timeout=15)
                env.profile = config_profile
            except Exception as e:
                reporter.log_alert(f"Failed to access target airway {target_url}: {e}")
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
                reporter.log_active(f"Docker provisioning note: {e}")
                reporter.log_active("Falling back to local atmospheric simulation...")
                env = TargetEnvironment(
                    name=target,
                    base_url="http://localhost:8080",
                    managed_by_docker=False,
                    profile=config_profile,
                )
        reporter.log_success(f"Target airway online at [bold]{env.base_url}[/bold]")

    # Step 2: Canary Cage Seeding (Alice)
    engine = ProbingEngine()
    decoys = engine.generate_decoys(count=canaries, owner="Alice")
    planted_tokens = [c for d in decoys for c in d.canaries]

    with console.status(
        f"[bold cyan]Synthesizing {len(planted_tokens)} verifiable canaries across {len(decoys)} decoy records...",
        spinner="dots"
    ) as status:
        try:
            adapter = get_adapter(target)
        except Exception:
            from adapters.openwebui import OpenWebUIAdapter
            adapter = OpenWebUIAdapter()

        if not dry_run:
            status.update("[bold cyan]Authorizing Alice session & seeding canary cages in private tenant scope...")
            alice_session = adapter.authenticate_user(
                env.base_url,
                username="alice_owner",
                password="AegisPassword!123",
                role="owner"
            )
            for doc in decoys:
                adapter.ingest_document(env.base_url, alice_session, doc)
        else:
            from adapters.base import UserSession
            alice_session = UserSession(
                username="alice_owner",
                role="owner",
                token="simulated-alice-token",
                metadata={"file_ids": ["sim-file-1"], "knowledge_ids": ["sim-kb-uuid-1"]},
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
    if not dry_run:
        bob_session = adapter.authenticate_user(
            env.base_url,
            username="bob_attacker",
            password="BobPassword!456",
            role="attacker"
        )
    else:
        from adapters.base import UserSession
        bob_session = UserSession(
            username="bob_attacker",
            role="attacker",
            token="simulated-bob-token",
            metadata={"file_ids": [], "knowledge_ids": []},
        )

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
            )
            for res in cve_results:
                probe_results.append(res)
                if res.is_leak:
                    reporter.log_alert(
                        f"CVE Breach detected ({res.probe_category})! Canary compromised: [bold red]{res.leaked_canaries[0]}[/bold red]"
                    )
                else:
                    reporter.log_success(f"Passed CVE probe: [dim]{res.probe_category}[/dim]")

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
                else:
                    reporter.log_success(f"Passed scenario: [dim]{res.probe_category}[/dim]")

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
                else:
                    reporter.log_success(f"Passed scenario: [dim]{res.probe_category}[/dim]")

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
                else:
                    reporter.log_success(f"Passed scenario: [dim]{res.probe_category}[/dim]")

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
            adapter.cleanup(env.base_url, alice_session)
        reporter.log_success("Test artifacts removed from target.")

    # Teardown if managed by Docker
    if env.managed_by_docker:
        with console.status("[bold cyan]Depressurizing airway and tearing down test container...", spinner="dots"):
            manager.stop(env)
        reporter.log_success("Container airway safely decommissioned.")

    if (fail_on_leak and summary.firedamp_index > 0) or policy_failed:
        reporter.log_alert("Hazardous atmosphere or policy violation detected! Halting execution with exit code 1.")
        return 1

    return 0


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
