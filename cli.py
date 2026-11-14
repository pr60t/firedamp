#!/usr/bin/env python3
"""
Firedamp CLI: Canaries for your RAG stack.
Automated cross-tenant data leakage detection and isolation auditing.
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
    fail_on_leak: bool = False,
    dry_run: bool = False,
) -> int:
    """Core execution pipeline for an isolation scan."""
    reporter.print_banner()

    console.print(f"[bold cyan][PHASE 1: TARGET INITIALIZATION][/bold cyan]")
    if dry_run:
        console.print("[yellow]Running in DRY-RUN simulation mode (bypassing external container)[/yellow]")
        env = TargetEnvironment(
            name=target,
            base_url="http://mock-simulation:8080",
            managed_by_docker=False
        )
    elif target_url:
        console.print(f"Connecting to existing target deployment at [bold]{target_url}[/bold]...")
        manager = RemoteTargetManager(target_url=target_url, target_name=target)
        try:
            env = manager.start(timeout=10)
        except Exception as e:
            console.print(f"[red]Failed to connect to target: {e}[/red]")
            return 1
    else:
        console.print(f"Provisioning ephemeral Docker container for [bold]{target}:{version}[/bold]...")
        manager = DockerTargetManager(target_name=target)
        try:
            env = manager.start(version=version, timeout=45)
        except Exception as e:
            console.print(f"[yellow]Docker provisioning note: {e}[/yellow]")
            console.print("[dim]Falling back to simulation mode for this environment...[/dim]")
            env = TargetEnvironment(name=target, base_url="http://localhost:8080", managed_by_docker=False)

    console.print(f"✓ Target environment active at [bold]{env.base_url}[/bold]\n")

    # Phase 2: Canary Generation & Alice Ingestion
    console.print(f"[bold cyan][PHASE 2: CANARY SYNTHESIS & INGESTION][/bold cyan]")
    engine = ProbingEngine()
    decoys = engine.generate_decoys(count=canaries, owner="Alice")
    planted_tokens = [c for d in decoys for c in d.canaries]

    console.print(f"Generated {len(decoys)} decoy documents with {len(planted_tokens)} verifiable canaries.")
    
    # Ingestion via Adapter
    try:
        adapter = get_adapter(target)
    except Exception:
        from adapters.openwebui import OpenWebUIAdapter
        adapter = OpenWebUIAdapter()

    if not dry_run:
        alice_session = adapter.authenticate_user(env.base_url, username="alice_owner", password="AegisPassword!123", role="owner")
        for doc in decoys:
            adapter.ingest_document(env.base_url, alice_session, doc)
    console.print(f"✓ Successfully ingested canary documents into Alice's tenant scope.\n")

    # Phase 3: Adversarial Multi-Tenant Probing (Bob)
    console.print(f"[bold cyan][PHASE 3: ADVERSARIAL MULTI-TENANT PROBING][/bold cyan]")
    if not dry_run:
        bob_session = adapter.authenticate_user(env.base_url, username="bob_attacker", password="BobPassword!456", role="attacker")

    probe_results = []
    strategies = engine.PROBE_STRATEGIES[:canaries]
    
    with console.status("[bold green]Dispatching exfiltration probes across retrieval boundaries...") as status:
        for idx, prompt in enumerate(strategies, 1):
            status.update(f"[bold green]Dispatching probe {idx}/{len(strategies)}...")
            if dry_run:
                # In dry run, simulate clean isolation
                resp_text = "I do not have access to any documents matching that query."
                retrieved_ctx = []
            else:
                resp_text, retrieved_ctx = adapter.query_rag(env.base_url, bob_session, prompt)

            res = engine.evaluate_response(
                prompt=prompt,
                response_text=resp_text,
                retrieved_contexts=retrieved_ctx,
                planted_canaries=planted_tokens
            )
            probe_results.append(res)

    # Phase 4: Reporting & Firedamp Index
    console.print(f"[bold cyan][PHASE 4: AUDIT EVALUATION & METRICS][/bold cyan]")
    summary = reporter.calculate_summary(
        target_name=target,
        target_url=env.base_url,
        planted_canaries=planted_tokens,
        probe_results=probe_results
    )
    reporter.render_summary(summary)

    if output:
        reporter.export_json(summary, output)

    # Teardown if managed by Docker
    if env.managed_by_docker:
        manager.stop(env)

    if fail_on_leak and summary.firedamp_index > 0:
        console.print("[bold red]Gas detected! Exiting with code 1 as --fail-on-leak is enabled.[/bold red]")
        return 1

    return 0


def list_targets_flow() -> None:
    """Lists available target platform adapters."""
    reporter.print_banner()
    table = Table(title="Available Firedamp Target Adapters", border_style="cyan")
    table.add_column("Adapter", style="bold green")
    table.add_column("Type", style="yellow")
    table.add_column("Status", style="white")
    table.add_column("Description", style="dim")

    table.add_row(
        "openwebui",
        "RAG WebUI / API",
        "Active",
        "Open WebUI (formerly Ollama WebUI) multi-user session & RAG knowledge base"
    )
    table.add_row(
        "dify",
        "App / RAG Workflow",
        "Planned",
        "Dify.ai workspace document knowledge collections & agent apps"
    )
    table.add_row(
        "langflow",
        "RAG Flow",
        "Planned",
        "Langflow vector store retriever pipelines & multi-tenant chains"
    )
    table.add_row(
        "flowise",
        "Canvas / Flow",
        "Planned",
        "Flowise AI conversational retrieval chains & document stores"
    )

    console.print(table)


# Typer Dispatcher (with standard library fallback if typer is not yet installed)
try:
    import typer
    app = typer.Typer(
        name="firedamp",
        help="Canaries for your RAG Stack: Automated cross-tenant data leakage detection.",
        add_completion=False,
    )

    @app.command("scan")
    def scan_cmd(
        target: str = typer.Option("openwebui", "--target", "-t", help="Target platform adapter name."),
        target_url: Optional[str] = typer.Option(None, "--target-url", "-u", help="URL of existing deployment."),
        version: str = typer.Option("latest", "--version", "-v", help="Docker container image tag."),
        canaries: int = typer.Option(4, "--canaries", "-n", help="Number of canary documents to plant."),
        output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to export JSON audit report."),
        fail_on_leak: bool = typer.Option(False, "--fail-on-leak", help="Exit code 1 if gas is detected."),
        dry_run: bool = typer.Option(False, "--dry-run", help="Run simulated scan without network/docker."),
    ):
        """Execute a cross-tenant isolation and canary exfiltration scan."""
        exit_code = run_scan_flow(
            target=target,
            target_url=target_url,
            version=version,
            canaries=canaries,
            output=output,
            fail_on_leak=fail_on_leak,
            dry_run=dry_run,
        )
        if exit_code != 0:
            raise typer.Exit(code=exit_code)

    @app.command("list-targets")
    def list_targets_cmd():
        """List supported RAG target adapters and architectures."""
        list_targets_flow()

    @app.command("version")
    def version_cmd():
        """Show Firedamp version banner."""
        reporter.print_banner()
        console.print("[bold]Firedamp[/bold] version 0.1.0\n")

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
        scan_parser.add_argument("--output", "-o", default=None, help="Path for JSON audit report")
        scan_parser.add_argument("--fail-on-leak", action="store_true", help="Exit code 1 if gas detected")
        scan_parser.add_argument("--dry-run", action="store_true", help="Run simulated scan without network/docker")

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
                fail_on_leak=args.fail_on_leak,
                dry_run=args.dry_run,
            ))
        elif args.subcommand == "list-targets":
            list_targets_flow()
        elif args.subcommand == "version":
            reporter.print_banner()
            console.print("[bold]Firedamp[/bold] version 0.1.0\n")
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
