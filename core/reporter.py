"""
Reporting Engine & Firedamp Index Calculation.
Formats audit results, computes isolation risk scores, and outputs Rich UI telemetry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .engine import ProbeResult, LeakSeverity, CanaryToken


@dataclass
class AuditSummary:
    """Quantitative summary of an isolation audit."""
    target_name: str
    target_url: str
    total_canaries_planted: int
    total_probes_dispatched: int
    total_leaks_detected: int
    direct_leaks: int
    context_leaks: int
    firedamp_index: float
    status: str
    timestamp: str = datetime.now(timezone.utc).isoformat()
    probe_results: List[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


class FiredampReporter:
    """Handles terminal rendering and JSON export for RAG isolation audits."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def calculate_summary(
        self,
        target_name: str,
        target_url: str,
        planted_canaries: List[CanaryToken],
        probe_results: List[ProbeResult],
    ) -> AuditSummary:
        total_probes = len(probe_results)
        leaked_probes = [p for p in probe_results if p.is_leak]
        direct_leaks = sum(1 for p in probe_results if p.severity == LeakSeverity.DIRECT_LEAK)
        context_leaks = sum(1 for p in probe_results if p.severity == LeakSeverity.CONTEXT_LEAK)

        # Unique canaries compromised
        all_compromised_canaries = set()
        for p in leaked_probes:
            all_compromised_canaries.update(p.leaked_canaries)

        num_compromised = len(all_compromised_canaries)
        num_planted = max(len(planted_canaries), 1)

        # Calculate Firedamp Index (0.0 = completely isolated/safe, 100.0 = catastrophic bleed)
        if not leaked_probes:
            index_score = 0.0
            status = "CLEAR"
        else:
            probe_ratio = len(leaked_probes) / max(total_probes, 1)
            canary_penetration = num_compromised / num_planted
            severity_weight = (direct_leaks * 1.5 + context_leaks * 1.0) / max(len(leaked_probes), 1)

            # Weighted combination scaled to 0-100
            raw_score = (probe_ratio * 40.0) + (canary_penetration * 40.0) + (severity_weight * 13.3)
            index_score = round(min(100.0, raw_score), 1)
            status = "GAS DETECTED"

        return AuditSummary(
            target_name=target_name,
            target_url=target_url,
            total_canaries_planted=len(planted_canaries),
            total_probes_dispatched=total_probes,
            total_leaks_detected=len(leaked_probes),
            direct_leaks=direct_leaks,
            context_leaks=context_leaks,
            firedamp_index=index_score,
            status=status,
            probe_results=[asdict(p) for p in probe_results]
        )

    def print_banner(self) -> None:
        banner = r"""
   ______ _               _                           
  |  ____(_)             | |                          
  | |__   _ _ __ ___   __| | __ _ _ __ ___  _ __     
  |  __| | | '__/ _ \ / _` |/ _` | '_ ` _ \| '_ \    
  | |    | | | |  __/| (_| | (_| | | | | | | |_) |   
  |_|    |_|_|  \___| \__,_|\__,_|_| |_| |_| .__/    
                                           | |       
        Canaries for your RAG stack        |_|       
        """
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")

    def render_summary(self, summary: AuditSummary) -> None:
        self.console.print("\n")
        if summary.status == "CLEAR":
            status_panel = Panel(
                Text(
                    f"✓ STATUS: CLEAR\nFiredamp Index: {summary.firedamp_index}/100.0\n"
                    "No canary tokens detected in unauthorized retrieval streams. Isolation holds.",
                    style="bold green",
                    justify="center"
                ),
                title="[bold green]RAG SHAFT INTEGRITY VERIFIED[/bold green]",
                border_style="green"
            )
        else:
            status_panel = Panel(
                Text(
                    f"⚠ DANGER: GAS DETECTED IN THE RAG SHAFT!\n"
                    f"Firedamp Index: {summary.firedamp_index}/100.0 (High Exposure)\n"
                    f"{summary.total_leaks_detected} unauthorized retrieval leaks detected across tenant boundaries!",
                    style="bold red",
                    justify="center"
                ),
                title="[bold red]CROSS-TENANT LEAKAGE ALERT[/bold red]",
                border_style="red"
            )

        self.console.print(status_panel)

        # Telemetry metrics table
        table = Table(title="Audit Telemetry Breakdown", border_style="dim")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="bold white")
        table.add_column("Assessment", style="magenta")

        table.add_row("Target Platform", summary.target_name, summary.target_url)
        table.add_row("Canaries Planted (Alice)", str(summary.total_canaries_planted), "Isolated Baseline")
        table.add_row("Probes Dispatched (Bob)", str(summary.total_probes_dispatched), "Adversarial Probing")
        table.add_row(
            "Direct Generation Leaks",
            str(summary.direct_leaks),
            "[red]Critical[/red]" if summary.direct_leaks > 0 else "[green]Nominal[/green]"
        )
        table.add_row(
            "Context / Citation Leaks",
            str(summary.context_leaks),
            "[yellow]Elevated[/yellow]" if summary.context_leaks > 0 else "[green]Nominal[/green]"
        )
        table.add_row(
            "Firedamp Index Score",
            f"{summary.firedamp_index}/100.0",
            "[red]Gas Detected[/red]" if summary.firedamp_index > 0 else "[green]Safe / Isolated[/green]"
        )

        self.console.print(table)

    def export_json(self, summary: AuditSummary, file_path: str) -> None:
        """Exports audit summary to a formatted JSON file for CI/CD pipelines."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2)
        self.console.print(f"[dim]Audit report successfully saved to [bold]{file_path}[/bold][/dim]")
