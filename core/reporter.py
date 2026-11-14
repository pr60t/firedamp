"""
Reporting Engine & Firedamp Index Calculation.
Formats audit results, computes isolation risk scores, and outputs mine-safety atmospheric telemetry.
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
    """Handles mine-safety atmospheric telemetry rendering and JSON export for RAG isolation audits."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def log_success(self, message: str) -> None:
        """Log a completed/successful operation with [+] glyph."""
        self.console.print(f"[bold green][+][/bold green] {message}")

    def log_active(self, message: str) -> None:
        """Log an active process/transitional event with [~] glyph."""
        self.console.print(f"[bold cyan][~][/bold cyan] {message}")

    def log_alert(self, message: str) -> None:
        """Log a gas leak / atmospheric hazard with [🚨] glyph."""
        self.console.print(f"[bold red][🚨][/bold red] {message}")

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

        # Calculate Firedamp Index (0.0 = clean atmosphere, 100.0 = catastrophic bleed)
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
     Mine Safety & Atmospheric Sensor for RAG |_|       
        """
        self.console.print(f"[bold cyan]{banner}[/bold cyan]")

    def render_summary(self, summary: AuditSummary) -> None:
        self.console.print("\n")
        if summary.status == "CLEAR":
            panel_content = Text()
            panel_content.append("[+] AIRWAY SECURE // 0.0 ppm FIREDAMP\n", style="bold green")
            panel_content.append(f"Firedamp Index: {summary.firedamp_index} / 100.0 [NOMINAL]\n", style="bold white")
            panel_content.append("All canary cages intact. Zero cross-tenant atmospheric bleed detected.", style="green")

            status_panel = Panel(
                panel_content,
                title="[bold green]ATMOSPHERIC TELEMETRY REPORT // MINE SHAFT CLEAR[/bold green]",
                border_style="green",
                padding=(1, 2)
            )
        else:
            panel_content = Text()
            panel_content.append("[🚨] HAZARDOUS ATMOSPHERIC BLEED DETECTED!\n", style="bold red")
            panel_content.append(
                f"Firedamp Index: {summary.firedamp_index} / 100.0 [CRITICAL HAZARD]\n",
                style="bold red"
            )
            panel_content.append(
                f"Canaries compromised! {summary.total_leaks_detected} cross-tenant gas leak(s) intercepted.",
                style="bold yellow"
            )

            status_panel = Panel(
                panel_content,
                title="[bold red]ATMOSPHERIC TELEMETRY REPORT // GAS IN THE SHAFT[/bold red]",
                border_style="red",
                padding=(1, 2)
            )

        self.console.print(status_panel)

        # Atmospheric sensor telemetry table
        table = Table(
            title="Atmospheric Sensor Readings & Safety Margins",
            border_style="cyan",
            header_style="bold cyan"
        )
        table.add_column("Sensor Channel", style="cyan", no_wrap=True)
        table.add_column("Parameter / Target", style="white")
        table.add_column("Reading", style="bold white")
        table.add_column("Atmospheric Status", style="bold")

        table.add_row(
            "Airway Intake",
            summary.target_name,
            summary.target_url,
            "[green]Connected[/green]"
        )
        table.add_row(
            "Canary Cages Seeded",
            "Alice (Data Owner)",
            f"{summary.total_canaries_planted} synthetic canaries",
            "[green]Seeded[/green]"
        )
        table.add_row(
            "Exfiltration Probes",
            "Bob (Unauthorized)",
            f"{summary.total_probes_dispatched} air samples",
            "[green]Evaluated[/green]"
        )
        table.add_row(
            "Direct Generation Bleed",
            "LLM Assistant Stream",
            f"{summary.direct_leaks} leak(s)",
            "[bold red][🚨] CRITICAL BLEED[/bold red]" if summary.direct_leaks > 0 else "[bold green]0.0 ppm (Clear)[/bold green]"
        )
        table.add_row(
            "Latent Context Bleed",
            "Citations & Chunks",
            f"{summary.context_leaks} leak(s)",
            "[bold yellow][🚨] ELEVATED[/bold yellow]" if summary.context_leaks > 0 else "[bold green]0.0 ppm (Clear)[/bold green]"
        )
        table.add_row(
            "Firedamp Index",
            "Composite Risk Exposure",
            f"{summary.firedamp_index} / 100.0",
            "[bold red][🚨] GAS DETECTED[/bold red]" if summary.firedamp_index > 0 else "[bold green][+] AIRWAY SAFE[/bold green]"
        )

        self.console.print(table)

        # If leaks occurred, render a punchy audit log of breached tokens
        leaked_results = [p for p in (summary.probe_results or []) if p.get("severity") != LeakSeverity.NONE]
        if leaked_results:
            leak_table = Table(
                title="[bold red]Contaminated Airway Sample Logs[/bold red]",
                border_style="red",
                header_style="bold red"
            )
            leak_table.add_column("Breach Vector", style="yellow")
            leak_table.add_column("Probe Prompt", style="white")
            leak_table.add_column("Compromised Canary", style="bold red")

            for item in leaked_results:
                tokens = ", ".join(item.get("leaked_canaries", [])) or "Token extracted"
                leak_table.add_row(
                    item.get("severity", "").upper(),
                    item.get("probe_prompt", "")[:50] + "...",
                    tokens
                )
            self.console.print(leak_table)

    def export_json(self, summary: AuditSummary, file_path: str) -> None:
        """Exports audit summary to a formatted JSON file for CI/CD pipelines."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2)
        self.console.print(f"[dim][+] Telemetry exported to [bold]{file_path}[/bold][/dim]")
