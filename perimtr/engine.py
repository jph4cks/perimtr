"""
Perimtr Assessment Engine.

Orchestrates all recon modules, data storage, diffing, LLM analysis,
and report generation.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table

from perimtr.core.config import Config
from perimtr.core.datastore import DataStore
from perimtr.core.diff_engine import DiffEngine
from perimtr.core.llm_engine import LLMEngine
from perimtr.modules import MODULES
from perimtr.reports.html_report import HTMLReportGenerator

logger = logging.getLogger("perimtr")
console = Console()


class Engine:
    """Main assessment orchestration engine."""

    def __init__(self, config: Config):
        self.config = config
        self.data = config.data
        self.datastore = DataStore(
            data_dir=self.data.get("data_dir", "data"),
            project_name=self.data.get("project_name", "default"),
        )
        self.diff_engine = DiffEngine()
        self.llm_engine = LLMEngine(self.data)
        self.report_generator = HTMLReportGenerator(self.data)

    def run_assessment(self) -> dict:
        """
        Run a full perimeter assessment.

        Returns:
            Complete assessment results dict
        """
        start_time = time.time()
        targets = self.data.get("targets", {})
        threads = self.data.get("scan_settings", {}).get("threads", 5)

        console.print(Panel(
            f"[bold cyan]Starting Perimeter Assessment[/bold cyan]\n"
            f"Networks: {', '.join(targets.get('networks', [])) or 'None'}\n"
            f"Domains: {', '.join(targets.get('domains', [])) or 'None'}\n"
            f"Modules: {sum(1 for m in MODULES if m(self.data).is_enabled(self.data))} enabled",
            title="🔍 Perimtr Assessment",
            border_style="cyan",
        ))

        # Initialize enabled modules
        enabled_modules = []
        for ModuleClass in MODULES:
            module = ModuleClass(self.data)
            if module.is_enabled(self.data):
                enabled_modules.append(module)

        if not enabled_modules:
            console.print("[yellow]No modules enabled. Check your configuration.[/yellow]")
            return {}

        # Run modules
        results = {}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            overall = progress.add_task(
                "Running assessment...",
                total=len(enabled_modules),
            )

            # Run modules concurrently
            with ThreadPoolExecutor(max_workers=min(threads, len(enabled_modules))) as executor:
                futures = {}
                for module in enabled_modules:
                    task_id = progress.add_task(
                        f"  {module.description}",
                        total=None,
                    )
                    future = executor.submit(module.safe_run, targets)
                    futures[future] = (module, task_id)

                for future in as_completed(futures):
                    module, task_id = futures[future]
                    try:
                        module_results = future.result()
                        results[module.name] = module_results
                        status = module_results.get("_meta", {}).get("status", "unknown")
                        duration = module_results.get("_meta", {}).get("duration_seconds", 0)
                        if status == "success":
                            progress.update(task_id, description=f"  [green]✓[/green] {module.description} ({duration}s)")
                        else:
                            error = module_results.get("_meta", {}).get("error", "Unknown error")
                            progress.update(task_id, description=f"  [red]✗[/red] {module.description}: {error[:50]}")
                    except Exception as e:
                        progress.update(task_id, description=f"  [red]✗[/red] {module.description}: {e}")
                    progress.advance(overall)

        # Save assessment
        assessment_path = self.datastore.save_assessment(results)
        console.print(f"\n[green]Assessment saved:[/green] {assessment_path}")

        # Compare with previous assessment
        diff = None
        previous = self.datastore.get_previous_assessment()
        if previous:
            console.print("\n[cyan]Comparing with previous assessment...[/cyan]")
            diff = self.diff_engine.compare(results, previous)
            self._display_diff_summary(diff)

        # LLM analysis
        llm_analysis = None
        console.print("\n[cyan]Generating analysis...[/cyan]")
        llm_analysis = self.llm_engine.analyze(results, diff)

        if llm_analysis:
            self._display_risk_summary(llm_analysis)

        # Generate HTML report
        report_dir = Path(self.data.get("data_dir", "data")) / self.data.get("project_name", "default")
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = str(report_dir / f"report_{timestamp}.html")
        self.report_generator.generate(results, diff, llm_analysis, report_path)
        console.print(f"[green]Report generated:[/green] {report_path}")

        # Also generate a "latest" report
        latest_path = str(report_dir / "report_latest.html")
        self.report_generator.generate(results, diff, llm_analysis, latest_path)

        elapsed = time.time() - start_time
        console.print(f"\n[bold green]Assessment complete in {elapsed:.1f}s[/bold green]")

        return results

    def _display_diff_summary(self, diff: dict):
        """Display change summary in the terminal."""
        summary = diff.get("summary", {})
        if not summary.get("has_changes"):
            console.print("[dim]No changes since last assessment.[/dim]")
            return

        table = Table(title="Changes Since Last Assessment", border_style="dim")
        table.add_column("Type", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("[red]New findings[/red]", str(summary.get("total_new", 0)))
        table.add_row("[green]Resolved[/green]", str(summary.get("total_removed", 0)))
        table.add_row("[yellow]Changed[/yellow]", str(summary.get("total_changed", 0)))
        console.print(table)

        # Show critical new findings
        for item in diff.get("new", []):
            if item.get("severity") in ("critical", "high"):
                console.print(f"  [red]NEW:[/red] {item.get('detail', '')}")

    def _display_risk_summary(self, analysis: dict):
        """Display risk summary in the terminal."""
        risk_score = analysis.get("risk_score", 0)
        risk_rating = analysis.get("risk_rating", "unknown")

        color = {
            "critical": "red",
            "high": "bright_red",
            "medium": "yellow",
            "low": "green",
        }.get(risk_rating, "white")

        console.print(Panel(
            f"[bold {color}]Risk Score: {risk_score}/100 ({risk_rating.upper()})[/bold {color}]",
            title="Risk Assessment",
            border_style=color,
        ))

        # Show top priority actions
        actions = analysis.get("priority_actions", [])[:5]
        if actions:
            console.print("\n[bold]Top Priority Actions:[/bold]")
            for action in actions:
                console.print(f"  {action.get('priority', '?')}. {action.get('action', '')}")
