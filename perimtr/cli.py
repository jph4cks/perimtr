"""
Perimtr CLI — Command-line interface.

Usage:
    perimtr                  # Run assessment (first run triggers setup)
    perimtr scan             # Run assessment
    perimtr setup            # Re-run interactive setup
    perimtr report           # Generate report from latest assessment
    perimtr diff             # Show changes between last two assessments
    perimtr history          # List all assessments
    perimtr schedule         # Start scheduled assessments
    perimtr version          # Show version
"""

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logging(verbose: bool = False):
    """Configure logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(
            console=console,
            show_path=False,
            rich_tracebacks=True,
        )],
    )


def cmd_scan(args):
    """Run a perimeter assessment."""
    from perimtr.core.config import Config
    from perimtr.engine import Engine

    config = Config(args.config)

    if not config.exists():
        console.print("[yellow]No configuration found. Starting first-run setup...[/yellow]\n")
        config.setup_interactive()
    else:
        config.load()

    # Parse --modules flag
    modules_filter = None
    if hasattr(args, "modules") and args.modules:
        modules_filter = [m.strip() for m in args.modules.split(",") if m.strip()]

    dry_run = getattr(args, "dry_run", False)
    output_dir = getattr(args, "output_dir", None)
    no_report = getattr(args, "no_report", False)

    engine = Engine(config)
    engine.run_assessment(
        dry_run=dry_run,
        modules_filter=modules_filter,
        output_dir=output_dir,
        no_report=no_report,
    )


def cmd_setup(args):
    """Run interactive setup."""
    from perimtr.core.config import Config

    config = Config(args.config)
    config.setup_interactive()


def cmd_report(args):
    """Generate report from latest assessment."""
    from perimtr.core.config import Config
    from perimtr.core.datastore import DataStore
    from perimtr.core.diff_engine import DiffEngine
    from perimtr.core.llm_engine import LLMEngine
    from perimtr.reports.html_report import HTMLReportGenerator

    config = Config(args.config)
    config.load()

    datastore = DataStore(
        data_dir=config.data.get("data_dir", "data"),
        project_name=config.data.get("project_name", "default"),
    )

    latest = datastore.get_latest_assessment()
    if not latest:
        console.print("[red]No assessments found. Run 'perimtr scan' first.[/red]")
        return

    # Get diff if previous exists
    previous = datastore.get_previous_assessment()
    diff = None
    if previous:
        diff_engine = DiffEngine()
        diff = diff_engine.compare(latest, previous)

    use_json = getattr(args, "json", False)

    if use_json:
        import json
        output = args.output or "report.json"
        with open(output, "w") as f:
            json.dump({"assessment": latest, "diff": diff}, f, indent=2, default=str)
        console.print(f"[green]JSON report generated:[/green] {output}")
        return

    # LLM analysis
    llm = LLMEngine(config.data)
    analysis = llm.analyze(latest, diff)

    # Generate report
    report_gen = HTMLReportGenerator(config.data)
    output = args.output or "report.html"
    report_gen.generate(latest, diff, analysis, output)
    console.print(f"[green]Report generated:[/green] {output}")


def cmd_diff(args):
    """Show changes between assessments."""
    from perimtr.core.config import Config
    from perimtr.core.datastore import DataStore
    from perimtr.core.diff_engine import DiffEngine
    from rich.table import Table

    config = Config(args.config)
    config.load()

    datastore = DataStore(
        data_dir=config.data.get("data_dir", "data"),
        project_name=config.data.get("project_name", "default"),
    )

    if datastore.get_assessment_count() < 2:
        console.print("[yellow]Need at least 2 assessments to compare. Run 'perimtr scan' again.[/yellow]")
        return

    latest = datastore.get_latest_assessment()
    previous = datastore.get_previous_assessment()

    diff_engine = DiffEngine()
    diff = diff_engine.compare(latest, previous)

    summary = diff.get("summary", {})
    if not summary.get("has_changes"):
        console.print("[green]No changes between assessments.[/green]")
        return

    # Display changes
    table = Table(title="Attack Surface Changes", border_style="cyan")
    table.add_column("Type", style="bold")
    table.add_column("Severity")
    table.add_column("Detail")
    table.add_column("Module", style="dim")

    for item in diff.get("new", []):
        table.add_row(
            "[red]NEW[/red]",
            item.get("severity", "info"),
            item.get("detail", ""),
            item.get("module", ""),
        )

    for item in diff.get("removed", []):
        table.add_row(
            "[green]RESOLVED[/green]",
            item.get("severity", "info"),
            item.get("detail", ""),
            item.get("module", ""),
        )

    for item in diff.get("changed", []):
        table.add_row(
            "[yellow]CHANGED[/yellow]",
            item.get("severity", "info"),
            item.get("detail", ""),
            item.get("module", ""),
        )

    console.print(table)


def cmd_history(args):
    """List all assessments."""
    from perimtr.core.config import Config
    from perimtr.core.datastore import DataStore
    from rich.table import Table

    config = Config(args.config)
    config.load()

    datastore = DataStore(
        data_dir=config.data.get("data_dir", "data"),
        project_name=config.data.get("project_name", "default"),
    )

    files = datastore.list_assessments()
    if not files:
        console.print("[yellow]No assessments found. Run 'perimtr scan' first.[/yellow]")
        return

    table = Table(title="Assessment History", border_style="cyan")
    table.add_column("#", justify="right")
    table.add_column("File")
    table.add_column("Size")

    for i, f in enumerate(files, 1):
        p = Path(f)
        size = p.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B"
        table.add_row(str(i), p.name, size_str)

    console.print(table)


def cmd_schedule(args):
    """Start the scheduler for recurring assessments."""
    from perimtr.core.config import Config
    from perimtr.core.scheduler import Scheduler
    from perimtr.engine import Engine

    config = Config(args.config)
    config.load()

    frequency = config.data.get("schedule", {}).get("frequency", "weekly")
    console.print(f"[cyan]Starting scheduler ({frequency})...[/cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")

    engine = Engine(config)
    scheduler = Scheduler(frequency)
    scheduler.schedule_task(engine.run_assessment)
    scheduler.start()

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        scheduler.stop()
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


def cmd_version(args):
    """Show version."""
    from perimtr import __version__
    console.print(f"Perimtr v{__version__}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="perimtr",
        description="Perimtr — Perimeter Intelligence Platform",
    )
    parser.add_argument("-c", "--config", default="perimtr.yaml", help="Config file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Run perimeter assessment")
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print what would be scanned without actually running modules",
    )
    scan_parser.add_argument(
        "--modules",
        default=None,
        help="Comma-separated list of module names to run (e.g. port_scanner,dns_enum)",
    )
    scan_parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write reports to (overrides config data_dir)",
    )
    scan_parser.add_argument(
        "--no-report",
        action="store_true",
        default=False,
        help="Skip HTML report generation after the scan",
    )

    # setup
    setup_parser = subparsers.add_parser("setup", help="Interactive setup")  # noqa: F841

    # report
    report_parser = subparsers.add_parser("report", help="Generate report from latest")
    report_parser.add_argument("-o", "--output", help="Output file path")
    report_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output JSON instead of HTML",
    )

    # diff
    diff_parser = subparsers.add_parser("diff", help="Show changes between assessments")  # noqa: F841

    # history
    history_parser = subparsers.add_parser("history", help="List assessments")  # noqa: F841

    # schedule
    schedule_parser = subparsers.add_parser("schedule", help="Start scheduler")  # noqa: F841

    # version
    version_parser = subparsers.add_parser("version", help="Show version")  # noqa: F841

    args = parser.parse_args()
    setup_logging(args.verbose)

    commands = {
        "scan": cmd_scan,
        "setup": cmd_setup,
        "report": cmd_report,
        "diff": cmd_diff,
        "history": cmd_history,
        "schedule": cmd_schedule,
        "version": cmd_version,
    }

    try:
        if args.command in commands:
            commands[args.command](args)
        elif args.command is None:
            # Default: run scan
            cmd_scan(args)
        else:
            parser.print_help()

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Exiting.[/yellow]")
        sys.exit(0)

    except FileNotFoundError as exc:
        console.print(f"[red]Config file not found:[/red] {exc}")
        console.print("[dim]Run 'perimtr setup' to create a configuration.[/dim]")
        sys.exit(1)

    except Exception:
        # Import here to access ConfigError after potential import issues
        try:
            from perimtr.core.config import ConfigError
        except ImportError:
            ConfigError = None  # type: ignore[assignment,misc]

        import traceback as _tb

        # Re-raise so we can inspect the live exception
        exc_info = sys.exc_info()
        exc = exc_info[1]

        if ConfigError is not None and isinstance(exc, ConfigError):
            console.print("[red]Configuration error:[/red]")
            for error in exc.errors:
                console.print(f"  [red]•[/red] {error}")
            sys.exit(1)

        # Generic unexpected error
        console.print(f"[red]Unexpected error:[/red] {exc}")
        if not args.verbose:
            console.print("[dim]Run with -v for full traceback.[/dim]")
        else:
            _tb.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
