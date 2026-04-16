"""
Configuration management for Perimtr.

Handles loading, saving, and first-run setup of the perimtr.yaml config file.
On first run, interactively asks the user for target ranges, domains, and schedule.
"""

import os
import yaml
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG = {
    "project_name": "my-perimeter",
    "targets": {
        "networks": [],      # e.g. ["192.168.1.0/24", "10.0.0.0/16"]
        "domains": [],       # e.g. ["example.com", "sub.example.com"]
    },
    "schedule": {
        "frequency": "weekly",  # daily, weekly, monthly
        "enabled": False,
    },
    "scan_settings": {
        "port_scan_rate": 10,       # max packets/sec (slow to avoid blocks)
        "top_ports": 1000,          # well-known ports
        "dns_timeout": 10,          # seconds
        "http_timeout": 15,         # seconds
        "threads": 5,               # concurrent module threads
    },
    "modules": {
        "port_scanner": {"enabled": True},
        "dns_enum": {"enabled": True},
        "http_headers": {"enabled": True},
        "whois_cert": {"enabled": True},
        "vuln_check": {"enabled": True},
        "domain_security": {"enabled": True},
    },
    "llm": {
        "provider": None,       # "openrouter", "openai", "anthropic", "local"
        "api_key": None,
        "model": None,
        "base_url": None,       # for local LLM or openrouter
    },
    "data_dir": "data",
}


class Config:
    """Manages Perimtr configuration."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else Path("perimtr.yaml")
        self.data = dict(DEFAULT_CONFIG)

    def exists(self) -> bool:
        """Check if config file exists."""
        return self.config_path.exists()

    def load(self) -> dict:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        with open(self.config_path, "r") as f:
            loaded = yaml.safe_load(f) or {}
        # Deep merge with defaults
        self.data = self._deep_merge(dict(DEFAULT_CONFIG), loaded)
        return self.data

    def save(self):
        """Save current configuration to YAML file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            yaml.dump(self.data, f, default_flow_style=False, sort_keys=False)

    def setup_interactive(self):
        """First-run interactive setup."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.prompt import Prompt, Confirm

        console = Console()
        console.print(Panel(
            "[bold cyan]Welcome to Perimtr — Perimeter Intelligence Platform[/bold cyan]\n\n"
            "This tool will investigate your perimeter, inventory findings,\n"
            "and track changes over time.",
            title="🔍 First Run Setup",
            border_style="cyan"
        ))

        # Project name
        self.data["project_name"] = Prompt.ask(
            "\n[bold]Project name[/bold]",
            default="my-perimeter"
        )

        # Network ranges
        console.print("\n[bold]Network ranges to scan[/bold] (CIDR notation)")
        console.print("[dim]Examples: 203.0.113.0/24, 198.51.100.0/24[/dim]")
        networks_input = Prompt.ask("Enter ranges (comma-separated)", default="")
        if networks_input.strip():
            self.data["targets"]["networks"] = [
                n.strip() for n in networks_input.split(",") if n.strip()
            ]

        # Domains
        console.print("\n[bold]Domains to investigate[/bold]")
        console.print("[dim]Examples: example.com, api.example.com[/dim]")
        domains_input = Prompt.ask("Enter domains (comma-separated)", default="")
        if domains_input.strip():
            self.data["targets"]["domains"] = [
                d.strip() for d in domains_input.split(",") if d.strip()
            ]

        # Schedule
        console.print()
        frequency = Prompt.ask(
            "[bold]How often should assessments run?[/bold]",
            choices=["daily", "weekly", "monthly"],
            default="weekly"
        )
        self.data["schedule"]["frequency"] = frequency
        self.data["schedule"]["enabled"] = Confirm.ask(
            "Enable automatic scheduling?", default=False
        )

        # LLM integration
        console.print()
        if Confirm.ask("[bold]Configure LLM integration?[/bold] (enhances reports with AI recommendations)", default=False):
            provider = Prompt.ask(
                "LLM provider",
                choices=["openai", "anthropic", "openrouter", "local"],
                default="openai"
            )
            self.data["llm"]["provider"] = provider
            if provider == "local":
                self.data["llm"]["base_url"] = Prompt.ask("Local LLM base URL", default="http://localhost:11434/v1")
                self.data["llm"]["model"] = Prompt.ask("Model name", default="llama3")
            elif provider == "openrouter":
                self.data["llm"]["api_key"] = Prompt.ask("OpenRouter API key")
                self.data["llm"]["base_url"] = "https://openrouter.ai/api/v1"
                self.data["llm"]["model"] = Prompt.ask("Model", default="anthropic/claude-3.5-sonnet")
            else:
                self.data["llm"]["api_key"] = Prompt.ask(f"{provider.title()} API key")
                if provider == "openai":
                    self.data["llm"]["model"] = Prompt.ask("Model", default="gpt-4o-mini")
                else:
                    self.data["llm"]["model"] = Prompt.ask("Model", default="claude-sonnet-4-20250514")

        # Save
        self.save()
        console.print(f"\n[green]✓ Configuration saved to {self.config_path}[/green]")
        return self.data

    def get_data_dir(self) -> Path:
        """Get the data directory path."""
        data_dir = Path(self.data.get("data_dir", "data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
