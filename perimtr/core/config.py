"""
Configuration management for Perimtr.

Handles loading, saving, and first-run setup of the perimtr.yaml config file.
On first run, interactively asks the user for target ranges, domains, and schedule.
"""

import copy
import ipaddress
import os
import re
import yaml
from pathlib import Path
from typing import List, Optional

DEFAULT_CONFIG = {
    "project_name": "my-perimeter",
    "targets": {
        "networks": [],      # e.g. [\"192.168.1.0/24\", \"10.0.0.0/16\"]
        "domains": [],       # e.g. [\"example.com\", \"sub.example.com\"]
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
        "web_tech": {"enabled": True},
        "ssl_audit": {"enabled": True},
    },
    "llm": {
        "provider": None,       # "openrouter", "openai", "anthropic", "local"
        "api_key": None,
        "model": None,
        "base_url": None,       # for local LLM or openrouter
    },
    "data_dir": "data",
}

# Regex for valid domain names
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)

VALID_FREQUENCIES = {"daily", "weekly", "monthly"}
VALID_PROVIDERS = {"openai", "anthropic", "openrouter", "local"}


class ConfigError(Exception):
    """Raised when configuration validation fails.

    Attributes:
        errors: List of human-readable validation error strings.
    """

    def __init__(self, errors: List[str]) -> None:
        self.errors = errors
        super().__init__("Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


class Config:
    """Manages Perimtr configuration."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else Path("perimtr.yaml")
        self.data = dict(DEFAULT_CONFIG)

    def exists(self) -> bool:
        """Check if config file exists."""
        return self.config_path.exists()

    def load(self) -> dict:
        """Load configuration from YAML file.

        Reads the YAML file, deep-merges with defaults, applies environment
        variable overrides, then validates the resulting configuration.

        Returns:
            The merged configuration dict.

        Raises:
            FileNotFoundError: If the config file does not exist.
            ConfigError: If the configuration fails validation.
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        with open(self.config_path, "r") as f:
            loaded = yaml.safe_load(f) or {}
        # Deep merge with defaults
        self.data = self._deep_merge(dict(DEFAULT_CONFIG), loaded)
        # Apply environment variable overrides
        self._apply_env_overrides()
        # Validate
        self.validate()
        return self.data

    def save(self):
        """Save current configuration to YAML file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            yaml.dump(self.data, f, default_flow_style=False, sort_keys=False)

    def setup_interactive(self):
        """First-run interactive setup.

        Raises:
            ConfigError: If the resulting configuration fails validation.
        """
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

        # Apply env var overrides before saving/validating
        self._apply_env_overrides()

        # Save
        self.save()
        console.print(f"\n[green]✓ Configuration saved to {self.config_path}[/green]")

        # Validate after save
        self.validate()

        return self.data

    def validate(self) -> None:
        """Validate the current configuration data.

        Checks all required fields for correct types, valid values, and
        consistency.  Collects all errors before raising so the caller
        receives the full list in one shot.

        Raises:
            ConfigError: If any validation rule is violated.  The
                ``errors`` attribute contains all individual error messages.
        """
        errors: List[str] = []

        targets = self.data.get("targets", {})
        networks = targets.get("networks") or []
        domains = targets.get("domains") or []

        # At least one target must be defined
        if not networks and not domains:
            errors.append("At least one target (network CIDR or domain) must be defined")

        # Validate network CIDRs
        for cidr in networks:
            if not isinstance(cidr, str):
                errors.append(f"Network target must be a string, got: {cidr!r}")
                continue
            try:
                ipaddress.ip_network(cidr.strip(), strict=False)
            except ValueError:
                errors.append(f"Invalid CIDR notation: {cidr!r}")

        # Validate domain names
        for domain in domains:
            if not isinstance(domain, str):
                errors.append(f"Domain target must be a string, got: {domain!r}")
                continue
            if not _DOMAIN_RE.match(domain.strip()):
                errors.append(f"Invalid domain name: {domain!r}")

        # Validate scan_settings
        scan = self.data.get("scan_settings", {})

        threads = scan.get("threads", 5)
        if not isinstance(threads, int) or not (1 <= threads <= 50):
            errors.append(f"scan_settings.threads must be an integer between 1 and 50, got: {threads!r}")

        rate = scan.get("port_scan_rate", 10)
        if not isinstance(rate, int) or not (1 <= rate <= 1000):
            errors.append(f"scan_settings.port_scan_rate must be an integer between 1 and 1000, got: {rate!r}")

        top_ports = scan.get("top_ports", 1000)
        if not isinstance(top_ports, int) or not (1 <= top_ports <= 65535):
            errors.append(f"scan_settings.top_ports must be an integer between 1 and 65535, got: {top_ports!r}")

        # Validate schedule frequency
        frequency = self.data.get("schedule", {}).get("frequency", "weekly")
        if frequency not in VALID_FREQUENCIES:
            errors.append(
                f"schedule.frequency must be one of {sorted(VALID_FREQUENCIES)}, got: {frequency!r}"
            )

        # Validate LLM provider (if set)
        provider = self.data.get("llm", {}).get("provider")
        if provider is not None and provider not in VALID_PROVIDERS:
            errors.append(
                f"llm.provider must be one of {sorted(VALID_PROVIDERS)}, got: {provider!r}"
            )

        if errors:
            raise ConfigError(errors)

    def mask_secrets(self) -> dict:
        """Return a deep copy of the config with API keys masked for display or logging.

        Any non-empty ``api_key`` value is replaced with the first four
        characters followed by ``****``.

        Returns:
            A deep copy of ``self.data`` with secrets masked.
        """
        masked = copy.deepcopy(self.data)
        llm = masked.get("llm", {})
        api_key = llm.get("api_key")
        if api_key and isinstance(api_key, str) and len(api_key) > 0:
            visible = api_key[:4] if len(api_key) >= 4 else api_key
            llm["api_key"] = visible + "****"
        return masked

    def get_data_dir(self) -> Path:
        """Get the data directory path."""
        data_dir = Path(self.data.get("data_dir", "data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to the configuration.

        The following environment variables are supported:

        * ``PERIMTR_LLM_API_KEY`` — overrides ``llm.api_key``
        * ``PERIMTR_LLM_PROVIDER`` — overrides ``llm.provider``
        * ``PERIMTR_LLM_MODEL`` — overrides ``llm.model``
        """
        llm = self.data.setdefault("llm", {})

        api_key = os.environ.get("PERIMTR_LLM_API_KEY")
        if api_key:
            llm["api_key"] = api_key

        provider = os.environ.get("PERIMTR_LLM_PROVIDER")
        if provider:
            llm["provider"] = provider

        model = os.environ.get("PERIMTR_LLM_MODEL")
        if model:
            llm["model"] = model

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep merge two dictionaries.

        Values in *override* take precedence over *base* for scalar values.
        Nested dicts are merged recursively.  ``None`` values in *override*
        do **not** overwrite non-``None`` values in *base*, preserving
        meaningful defaults when only a partial override is supplied.

        Args:
            base: The base dictionary (defaults).
            override: The override dictionary (user-supplied values).

        Returns:
            A new dictionary with the merged result.
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            elif value is None and key in result and result[key] is not None:
                # Don't let None override a real base value
                pass
            else:
                result[key] = value
        return result
