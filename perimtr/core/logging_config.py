"""
Structured logging configuration for Perimtr.

Provides file-based log rotation, per-module verbosity control,
and clean console output via Rich.

Usage:
    from perimtr.core.logging_config import setup_logging
    setup_logging(verbose=True, log_file="perimtr.log")
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


# Noisy third-party loggers to suppress
_NOISY_LOGGERS = [
    "urllib3",
    "urllib3.connectionpool",
    "requests",
    "requests.packages.urllib3",
    "charset_normalizer",
    "asyncio",
    "httpcore",
    "httpx",
    "nmap",
    "dnspython",
]


def setup_logging(
    verbose: bool = False,
    log_file: Optional[str] = None,
    log_dir: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    module_levels: Optional[dict] = None,
) -> None:
    """
    Configure logging for Perimtr with console + optional file output.

    Args:
        verbose: If True, set console to DEBUG. Otherwise INFO.
        log_file: Explicit log file path. If None, uses log_dir/perimtr.log.
        log_dir: Directory for log files. Created if needed.
        max_bytes: Max size per log file before rotation.
        backup_count: Number of rotated log files to keep.
        module_levels: Dict of module_name -> logging level for per-module control.
            Example: {"perimtr.port_scanner": "DEBUG", "perimtr.dns_enum": "WARNING"}
    """
    console_level = logging.DEBUG if verbose else logging.INFO

    # --- Console handler via Rich ---
    console = Console(stderr=True)
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=verbose,  # show file/line only in verbose mode
        rich_tracebacks=True,
        markup=True,
        log_time_format="[%X]",
    )
    rich_handler.setLevel(console_level)

    handlers: list[logging.Handler] = [rich_handler]

    # --- File handler with rotation ---
    if log_file or log_dir:
        if log_file:
            file_path = Path(log_file)
        else:
            log_dir_path = Path(log_dir)
            log_dir_path.mkdir(parents=True, exist_ok=True)
            file_path = log_dir_path / "perimtr.log"

        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_formatter = logging.Formatter(
            fmt="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(file_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)  # always capture everything to file
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    # --- Configure root logger ---
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # root captures all; handlers filter

    # Clear any pre-existing handlers to avoid duplicate output
    root_logger.handlers.clear()
    for handler in handlers:
        root_logger.addHandler(handler)

    # --- Suppress noisy third-party loggers ---
    for logger_name in _NOISY_LOGGERS:
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    # --- Per-module level overrides ---
    if module_levels:
        for module_name, level in module_levels.items():
            if isinstance(level, str):
                level = getattr(logging, level.upper(), logging.DEBUG)
            logging.getLogger(module_name).setLevel(level)

    # Emit a debug message to confirm setup
    logger = logging.getLogger("perimtr.logging_config")
    logger.debug(
        "Logging configured: console_level=%s, file=%s",
        logging.getLevelName(console_level),
        str(log_file or (Path(log_dir) / "perimtr.log" if log_dir else "none")),
    )
