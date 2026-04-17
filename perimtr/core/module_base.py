"""
Base class for all recon modules.

Every module inherits from ReconModule and implements:
  - name: str — unique module identifier
  - description: str — human-readable description
  - run(targets, config) -> dict — execute the module and return findings
"""

import ipaddress
import logging
import re
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List, Optional, Tuple, Type

logger = logging.getLogger("perimtr")

# Default per-module timeout in seconds (0 = no timeout)
DEFAULT_MODULE_TIMEOUT = 0

# Regex for valid domain names (mirrors the one in config.py)
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)


class ReconModule(ABC):
    """Abstract base class for recon modules."""

    name: str = "base"
    description: str = "Base recon module"
    category: str = "general"  # network, dns, web, cert, vuln, domain

    # Per-module timeout in seconds (0 = no timeout).  Subclasses may
    # override this to impose a ceiling on how long safe_run() will wait.
    module_timeout: int = DEFAULT_MODULE_TIMEOUT

    # Number of extra retry attempts on retryable exceptions (0 = no retry).
    retry_count: int = 0

    # Tuple of exception types that trigger a retry.  An empty tuple
    # disables retries even if retry_count > 0.
    retryable_exceptions: Tuple[Type[BaseException], ...] = ()

    def __init__(self, config: dict):
        self.config = config
        self.scan_settings = config.get("scan_settings", {})
        self.logger = logging.getLogger(f"perimtr.{self.name}")
        # Modules may populate this during run() to expose partial results
        # that safe_run() will include even when an exception is raised.
        self._partial_results: Optional[dict] = None

    @abstractmethod
    def run(self, targets: dict) -> dict:
        """
        Execute the recon module.

        Args:
            targets: dict with 'networks' (list of CIDRs) and 'domains' (list of domains)

        Returns:
            dict of findings structured per module spec
        """
        pass

    def is_enabled(self, config: dict) -> bool:
        """Check if this module is enabled in config."""
        modules_config = config.get("modules", {})
        module_config = modules_config.get(self.name, {})
        return module_config.get("enabled", True)

    def validate_targets(self, targets: dict) -> dict:
        """Clean and validate targets, returning a sanitised copy.

        Performs the following transformations:

        * Strips surrounding whitespace from domain names.
        * Lowercases domain names.
        * Removes duplicate targets (preserving order of first occurrence).
        * Logs and skips invalid CIDR ranges (instead of crashing).

        Args:
            targets: dict with optional keys ``'networks'`` (list of CIDR
                strings) and ``'domains'`` (list of domain name strings).

        Returns:
            A new dict with cleaned ``'networks'`` and ``'domains'`` lists.
        """
        raw_networks: List[str] = targets.get("networks") or []
        raw_domains: List[str] = targets.get("domains") or []

        # --- Validate & deduplicate networks ---
        seen_nets: set = set()
        clean_networks: List[str] = []
        for net in raw_networks:
            if not isinstance(net, str):
                self.logger.warning(
                    "Skipping non-string network target: %r", net
                )
                continue
            net = net.strip()
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError:
                self.logger.warning(
                    "Skipping invalid CIDR range: %r", net
                )
                continue
            if net not in seen_nets:
                seen_nets.add(net)
                clean_networks.append(net)

        # --- Clean & deduplicate domains ---
        seen_domains: set = set()
        clean_domains: List[str] = []
        for domain in raw_domains:
            if not isinstance(domain, str):
                self.logger.warning(
                    "Skipping non-string domain target: %r", domain
                )
                continue
            domain = domain.strip().lower()
            if not domain:
                continue
            if domain not in seen_domains:
                seen_domains.add(domain)
                clean_domains.append(domain)

        return {"networks": clean_networks, "domains": clean_domains}

    def safe_run(self, targets: dict) -> dict:
        """Run with error handling, timing, optional timeout, and retries.

        Validates and cleans *targets* before passing them to :meth:`run`.
        On success, appends ``_meta`` with timing and status.  On failure,
        returns ``_meta`` with the error details plus any partial results
        stored in ``self._partial_results``.

        If :attr:`module_timeout` is greater than zero the module is
        executed inside a :class:`~concurrent.futures.ThreadPoolExecutor`
        and cancelled (best-effort) after that many seconds.

        If :attr:`retry_count` is greater than zero and the raised
        exception is an instance of one of the types in
        :attr:`retryable_exceptions`, the run is attempted again up to
        ``retry_count`` additional times.

        Args:
            targets: Raw targets dict; will be validated/cleaned before use.

        Returns:
            Module result dict augmented with a ``_meta`` key.
        """
        clean_targets = self.validate_targets(targets)
        start = time.time()
        self.logger.info(f"Starting module: {self.name}")

        attempts = 1 + max(0, self.retry_count)
        last_exc: Optional[Exception] = None

        for attempt in range(attempts):
            if attempt > 0:
                self.logger.info(
                    f"Retrying module {self.name} (attempt {attempt + 1}/{attempts})"
                )
            try:
                results = self._run_with_timeout(clean_targets)
                elapsed = time.time() - start
                results["_meta"] = {
                    "module": self.name,
                    "duration_seconds": round(elapsed, 2),
                    "status": "success",
                }
                if attempt > 0:
                    results["_meta"]["retries"] = attempt
                self.logger.info(f"Module {self.name} completed in {elapsed:.1f}s")
                return results

            except Exception as exc:
                last_exc = exc
                exc_type_name = type(exc).__name__
                self.logger.exception(
                    f"Module {self.name} failed on attempt {attempt + 1}/{attempts} "
                    f"({exc_type_name}): {exc}"
                )
                # Only retry on explicitly retryable exception types
                if (
                    self.retryable_exceptions
                    and isinstance(exc, self.retryable_exceptions)
                    and attempt < attempts - 1
                ):
                    continue
                # Non-retryable or exhausted retries — fall through
                break

        elapsed = time.time() - start
        meta: Dict[str, Any] = {
            "module": self.name,
            "duration_seconds": round(elapsed, 2),
            "status": "error",
            "error": str(last_exc),
            "error_type": type(last_exc).__name__ if last_exc else "unknown",
        }
        if attempts > 1:
            meta["retries_attempted"] = attempts - 1

        # Return partial results if the module stored any
        partial = self._partial_results or {}
        result = dict(partial)
        result["_meta"] = meta
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_with_timeout(self, targets: dict) -> dict:
        """Execute :meth:`run` with an optional timeout.

        Args:
            targets: Pre-validated targets dict.

        Returns:
            Result dict from :meth:`run`.

        Raises:
            TimeoutError: If the module exceeds :attr:`module_timeout` seconds.
            Exception: Any exception raised by :meth:`run`.
        """
        timeout = self.module_timeout
        if timeout and timeout > 0:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self.run, targets)
                try:
                    return future.result(timeout=timeout)
                except FuturesTimeoutError:
                    raise TimeoutError(
                        f"Module {self.name} exceeded timeout of {timeout}s"
                    )
        else:
            return self.run(targets)
