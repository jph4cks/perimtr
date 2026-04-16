"""
Base class for all recon modules.

Every module inherits from ReconModule and implements:
  - name: str — unique module identifier
  - description: str — human-readable description
  - run(targets, config) -> dict — execute the module and return findings
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("perimtr")


class ReconModule(ABC):
    """Abstract base class for recon modules."""

    name: str = "base"
    description: str = "Base recon module"
    category: str = "general"  # network, dns, web, cert, vuln, domain

    def __init__(self, config: dict):
        self.config = config
        self.scan_settings = config.get("scan_settings", {})
        self.logger = logging.getLogger(f"perimtr.{self.name}")

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

    def safe_run(self, targets: dict) -> dict:
        """Run with error handling and timing."""
        start = time.time()
        self.logger.info(f"Starting module: {self.name}")
        try:
            results = self.run(targets)
            elapsed = time.time() - start
            results["_meta"] = {
                "module": self.name,
                "duration_seconds": round(elapsed, 2),
                "status": "success",
            }
            self.logger.info(f"Module {self.name} completed in {elapsed:.1f}s")
            return results
        except Exception as e:
            elapsed = time.time() - start
            self.logger.error(f"Module {self.name} failed: {e}")
            return {
                "_meta": {
                    "module": self.name,
                    "duration_seconds": round(elapsed, 2),
                    "status": "error",
                    "error": str(e),
                }
            }
