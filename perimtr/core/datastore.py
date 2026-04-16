"""
JSON-based local data store for assessment results.

Each assessment is stored as a timestamped JSON file:
  data/<project_name>/assessment_<timestamp>.json
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import logging

logger = logging.getLogger("perimtr")


class DataStore:
    """Manages assessment data stored as local JSON files."""

    def __init__(self, data_dir: str, project_name: str):
        self.base_dir = Path(data_dir) / project_name
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def save_assessment(self, results: dict) -> Path:
        """
        Save an assessment to a timestamped JSON file.

        Args:
            results: Complete assessment results dict

        Returns:
            Path to the saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"assessment_{timestamp}.json"
        filepath = self.base_dir / filename

        # Add metadata
        results["_assessment"] = {
            "timestamp": datetime.now().isoformat(),
            "timestamp_id": timestamp,
            "version": "1.0.0",
        }

        with open(filepath, "w") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Assessment saved: {filepath}")
        return filepath

    def load_assessment(self, filepath: str) -> dict:
        """Load a specific assessment from file."""
        with open(filepath, "r") as f:
            return json.load(f)

    def get_latest_assessment(self) -> Optional[dict]:
        """Get the most recent assessment."""
        files = self.list_assessments()
        if not files:
            return None
        latest = files[-1]
        return self.load_assessment(latest)

    def get_previous_assessment(self) -> Optional[dict]:
        """Get the second-most-recent assessment (for diffing)."""
        files = self.list_assessments()
        if len(files) < 2:
            return None
        return self.load_assessment(files[-2])

    def list_assessments(self) -> list:
        """List all assessment files sorted by date."""
        files = sorted(self.base_dir.glob("assessment_*.json"))
        return [str(f) for f in files]

    def get_assessment_count(self) -> int:
        """Return number of stored assessments."""
        return len(self.list_assessments())
