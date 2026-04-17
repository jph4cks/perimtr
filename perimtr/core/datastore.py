"""
JSON-based local data store for assessment results.

Each assessment is stored as a timestamped JSON file:
  data/<project_name>/assessment_<timestamp>.json
"""

import csv
import fcntl
import json
import logging
import os
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional

logger = logging.getLogger("perimtr")


class DataStore:
    """Manages assessment data stored as local JSON files."""

    def __init__(self, data_dir: str, project_name: str):
        self.base_dir = Path(data_dir) / project_name
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.base_dir / ".datastore.lock"

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def save_assessment(self, results: dict) -> Path:
        """Save an assessment to a timestamped JSON file.

        Uses a file lock to prevent concurrent writes from corrupting the
        data directory.

        Args:
            results: Complete assessment results dict.  A ``_assessment``
                metadata key is added in-place.

        Returns:
            :class:`~pathlib.Path` to the saved file.
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

        with open(self._lock_path, "w") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                with open(filepath, "w") as f:
                    json.dump(results, f, indent=2, default=str)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

        logger.info(f"Assessment saved: {filepath}")
        return filepath

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def load_assessment(self, filepath: str) -> dict:
        """Load a specific assessment from file.

        Args:
            filepath: Path to the assessment JSON file.

        Returns:
            Parsed assessment dict.

        Raises:
            json.JSONDecodeError: If the file contains invalid JSON and
                strict parsing is required (callers that want graceful
                handling should use :meth:`list_assessments` which skips
                corrupt files automatically).
        """
        with open(filepath, "r") as f:
            return json.load(f)

    def get_latest_assessment(self) -> Optional[dict]:
        """Get the most recent assessment.

        Corrupt JSON files are skipped with a warning.

        Returns:
            The parsed assessment dict or ``None`` if no valid assessments exist.
        """
        files = self.list_assessments()
        # Iterate from most-recent backwards, skipping corrupt files
        for filepath in reversed(files):
            try:
                return self.load_assessment(filepath)
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning(f"Skipping corrupt assessment file {filepath}: {exc}")
        return None

    def get_previous_assessment(self) -> Optional[dict]:
        """Get the second-most-recent assessment (for diffing).

        Corrupt JSON files are skipped with a warning.

        Returns:
            The parsed assessment dict or ``None`` if fewer than two valid
            assessments exist.
        """
        files = self.list_assessments()
        valid_count = 0
        for filepath in reversed(files):
            try:
                data = self.load_assessment(filepath)
                valid_count += 1
                if valid_count == 2:
                    return data
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning(f"Skipping corrupt assessment file {filepath}: {exc}")
        return None

    def list_assessments(self) -> list:
        """List all assessment files sorted by date.

        Returns:
            Sorted list of file path strings (oldest first).
        """
        files = sorted(self.base_dir.glob("assessment_*.json"))
        return [str(f) for f in files]

    def get_assessment_count(self) -> int:
        """Return number of stored assessments."""
        return len(self.list_assessments())

    # ------------------------------------------------------------------
    # Maintenance helpers
    # ------------------------------------------------------------------

    def cleanup_old_assessments(self, keep: int = 10) -> int:
        """Remove oldest assessment files, keeping at most *keep* files.

        Args:
            keep: Number of most-recent files to retain.  Must be >= 1.

        Returns:
            Number of files that were deleted.

        Raises:
            ValueError: If *keep* is less than 1.
        """
        if keep < 1:
            raise ValueError(f"keep must be >= 1, got {keep}")

        files = self.list_assessments()  # sorted oldest-first
        to_delete = files[: max(0, len(files) - keep)]
        deleted = 0
        for filepath in to_delete:
            try:
                Path(filepath).unlink()
                deleted += 1
                logger.debug(f"Deleted old assessment: {filepath}")
            except OSError as exc:
                logger.warning(f"Could not delete {filepath}: {exc}")
        if deleted:
            logger.info(f"Cleaned up {deleted} old assessment file(s) (kept {keep})")
        return deleted

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def export_assessment(self, assessment_id: str, format: str = "json") -> str:
        """Export a specific assessment in JSON or CSV format.

        The exported content is returned as a string (not written to disk).
        Callers can write the string to any desired destination.

        Args:
            assessment_id: The ``timestamp_id`` value (e.g. ``"20240101_120000"``)
                or a full file path to the assessment JSON file.
            format: ``'json'`` (default) or ``'csv'``.

        Returns:
            Serialised assessment as a JSON or CSV string.

        Raises:
            FileNotFoundError: If no matching assessment file can be located.
            ValueError: If *format* is not one of ``'json'`` or ``'csv'``.
            json.JSONDecodeError: If the assessment file is corrupt.
        """
        if format not in ("json", "csv"):
            raise ValueError(f"Unsupported export format: {format!r}. Use 'json' or 'csv'.")

        # Resolve the file path
        filepath = self._resolve_assessment_path(assessment_id)
        data = self.load_assessment(filepath)

        if format == "json":
            return json.dumps(data, indent=2, default=str)

        # CSV export — flatten top-level module results into rows
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["module", "key", "value"])
        for module_name, module_data in data.items():
            if module_name.startswith("_"):
                continue
            if isinstance(module_data, dict):
                for key, value in module_data.items():
                    if key == "_meta":
                        continue
                    writer.writerow([module_name, key, json.dumps(value, default=str)])
            else:
                writer.writerow([module_name, "", json.dumps(module_data, default=str)])
        return output.getvalue()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_assessment_path(self, assessment_id: str) -> str:
        """Resolve an assessment_id or filepath to an existing file path.

        Args:
            assessment_id: Either a ``timestamp_id`` (bare ID like
                ``"20240101_120000"``) or a full path string.

        Returns:
            Absolute file path string.

        Raises:
            FileNotFoundError: If no matching file is found.
        """
        # If it looks like an existing path, use it directly
        candidate = Path(assessment_id)
        if candidate.exists():
            return str(candidate)

        # Try constructing the canonical filename from a bare timestamp_id
        canonical = self.base_dir / f"assessment_{assessment_id}.json"
        if canonical.exists():
            return str(canonical)

        raise FileNotFoundError(
            f"No assessment found for id/path: {assessment_id!r}"
        )
