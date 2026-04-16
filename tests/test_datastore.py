"""Tests for the data store."""

import json
import pytest
from pathlib import Path

from perimtr.core.datastore import DataStore


@pytest.fixture
def datastore(tmp_path):
    """Create a temporary datastore."""
    return DataStore(str(tmp_path), "test-project")


class TestDataStore:
    def test_init_creates_directory(self, datastore):
        """Test that initialization creates the project directory."""
        assert Path(datastore.base_dir).exists()

    def test_save_assessment(self, datastore):
        """Test saving an assessment."""
        results = {
            "port_scanner": {"hosts": {"10.0.0.1": {"ports": [{"port": 80}]}}},
            "dns_enum": {"subdomains": ["www.test.com"]},
        }
        path = datastore.save_assessment(results)
        assert Path(path).exists()

        # Verify content
        with open(path) as f:
            saved = json.load(f)
        assert "port_scanner" in saved
        assert "_assessment" in saved
        assert "timestamp" in saved["_assessment"]

    def test_load_assessment(self, datastore):
        """Test loading an assessment."""
        results = {"test_key": "test_value"}
        path = datastore.save_assessment(results)

        loaded = datastore.load_assessment(str(path))
        assert loaded["test_key"] == "test_value"
        assert "_assessment" in loaded

    def test_get_latest_assessment(self, datastore):
        """Test getting the latest assessment."""
        # No assessments
        assert datastore.get_latest_assessment() is None

        # Add one
        datastore.save_assessment({"order": 1})
        import time
        time.sleep(0.1)
        datastore.save_assessment({"order": 2})

        latest = datastore.get_latest_assessment()
        assert latest["order"] == 2

    def test_get_previous_assessment(self, datastore):
        """Test getting the previous assessment for diffing."""
        # Need at least 2
        assert datastore.get_previous_assessment() is None

        datastore.save_assessment({"order": 1})
        assert datastore.get_previous_assessment() is None  # Still only 1

        import time
        time.sleep(1.1)  # Ensure different timestamp
        datastore.save_assessment({"order": 2})

        previous = datastore.get_previous_assessment()
        assert previous is not None
        assert previous["order"] == 1

    def test_list_assessments(self, datastore):
        """Test listing all assessments."""
        assert len(datastore.list_assessments()) == 0

        datastore.save_assessment({"test": 1})
        import time
        time.sleep(1.1)  # Ensure different timestamp
        datastore.save_assessment({"test": 2})

        files = datastore.list_assessments()
        assert len(files) == 2
        # Should be sorted chronologically
        assert files[0] < files[1]

    def test_assessment_count(self, datastore):
        """Test assessment count."""
        assert datastore.get_assessment_count() == 0
        datastore.save_assessment({"test": 1})
        assert datastore.get_assessment_count() == 1
