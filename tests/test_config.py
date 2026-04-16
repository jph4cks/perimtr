"""Tests for configuration management."""

import os
import pytest
import yaml
from pathlib import Path

from perimtr.core.config import Config, DEFAULT_CONFIG


@pytest.fixture
def tmp_config(tmp_path):
    """Create a temporary config file."""
    config_path = tmp_path / "test_config.yaml"
    return Config(str(config_path))


class TestConfig:
    def test_default_config_structure(self):
        """Verify default config has all required keys."""
        assert "project_name" in DEFAULT_CONFIG
        assert "targets" in DEFAULT_CONFIG
        assert "networks" in DEFAULT_CONFIG["targets"]
        assert "domains" in DEFAULT_CONFIG["targets"]
        assert "schedule" in DEFAULT_CONFIG
        assert "scan_settings" in DEFAULT_CONFIG
        assert "modules" in DEFAULT_CONFIG
        assert "llm" in DEFAULT_CONFIG
        assert "data_dir" in DEFAULT_CONFIG

    def test_config_save_and_load(self, tmp_config):
        """Test saving and loading configuration."""
        tmp_config.data["project_name"] = "test-project"
        tmp_config.data["targets"]["domains"] = ["example.com"]
        tmp_config.data["targets"]["networks"] = ["10.0.0.0/24"]
        tmp_config.save()

        assert tmp_config.config_path.exists()

        # Load it back
        loaded = Config(str(tmp_config.config_path))
        loaded.load()
        assert loaded.data["project_name"] == "test-project"
        assert "example.com" in loaded.data["targets"]["domains"]
        assert "10.0.0.0/24" in loaded.data["targets"]["networks"]

    def test_config_exists(self, tmp_config):
        """Test exists() method."""
        assert not tmp_config.exists()
        tmp_config.save()
        assert tmp_config.exists()

    def test_config_load_nonexistent(self, tmp_config):
        """Test loading non-existent config raises error."""
        with pytest.raises(FileNotFoundError):
            tmp_config.load()

    def test_deep_merge(self):
        """Test deep merge of configs."""
        base = {"a": 1, "b": {"c": 2, "d": 3}, "e": 4}
        override = {"b": {"c": 99}, "f": 5}
        result = Config._deep_merge(base, override)

        assert result["a"] == 1
        assert result["b"]["c"] == 99
        assert result["b"]["d"] == 3
        assert result["e"] == 4
        assert result["f"] == 5

    def test_config_partial_load(self, tmp_config):
        """Test loading config with only some keys merges with defaults."""
        # Write a minimal config
        minimal = {"project_name": "minimal", "targets": {"domains": ["test.com"]}}
        with open(tmp_config.config_path, "w") as f:
            yaml.dump(minimal, f)

        tmp_config.load()
        assert tmp_config.data["project_name"] == "minimal"
        assert tmp_config.data["targets"]["domains"] == ["test.com"]
        # Defaults should be preserved
        assert "scan_settings" in tmp_config.data
        assert "modules" in tmp_config.data
        assert tmp_config.data["scan_settings"]["port_scan_rate"] == 10

    def test_get_data_dir(self, tmp_config):
        """Test data directory creation."""
        tmp_config.data["data_dir"] = str(tmp_config.config_path.parent / "test_data")
        data_dir = tmp_config.get_data_dir()
        assert data_dir.exists()

    def test_module_config(self):
        """Test that all expected modules are in default config."""
        modules = DEFAULT_CONFIG["modules"]
        assert "port_scanner" in modules
        assert "dns_enum" in modules
        assert "http_headers" in modules
        assert "whois_cert" in modules
        assert "vuln_check" in modules
        assert "domain_security" in modules
        for mod in modules.values():
            assert mod["enabled"] is True
