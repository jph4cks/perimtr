"""Tests for the LLM analysis engine."""

import pytest
from unittest.mock import patch, MagicMock

from perimtr.core.config import DEFAULT_CONFIG
from perimtr.core.llm_engine import LLMEngine


@pytest.fixture
def config_no_llm():
    """Config without LLM."""
    config = dict(DEFAULT_CONFIG)
    config["llm"] = {"provider": None}
    return config


@pytest.fixture
def config_with_llm():
    """Config with OpenAI LLM."""
    config = dict(DEFAULT_CONFIG)
    config["llm"] = {
        "provider": "openai",
        "api_key": "sk-test-key",
        "model": "gpt-4o-mini",
        "base_url": None,
    }
    return config


@pytest.fixture
def sample_assessment():
    """Sample assessment data for testing."""
    return {
        "port_scanner": {
            "hosts": {
                "10.0.0.1": {
                    "ports": [
                        {"port": 80, "service": "http"},
                        {"port": 443, "service": "https"},
                        {"port": 22, "service": "ssh"},
                    ]
                }
            },
            "total_open_ports": 3,
        },
        "dns_enum": {
            "subdomains": ["www.test.com", "api.test.com", "dev.test.com"],
            "zone_transfer": {},
        },
        "http_headers": {
            "total_issues": 5,
            "results": {
                "test.com": {
                    "missing_headers": ["HSTS", "CSP"],
                    "info_leaks": [{"header": "Server"}],
                    "issues": [
                        {"severity": "high", "detail": "Missing HSTS"},
                        {"severity": "high", "detail": "Missing CSP"},
                    ],
                }
            },
        },
        "vuln_check": {
            "findings": [
                {"id": "HTTP-CLEARTEXT", "severity": "medium", "detail": "HTTP without TLS", "host": "10.0.0.1"},
            ],
            "summary": {"severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0}},
        },
        "domain_security": {
            "results": {
                "test.com": {
                    "spf": {"exists": True},
                    "dmarc": {"exists": False, "policy": None},
                    "dkim": {"found_selectors": []},
                    "dnssec": {"enabled": False},
                    "caa": {"exists": False},
                    "issues": [
                        {"issue": "no_dmarc", "severity": "high", "detail": "No DMARC"},
                        {"issue": "no_dnssec", "severity": "medium", "detail": "No DNSSEC"},
                    ],
                }
            }
        },
        "whois_cert": {
            "certificates": {
                "test.com": {
                    "days_until_expiry": 90,
                    "issuer": {"organizationName": "Let's Encrypt"},
                    "protocol": "TLSv1.3",
                    "key_info": {"algorithm": "RSA", "key_size": 2048},
                }
            },
            "issues": [],
        },
    }


class TestLLMEngine:
    def test_no_llm_available(self, config_no_llm):
        """Test engine without LLM configured."""
        engine = LLMEngine(config_no_llm)
        assert engine.available is False

    def test_llm_available(self, config_with_llm):
        """Test engine with LLM configured."""
        engine = LLMEngine(config_with_llm)
        assert engine.available is True

    def test_basic_analysis_structure(self, config_no_llm, sample_assessment):
        """Test basic analysis returns correct structure."""
        engine = LLMEngine(config_no_llm)
        analysis = engine.analyze(sample_assessment)

        assert "executive_summary" in analysis
        assert "risk_score" in analysis
        assert "risk_rating" in analysis
        assert "priority_actions" in analysis
        assert "recommendations" in analysis
        assert "findings_analysis" in analysis
        assert analysis["llm_generated"] is False

    def test_basic_risk_score(self, config_no_llm, sample_assessment):
        """Test risk score calculation."""
        engine = LLMEngine(config_no_llm)
        analysis = engine.analyze(sample_assessment)

        # Should have a risk score > 20 (base) due to findings
        assert analysis["risk_score"] > 20
        assert analysis["risk_score"] <= 100
        assert analysis["risk_rating"] in ("critical", "high", "medium", "low")

    def test_basic_analysis_with_diff(self, config_no_llm, sample_assessment):
        """Test basic analysis includes diff info."""
        engine = LLMEngine(config_no_llm)
        diff = {
            "summary": {"has_changes": True, "total_new": 3, "total_removed": 1, "total_changed": 2},
            "new": [], "removed": [], "changed": [],
        }
        analysis = engine.analyze(sample_assessment, diff)
        assert "previous assessment" in analysis["executive_summary"].lower() or "3 new" in analysis["executive_summary"]

    def test_recommendations_generated(self, config_no_llm, sample_assessment):
        """Test that recommendations are generated."""
        engine = LLMEngine(config_no_llm)
        analysis = engine.analyze(sample_assessment)
        assert len(analysis["recommendations"]) > 0
        # Should recommend DMARC since it's missing
        dmarc_recs = [r for r in analysis["recommendations"] if "DMARC" in r.get("recommendation", "")]
        assert len(dmarc_recs) > 0

    def test_priority_actions_ordered(self, config_no_llm, sample_assessment):
        """Test that priority actions are ordered."""
        engine = LLMEngine(config_no_llm)
        analysis = engine.analyze(sample_assessment)
        actions = analysis.get("priority_actions", [])
        if len(actions) > 1:
            # Should be numbered sequentially
            for i, action in enumerate(actions):
                assert action["priority"] == i + 1

    def test_summarize_assessment(self, config_no_llm, sample_assessment):
        """Test assessment summarization."""
        engine = LLMEngine(config_no_llm)
        summary = engine._summarize_assessment(sample_assessment)

        assert "network" in summary
        assert summary["network"]["hosts_found"] == 1
        assert summary["network"]["total_open_ports"] == 3

        assert "dns" in summary
        assert summary["dns"]["subdomains_found"] == 3

        assert "web_security" in summary
        assert summary["web_security"]["total_issues"] == 5

        assert "domain_security" in summary

    def test_llm_fallback_on_error(self, config_with_llm, sample_assessment):
        """Test that LLM failure falls back to basic analysis."""
        engine = LLMEngine(config_with_llm)
        with patch.object(engine, '_generate_llm_analysis', side_effect=Exception("API error")):
            analysis = engine.analyze(sample_assessment)
            # Should fall back to basic analysis
            assert analysis["llm_generated"] is False
            assert "executive_summary" in analysis

    def test_empty_assessment(self, config_no_llm):
        """Test analysis of empty assessment."""
        engine = LLMEngine(config_no_llm)
        analysis = engine.analyze({})
        assert analysis["risk_score"] == 20  # Base score
        assert analysis["risk_rating"] == "low"
