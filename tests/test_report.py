"""Tests for HTML report generation."""

import os
import pytest
from pathlib import Path

from perimtr.core.config import DEFAULT_CONFIG
from perimtr.reports.html_report import HTMLReportGenerator


@pytest.fixture
def config():
    config = dict(DEFAULT_CONFIG)
    config["project_name"] = "test-project"
    return config


@pytest.fixture
def sample_assessment():
    """Realistic sample assessment for report testing."""
    return {
        "_assessment": {
            "timestamp": "2026-04-16T10:00:00",
            "version": "1.0.0",
        },
        "port_scanner": {
            "hosts": {
                "10.0.0.1": {
                    "ports": [
                        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "2.4.41", "product": "Apache"},
                        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "", "product": ""},
                        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "8.9", "product": "OpenSSH"},
                    ],
                    "hostname": "web1.example.com",
                },
                "10.0.0.2": {
                    "ports": [
                        {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "8.0", "product": "MySQL"},
                    ],
                    "hostname": "db1.example.com",
                },
            },
            "total_open_ports": 4,
        },
        "dns_enum": {
            "subdomains": ["www.example.com", "api.example.com", "dev.example.com", "staging.example.com"],
            "records": {
                "example.com": {"A": ["10.0.0.1"], "MX": ["mail.example.com"], "NS": ["ns1.example.com"]},
            },
            "zone_transfer": {},
        },
        "http_headers": {
            "total_issues": 3,
            "results": {
                "example.com": {
                    "url": "https://example.com",
                    "status_code": 200,
                    "present_headers": [{"header": "Strict-Transport-Security", "value": "max-age=31536000"}],
                    "missing_headers": ["Content-Security-Policy", "Permissions-Policy"],
                    "info_leaks": [{"header": "Server", "value": "nginx/1.19.0", "severity": "low"}],
                    "cookie_issues": [],
                    "tls_info": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
                    "issues": [
                        {"issue": "missing_csp", "severity": "high", "detail": "Missing CSP", "recommendation": "Add CSP header"},
                    ],
                }
            },
        },
        "whois_cert": {
            "certificates": {
                "example.com": {
                    "subject": {"commonName": "example.com"},
                    "issuer": {"organizationName": "Let's Encrypt"},
                    "san": ["example.com", "www.example.com"],
                    "expiry": "Jun 15 12:00:00 2026 GMT",
                    "days_until_expiry": 60,
                    "protocol": "TLSv1.3",
                    "key_info": {"algorithm": "RSA", "key_size": 2048},
                }
            },
            "whois": {
                "example.com": {
                    "registrar": "Namecheap",
                    "creation_date": "2020-01-01",
                    "expiration_date": "2027-01-01",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                    "dnssec": "unsigned",
                }
            },
            "issues": [],
        },
        "vuln_check": {
            "findings": [
                {
                    "id": "MYSQL-EXPOSED",
                    "name": "MySQL Exposed",
                    "severity": "critical",
                    "detail": "MySQL exposed on port 3306",
                    "recommendation": "Restrict access",
                    "host": "10.0.0.2",
                    "domain": "db1.example.com",
                    "port": 3306,
                    "banner": "MySQL 8.0",
                },
            ],
            "summary": {"total_findings": 1, "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}},
        },
        "domain_security": {
            "results": {
                "example.com": {
                    "spf": {"exists": True, "record": "v=spf1 include:_spf.google.com -all", "issues": []},
                    "dmarc": {"exists": True, "policy": "quarantine", "record": "v=DMARC1; p=quarantine; rua=mailto:d@example.com", "issues": [
                        {"issue": "dmarc_quarantine", "severity": "low", "detail": "DMARC quarantine, reject is stronger", "recommendation": "Upgrade to reject"}
                    ]},
                    "dkim": {"found_selectors": [{"selector": "google", "record": "v=DKIM1; k=rsa; p=MIG..."}], "issues": []},
                    "dnssec": {"enabled": False, "issues": [
                        {"issue": "no_dnssec", "severity": "medium", "detail": "DNSSEC not enabled", "recommendation": "Enable DNSSEC"}
                    ]},
                    "caa": {"exists": False, "issues": [
                        {"issue": "no_caa", "severity": "low", "detail": "No CAA records", "recommendation": "Add CAA records"}
                    ]},
                    "mx_security": {"records": [{"priority": 10, "host": "mail.example.com"}], "issues": []},
                    "issues": [],
                }
            }
        },
    }


class TestHTMLReport:
    def test_generate_report(self, config, sample_assessment, tmp_path):
        """Test basic report generation."""
        generator = HTMLReportGenerator(config)
        output = str(tmp_path / "test_report.html")
        result = generator.generate(sample_assessment, output_path=output)

        assert os.path.exists(result)
        content = open(result).read()
        assert "Perimtr" in content
        assert "test-project" in content
        assert "10.0.0.1" in content

    def test_report_contains_all_sections(self, config, sample_assessment, tmp_path):
        """Test report contains all navigation tabs."""
        generator = HTMLReportGenerator(config)
        output = str(tmp_path / "test_report.html")
        generator.generate(sample_assessment, output_path=output)

        content = open(output).read()
        assert "tab-overview" in content
        assert "tab-network" in content
        assert "tab-dns" in content
        assert "tab-web" in content
        assert "tab-certs" in content
        assert "tab-domain" in content
        assert "tab-vulns" in content
        assert "tab-all-issues" in content

    def test_report_with_diff(self, config, sample_assessment, tmp_path):
        """Test report with diff data."""
        diff = {
            "new": [{"severity": "high", "detail": "New port 8080", "module": "port_scanner", "type": "new_port"}],
            "removed": [{"severity": "info", "detail": "Port 22 closed", "module": "port_scanner", "type": "closed_port"}],
            "changed": [],
            "summary": {"total_new": 1, "total_removed": 1, "total_changed": 0, "has_changes": True},
        }

        generator = HTMLReportGenerator(config)
        output = str(tmp_path / "test_report_diff.html")
        generator.generate(sample_assessment, diff=diff, output_path=output)

        content = open(output).read()
        assert "tab-changes" in content
        assert "New port 8080" in content

    def test_report_with_analysis(self, config, sample_assessment, tmp_path):
        """Test report with LLM analysis."""
        analysis = {
            "executive_summary": "This is a test executive summary.",
            "risk_score": 65,
            "risk_rating": "high",
            "priority_actions": [
                {"priority": 1, "action": "Fix MySQL exposure", "effort": "low", "impact": "Critical risk reduction"},
            ],
            "recommendations": [
                {"category": "Network", "recommendation": "Restrict database ports", "priority": "critical"},
            ],
        }

        generator = HTMLReportGenerator(config)
        output = str(tmp_path / "test_report_analysis.html")
        generator.generate(sample_assessment, llm_analysis=analysis, output_path=output)

        content = open(output).read()
        assert "tab-analysis" in content
        assert "test executive summary" in content
        assert "65" in content

    def test_collect_all_issues(self, config, sample_assessment):
        """Test issue collection from all modules."""
        generator = HTMLReportGenerator(config)
        issues = generator._collect_all_issues(sample_assessment)

        assert len(issues) > 0
        # Should be sorted by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i in range(len(issues) - 1):
            current_sev = severity_order.get(issues[i]["severity"], 5)
            next_sev = severity_order.get(issues[i + 1]["severity"], 5)
            assert current_sev <= next_sev

    def test_report_valid_html(self, config, sample_assessment, tmp_path):
        """Test that generated HTML is valid."""
        generator = HTMLReportGenerator(config)
        output = str(tmp_path / "test_report.html")
        generator.generate(sample_assessment, output_path=output)

        content = open(output).read()
        assert content.startswith("<!DOCTYPE html>")
        assert "</html>" in content
        assert "<script>" in content
        assert "</script>" in content

    def test_empty_assessment_report(self, config, tmp_path):
        """Test report generation with empty assessment."""
        generator = HTMLReportGenerator(config)
        output = str(tmp_path / "empty_report.html")
        generator.generate({"_assessment": {"timestamp": "2026-04-16T10:00:00", "version": "1.0.0"}}, output_path=output)

        assert os.path.exists(output)
        content = open(output).read()
        assert "Perimtr" in content
