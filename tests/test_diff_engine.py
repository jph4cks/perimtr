"""Tests for the diff/change detection engine."""

import pytest

from perimtr.core.diff_engine import DiffEngine


@pytest.fixture
def diff_engine():
    return DiffEngine()


class TestDiffEngine:
    def test_empty_comparison(self, diff_engine):
        """Test comparing two empty assessments."""
        diff = diff_engine.compare({}, {})
        assert diff["summary"]["has_changes"] is False
        assert diff["summary"]["total_new"] == 0

    def test_new_port_detected(self, diff_engine):
        """Test detection of new open ports."""
        current = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}, {"port": 443}, {"port": 8080}]},
                }
            }
        }
        previous = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}, {"port": 443}]},
                }
            }
        }

        diff = diff_engine.compare(current, previous)
        assert diff["summary"]["has_changes"] is True
        new_ports = [c for c in diff["new"] if c["type"] == "new_port"]
        assert len(new_ports) == 1
        assert "8080" in new_ports[0]["detail"]

    def test_closed_port_detected(self, diff_engine):
        """Test detection of closed ports."""
        current = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}]},
                }
            }
        }
        previous = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}, {"port": 22}]},
                }
            }
        }

        diff = diff_engine.compare(current, previous)
        removed = [c for c in diff["removed"] if c["type"] == "closed_port"]
        assert len(removed) == 1
        assert "22" in removed[0]["detail"]

    def test_new_host_detected(self, diff_engine):
        """Test detection of new hosts."""
        current = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}]},
                    "10.0.0.2": {"ports": [{"port": 22}]},
                }
            }
        }
        previous = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}]},
                }
            }
        }

        diff = diff_engine.compare(current, previous)
        new_hosts = [c for c in diff["new"] if c["type"] == "new_host"]
        assert len(new_hosts) == 1
        assert "10.0.0.2" in new_hosts[0]["host"]

    def test_host_gone(self, diff_engine):
        """Test detection of hosts that stopped responding."""
        current = {"port_scanner": {"hosts": {}}}
        previous = {
            "port_scanner": {
                "hosts": {"10.0.0.1": {"ports": [{"port": 80}]}}
            }
        }

        diff = diff_engine.compare(current, previous)
        gone = [c for c in diff["removed"] if c["type"] == "host_gone"]
        assert len(gone) == 1

    def test_new_subdomain_detected(self, diff_engine):
        """Test detection of new subdomains."""
        current = {"dns_enum": {"subdomains": ["www.test.com", "api.test.com", "dev.test.com"]}}
        previous = {"dns_enum": {"subdomains": ["www.test.com", "api.test.com"]}}

        diff = diff_engine.compare(current, previous)
        new_subs = [c for c in diff["new"] if c["type"] == "new_subdomain"]
        assert len(new_subs) == 1
        assert "dev.test.com" in new_subs[0]["detail"]

    def test_dns_record_change(self, diff_engine):
        """Test detection of DNS record changes."""
        current = {"dns_enum": {"subdomains": [], "records": {"test.com": ["1.2.3.4"]}}}
        previous = {"dns_enum": {"subdomains": [], "records": {"test.com": ["5.6.7.8"]}}}

        diff = diff_engine.compare(current, previous)
        changes = [c for c in diff["changed"] if c["type"] == "dns_record_changed"]
        assert len(changes) == 1

    def test_new_missing_header(self, diff_engine):
        """Test detection of new missing security headers."""
        current = {
            "http_headers": {
                "results": {
                    "test.com": {"missing_headers": ["HSTS", "CSP", "X-Frame-Options"]}
                }
            }
        }
        previous = {
            "http_headers": {
                "results": {
                    "test.com": {"missing_headers": ["HSTS", "CSP"]}
                }
            }
        }

        diff = diff_engine.compare(current, previous)
        new_missing = [c for c in diff["new"] if c["type"] == "new_missing_header"]
        assert len(new_missing) == 1
        assert "X-Frame-Options" in new_missing[0]["detail"]

    def test_header_fixed(self, diff_engine):
        """Test detection of fixed headers."""
        current = {
            "http_headers": {
                "results": {"test.com": {"missing_headers": ["CSP"]}}
            }
        }
        previous = {
            "http_headers": {
                "results": {"test.com": {"missing_headers": ["CSP", "HSTS"]}}
            }
        }

        diff = diff_engine.compare(current, previous)
        fixed = [c for c in diff["removed"] if c["type"] == "header_fixed"]
        assert len(fixed) == 1
        assert "HSTS" in fixed[0]["detail"]

    def test_new_vulnerability(self, diff_engine):
        """Test detection of new vulnerabilities."""
        current = {
            "vuln_check": {
                "findings": [
                    {"host": "10.0.0.1", "id": "TELNET-OPEN", "port": 23},
                    {"host": "10.0.0.1", "id": "FTP-ANON", "port": 21},
                ]
            }
        }
        previous = {
            "vuln_check": {
                "findings": [
                    {"host": "10.0.0.1", "id": "TELNET-OPEN", "port": 23},
                ]
            }
        }

        diff = diff_engine.compare(current, previous)
        new_vulns = [c for c in diff["new"] if c["type"] == "new_vulnerability"]
        assert len(new_vulns) == 1
        assert "FTP-ANON" in new_vulns[0]["detail"]

    def test_vulnerability_remediated(self, diff_engine):
        """Test detection of remediated vulnerabilities."""
        current = {"vuln_check": {"findings": []}}
        previous = {
            "vuln_check": {
                "findings": [
                    {"host": "10.0.0.1", "id": "RDP-EXPOSED", "port": 3389},
                ]
            }
        }

        diff = diff_engine.compare(current, previous)
        remediated = [c for c in diff["removed"] if c["type"] == "vuln_remediated"]
        assert len(remediated) == 1

    def test_cert_issuer_change(self, diff_engine):
        """Test detection of certificate issuer changes."""
        current = {
            "whois_cert": {
                "certificates": {
                    "test.com": {"issuer": "Let's Encrypt", "expiry": "2026-01-01"}
                }
            }
        }
        previous = {
            "whois_cert": {
                "certificates": {
                    "test.com": {"issuer": "DigiCert", "expiry": "2026-01-01"}
                }
            }
        }

        diff = diff_engine.compare(current, previous)
        changes = [c for c in diff["changed"] if c["type"] == "cert_issuer_changed"]
        assert len(changes) == 1
        assert changes[0]["severity"] == "high"

    def test_domain_security_new_issue(self, diff_engine):
        """Test detection of new domain security issues."""
        current = {
            "domain_security": {
                "results": {
                    "test.com": {
                        "issues": [
                            {"issue": "no_dmarc"},
                            {"issue": "no_spf"},
                        ]
                    }
                }
            }
        }
        previous = {
            "domain_security": {
                "results": {
                    "test.com": {
                        "issues": [{"issue": "no_dmarc"}]
                    }
                }
            }
        }

        diff = diff_engine.compare(current, previous)
        new_issues = [c for c in diff["new"] if c["type"] == "new_domain_issue"]
        assert len(new_issues) == 1

    def test_summary_counts(self, diff_engine):
        """Test that summary counts are correct."""
        current = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}, {"port": 8080}]},
                    "10.0.0.2": {"ports": [{"port": 22}]},
                }
            },
            "dns_enum": {"subdomains": ["new.test.com"], "records": {}},
        }
        previous = {
            "port_scanner": {
                "hosts": {
                    "10.0.0.1": {"ports": [{"port": 80}]},
                }
            },
            "dns_enum": {"subdomains": [], "records": {}},
        }

        diff = diff_engine.compare(current, previous)
        assert diff["summary"]["has_changes"] is True
        assert diff["summary"]["total_new"] > 0
