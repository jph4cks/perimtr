"""Tests for recon modules."""

import pytest
from unittest.mock import patch, MagicMock

from perimtr.core.config import DEFAULT_CONFIG
from perimtr.modules.port_scanner import PortScanner
from perimtr.modules.dns_enum import DNSEnum
from perimtr.modules.http_headers import HTTPHeaders, SECURITY_HEADERS
from perimtr.modules.whois_cert import WhoisCert
from perimtr.modules.vuln_check import VulnCheck
from perimtr.modules.domain_security import DomainSecurity


@pytest.fixture
def config():
    return dict(DEFAULT_CONFIG)


@pytest.fixture
def targets():
    return {
        "networks": [],
        "domains": ["example.com"],
    }


class TestPortScanner:
    def test_initialization(self, config):
        """Test module initialization."""
        scanner = PortScanner(config)
        assert scanner.name == "port_scanner"
        assert scanner.category == "network"

    def test_is_enabled(self, config):
        """Test enabled check."""
        scanner = PortScanner(config)
        assert scanner.is_enabled(config) is True

        config["modules"]["port_scanner"]["enabled"] = False
        assert scanner.is_enabled(config) is False

    def test_safe_run_with_error(self, config):
        """Test safe_run catches errors."""
        scanner = PortScanner(config)
        with patch.object(scanner, 'run', side_effect=Exception("test error")):
            result = scanner.safe_run({"networks": [], "domains": []})
            assert result["_meta"]["status"] == "error"
            assert "test error" in result["_meta"]["error"]

    def test_get_service_name(self):
        """Test service name lookup."""
        assert PortScanner._get_service_name(80) == "http"
        assert PortScanner._get_service_name(443) == "https"
        assert PortScanner._get_service_name(22) == "ssh"
        assert PortScanner._get_service_name(3306) == "mysql"
        assert PortScanner._get_service_name(99999) == "unknown"

    @patch("socket.gethostbyname")
    @patch("socket.socket")
    def test_socket_scan_fallback(self, mock_socket, mock_resolve, config):
        """Test socket-based scan fallback."""
        mock_resolve.return_value = "93.184.216.34"
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # All ports closed
        mock_socket.return_value = mock_sock

        scanner = PortScanner(config)
        scanner.scan_settings["port_scan_rate"] = 1000  # Fast for tests

        result = scanner._scan_with_sockets([], {"example.com": "93.184.216.34"}, {
            "hosts": {}, "total_hosts_scanned": 0, "total_open_ports": 0
        })
        assert result["total_hosts_scanned"] == 1


class TestDNSEnum:
    def test_initialization(self, config):
        """Test module initialization."""
        module = DNSEnum(config)
        assert module.name == "dns_enum"
        assert module.category == "dns"

    @patch("requests.get")
    def test_crtsh_subdomains(self, mock_get, config):
        """Test crt.sh subdomain discovery."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com\nwild.example.com"},
        ]
        mock_get.return_value = mock_response

        module = DNSEnum(config)
        subs = module._crtsh_subdomains("example.com")
        assert "www.example.com" in subs
        assert "api.example.com" in subs
        assert "wild.example.com" in subs

    def test_crtsh_failure_handled(self, config):
        """Test crt.sh failure is handled gracefully."""
        import requests as req
        with patch("perimtr.modules.dns_enum.requests.get", side_effect=req.RequestException("Connection failed")):
            module = DNSEnum(config)
            subs = module._crtsh_subdomains("example.com")
            assert subs == []


class TestHTTPHeaders:
    def test_initialization(self, config):
        """Test module initialization."""
        module = HTTPHeaders(config)
        assert module.name == "http_headers"
        assert module.category == "web"

    def test_security_headers_defined(self):
        """Verify all expected security headers are defined."""
        expected = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        for header in expected:
            assert header in SECURITY_HEADERS

    @patch("requests.get")
    def test_check_domain_success(self, mock_get, config):
        """Test successful domain header check."""
        mock_response = MagicMock()
        mock_response.url = "https://example.com"
        mock_response.status_code = 200
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Server": "nginx/1.19.0",
        }
        mock_response.history = []
        mock_get.return_value = mock_response

        module = HTTPHeaders(config)
        result = module._check_domain("example.com", 15)

        assert result["status_code"] == 200
        assert len(result["present_headers"]) >= 2
        assert len(result["missing_headers"]) > 0
        assert len(result["info_leaks"]) > 0  # Server header leaking

    def test_validate_hsts_weak(self, config):
        """Test HSTS validation for weak max-age."""
        module = HTTPHeaders(config)
        result = {"issues": []}
        module._validate_hsts("max-age=3600", result)
        assert any(i["issue"] == "weak_hsts_max_age" for i in result["issues"])

    def test_validate_csp_unsafe(self, config):
        """Test CSP validation for unsafe directives."""
        module = HTTPHeaders(config)
        result = {"issues": []}
        module._validate_csp("default-src 'self' 'unsafe-inline' 'unsafe-eval'", result)
        assert any(i["issue"] == "weak_csp" for i in result["issues"])


class TestWhoisCert:
    def test_initialization(self, config):
        """Test module initialization."""
        module = WhoisCert(config)
        assert module.name == "whois_cert"
        assert module.category == "cert"

    def test_cert_issue_detection_expired(self, config):
        """Test detection of expired certificate."""
        module = WhoisCert(config)
        results = {"issues": []}
        cert_data = {"days_until_expiry": -5}
        module._check_cert_issues("test.com", cert_data, results)
        assert any(i["issue"] == "cert_expired" for i in results["issues"])

    def test_cert_issue_detection_expiring_soon(self, config):
        """Test detection of certificate expiring soon."""
        module = WhoisCert(config)
        results = {"issues": []}
        cert_data = {"days_until_expiry": 15}
        module._check_cert_issues("test.com", cert_data, results)
        assert any(i["issue"] == "cert_expiring_soon" for i in results["issues"])

    def test_cert_issue_weak_key(self, config):
        """Test detection of weak certificate key."""
        module = WhoisCert(config)
        results = {"issues": []}
        cert_data = {"key_info": {"weak": True, "algorithm": "RSA", "key_size": 1024}}
        module._check_cert_issues("test.com", cert_data, results)
        assert any(i["issue"] == "weak_cert_key" for i in results["issues"])

    def test_cert_issue_deprecated_tls(self, config):
        """Test detection of deprecated TLS protocol."""
        module = WhoisCert(config)
        results = {"issues": []}
        cert_data = {"protocol": "TLSv1"}
        module._check_cert_issues("test.com", cert_data, results)
        assert any(i["issue"] == "deprecated_tls" for i in results["issues"])

    def test_self_signed_detection(self, config):
        """Test detection of self-signed certificates."""
        module = WhoisCert(config)
        results = {"issues": []}
        cert_data = {"self_signed": True, "error": "certificate_verification_failed"}
        module._check_cert_issues("test.com", cert_data, results)
        assert any(i["issue"] == "self_signed_certificate" for i in results["issues"])


class TestVulnCheck:
    def test_initialization(self, config):
        """Test module initialization."""
        module = VulnCheck(config)
        assert module.name == "vuln_check"
        assert module.category == "vuln"

    @patch("socket.socket")
    def test_is_port_open(self, mock_socket, config):
        """Test port open check."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock

        module = VulnCheck(config)
        assert module._is_port_open("10.0.0.1", 80) is True

    @patch("socket.socket")
    def test_is_port_closed(self, mock_socket, config):
        """Test port closed check."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock

        module = VulnCheck(config)
        assert module._is_port_open("10.0.0.1", 80) is False

    def test_dangerous_service_check(self, config):
        """Test dangerous service flagging."""
        module = VulnCheck(config)
        result = module._check_dangerous_service(
            "10.0.0.1", 3389,
            {"id": "RDP-EXPOSED", "name": "RDP Exposed", "severity": "critical",
             "recommendation": "Put behind VPN"},
            "RDP"
        )
        assert result["severity"] == "critical"
        assert "RDP" in result["detail"]

    def test_ssh_banner_weak_version(self, config):
        """Test SSH weak version detection."""
        module = VulnCheck(config)
        check = {"id": "SSH-WEAK-ALGO", "name": "SSH Weak", "severity": "medium",
                 "recommendation": "Update SSH"}

        # Weak version
        result = module._check_ssh_banner("10.0.0.1", 22, check, "SSH-1.99-OpenSSH_5.3")
        assert result is not None
        assert "Outdated" in result["detail"]

        # Modern version - should return None
        result = module._check_ssh_banner("10.0.0.1", 22, check, "SSH-2.0-OpenSSH_9.0")
        assert result is None

    def test_snmp_packet_build(self):
        """Test SNMP packet construction."""
        packet = VulnCheck._build_snmp_get("public")
        assert packet[0:1] == b"\x30"  # SEQUENCE
        assert b"public" in packet


class TestDomainSecurity:
    def test_initialization(self, config):
        """Test module initialization."""
        module = DomainSecurity(config)
        assert module.name == "domain_security"
        assert module.category == "domain"

    @patch("dns.resolver.Resolver.resolve")
    def test_spf_plus_all(self, mock_resolve, config):
        """Test SPF +all detection."""
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: '"v=spf1 +all"'
        mock_resolve.return_value = [mock_rdata]

        module = DomainSecurity(config)
        result = module._check_spf("test.com", 10)
        assert result["exists"] is True
        assert any(i["issue"] == "spf_plus_all" for i in result["issues"])

    @patch("dns.resolver.Resolver.resolve")
    def test_spf_softfail(self, mock_resolve, config):
        """Test SPF ~all detection."""
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: '"v=spf1 include:_spf.google.com ~all"'
        mock_resolve.return_value = [mock_rdata]

        module = DomainSecurity(config)
        result = module._check_spf("test.com", 10)
        assert any(i["issue"] == "spf_softfail" for i in result["issues"])

    @patch("dns.resolver.Resolver.resolve")
    def test_dmarc_none_policy(self, mock_resolve, config):
        """Test DMARC none policy detection."""
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: '"v=DMARC1; p=none;"'
        mock_resolve.return_value = [mock_rdata]

        module = DomainSecurity(config)
        result = module._check_dmarc("test.com", 10)
        assert result["exists"] is True
        assert result["policy"] == "none"
        assert any(i["issue"] == "dmarc_none_policy" for i in result["issues"])

    @patch("dns.resolver.Resolver.resolve")
    def test_dmarc_reject_policy(self, mock_resolve, config):
        """Test DMARC reject policy (good config)."""
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: '"v=DMARC1; p=reject; rua=mailto:d@test.com"'
        mock_resolve.return_value = [mock_rdata]

        module = DomainSecurity(config)
        result = module._check_dmarc("test.com", 10)
        assert result["policy"] == "reject"
        # No policy issues for reject (reporting is present)
        policy_issues = [i for i in result["issues"] if "dmarc_none" in i.get("issue", "")]
        assert len(policy_issues) == 0

    @patch("dns.resolver.Resolver.resolve")
    def test_no_dnssec(self, mock_resolve, config):
        """Test DNSSEC not enabled detection."""
        from dns.resolver import NoAnswer
        mock_resolve.side_effect = NoAnswer()

        module = DomainSecurity(config)
        result = module._check_dnssec("test.com", 10)
        assert result["enabled"] is False
        assert any(i["issue"] == "no_dnssec" for i in result["issues"])

    def test_issue_aggregation(self, config):
        """Test that issues are properly aggregated."""
        module = DomainSecurity(config)
        domain_result = {
            "spf": {"issues": [{"issue": "no_spf", "severity": "high"}]},
            "dmarc": {"issues": [{"issue": "no_dmarc", "severity": "high"}]},
            "dkim": {"issues": []},
            "dnssec": {"issues": [{"issue": "no_dnssec", "severity": "medium"}]},
            "caa": {"issues": []},
            "mx_security": {"issues": []},
            "issues": [],
        }
        module._analyze_issues("test.com", domain_result)
        assert len(domain_result["issues"]) == 3
        assert all(i.get("domain") == "test.com" for i in domain_result["issues"])
