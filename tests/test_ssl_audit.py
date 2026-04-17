"""Tests for the SSL/TLS Deep Analysis module."""

import ssl
import socket
import pytest
from unittest.mock import patch, MagicMock, call

from perimtr.core.config import DEFAULT_CONFIG
from perimtr.modules.ssl_audit import SSLAudit, WEAK_CIPHERS, PFS_KEY_EXCHANGES


@pytest.fixture
def config():
    return dict(DEFAULT_CONFIG)


@pytest.fixture
def module(config):
    return SSLAudit(config)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestSSLAuditInit:
    def test_name(self, module):
        assert module.name == "ssl_audit"

    def test_category(self, module):
        assert module.category == "cert"

    def test_description(self, module):
        assert module.description

    def test_is_enabled(self, config, module):
        assert module.is_enabled(config) is True


# ---------------------------------------------------------------------------
# Cipher classification
# ---------------------------------------------------------------------------

class TestClassifyCipher:
    def test_gcm_is_strong(self):
        assert SSLAudit._classify_cipher("TLS_AES_256_GCM_SHA384") == "strong"

    def test_chacha20_is_strong(self):
        assert SSLAudit._classify_cipher("TLS_CHACHA20_POLY1305_SHA256") == "strong"

    def test_poly1305_is_strong(self):
        assert SSLAudit._classify_cipher("ECDHE-RSA-CHACHA20-POLY1305") == "strong"

    def test_rc4_is_weak(self):
        assert SSLAudit._classify_cipher("RC4-SHA") == "weak"

    def test_des_is_weak(self):
        assert SSLAudit._classify_cipher("DES-CBC3-SHA") == "weak"

    def test_null_is_weak(self):
        assert SSLAudit._classify_cipher("NULL-SHA") == "weak"

    def test_export_is_weak(self):
        assert SSLAudit._classify_cipher("EXP-RC4-MD5") == "weak"

    def test_cbc_is_medium(self):
        assert SSLAudit._classify_cipher("AES128-CBC-SHA") == "medium"

    def test_aes_cbc_is_medium(self):
        assert SSLAudit._classify_cipher("ECDHE-RSA-AES256-SHA384") == "medium"


# ---------------------------------------------------------------------------
# Port open check
# ---------------------------------------------------------------------------

class TestPortOpen:
    @patch("socket.create_connection")
    def test_port_open_true(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        assert SSLAudit._port_open("example.com", 443, 5) is True

    @patch("socket.create_connection", side_effect=OSError("refused"))
    def test_port_open_false_on_os_error(self, mock_conn):
        assert SSLAudit._port_open("example.com", 443, 5) is False

    @patch("socket.create_connection", side_effect=socket.timeout("timed out"))
    def test_port_open_false_on_timeout(self, mock_conn):
        assert SSLAudit._port_open("example.com", 443, 5) is False


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------

class TestGradeConfiguration:
    def test_grade_f_for_critical_vuln(self, module):
        result = {
            "protocol_support": {"SSLv3": True, "TLSv1.0": False, "TLSv1.1": False,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [{"id": "POODLE", "severity": "critical"}],
        }
        assert module._grade_configuration(result) == "F"

    def test_grade_d_for_tls10(self, module):
        result = {
            "protocol_support": {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": False,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        assert module._grade_configuration(result) == "D"

    def test_grade_c_for_weak_cipher(self, module):
        result = {
            "protocol_support": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [{"name": "RC4-SHA", "strength": "weak"}],
            "pfs_supported": True,
            "hsts_preload": False,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        assert module._grade_configuration(result) == "C"

    def test_grade_b_for_no_pfs(self, module):
        result = {
            "protocol_support": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [{"name": "AES128-GCM-SHA256", "strength": "strong"}],
            "pfs_supported": False,
            "hsts_preload": False,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        assert module._grade_configuration(result) == "B"

    def test_grade_b_for_tls11(self, module):
        result = {
            "protocol_support": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": True,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [{"name": "TLS_AES_256_GCM_SHA384", "strength": "strong"}],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        assert module._grade_configuration(result) == "B"

    def test_grade_a_for_good_config(self, module):
        result = {
            "protocol_support": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [{"name": "TLS_AES_256_GCM_SHA384", "strength": "strong"}],
            "pfs_supported": True,
            "hsts_preload": False,  # No preload → A, not A+
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        grade = module._grade_configuration(result)
        assert grade in ("A", "A+")

    def test_grade_a_plus_for_perfect_config(self, module):
        result = {
            "protocol_support": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
                                  "TLSv1.2": True, "TLSv1.3": True},
            "cipher_suites": [{"name": "TLS_AES_256_GCM_SHA384", "strength": "strong"}],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        assert module._grade_configuration(result) == "A+"


# ---------------------------------------------------------------------------
# Vulnerability checks
# ---------------------------------------------------------------------------

class TestVulnerabilityChecks:
    def test_poodle_detected_for_sslv3(self, module):
        """POODLE is flagged when SSLv3 is supported."""
        vulns = module._check_vulnerabilities(
            "example.com",
            {"SSLv3": True, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            [],
            10,
        )
        ids = [v["id"] for v in vulns]
        assert "POODLE" in ids

    def test_beast_detected_for_tls10_cbc(self, module):
        """BEAST is flagged when TLS 1.0 is used with CBC cipher."""
        vulns = module._check_vulnerabilities(
            "example.com",
            {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            [{"name": "AES128-CBC-SHA", "strength": "medium"}],
            10,
        )
        ids = [v["id"] for v in vulns]
        assert "BEAST" in ids

    def test_rc4_detected(self, module):
        """RC4 cipher is flagged."""
        vulns = module._check_vulnerabilities(
            "example.com",
            {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            [{"name": "RC4-SHA", "strength": "weak"}],
            10,
        )
        ids = [v["id"] for v in vulns]
        assert "RC4" in ids

    def test_sweet32_detected_for_3des(self, module):
        """SWEET32 is flagged for 3DES cipher."""
        vulns = module._check_vulnerabilities(
            "example.com",
            {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            [{"name": "DES-CBC3-SHA", "strength": "weak"}],
            10,
        )
        ids = [v["id"] for v in vulns]
        assert "SWEET32" in ids

    def test_deprecated_tls10_flagged(self, module):
        """Deprecated TLS 1.0 is flagged."""
        vulns = module._check_vulnerabilities(
            "example.com",
            {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
            [],
            10,
        )
        ids = [v["id"] for v in vulns]
        assert "DEPRECATED_TLS10" in ids

    def test_deprecated_tls11_flagged(self, module):
        """Deprecated TLS 1.1 is flagged."""
        vulns = module._check_vulnerabilities(
            "example.com",
            {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True},
            [],
            10,
        )
        ids = [v["id"] for v in vulns]
        assert "DEPRECATED_TLS11" in ids

    def test_no_false_positives_for_good_config(self, module):
        """No vulnerabilities flagged for a modern, secure configuration."""
        with patch.object(module, "_check_compression", return_value=False):
            vulns = module._check_vulnerabilities(
                "example.com",
                {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
                 "TLSv1.2": True, "TLSv1.3": True},
                [{"name": "TLS_AES_256_GCM_SHA384", "strength": "strong"}],
                10,
            )
        assert vulns == []


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

class TestRecommendations:
    def test_recommends_disabling_sslv3(self, module):
        result = {
            "protocol_support": {"SSLv3": True},
            "cipher_suites": [],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        recs = module._build_recommendations(result)
        assert any("SSLv3" in r or "sslv3" in r.lower() for r in recs)

    def test_recommends_pfs_when_missing(self, module):
        result = {
            "protocol_support": {},
            "cipher_suites": [],
            "pfs_supported": False,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        recs = module._build_recommendations(result)
        assert any("Forward Secrecy" in r or "PFS" in r or "ECDHE" in r for r in recs)

    def test_recommends_removing_weak_ciphers(self, module):
        result = {
            "protocol_support": {},
            "cipher_suites": [{"name": "RC4-SHA", "strength": "weak"}],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        recs = module._build_recommendations(result)
        assert any("RC4" in r or "weak" in r.lower() or "cipher" in r.lower() for r in recs)

    def test_no_recommendations_for_good_config(self, module):
        """Minimal or no recommendations for a well-configured server."""
        result = {
            "protocol_support": {
                "SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
                "TLSv1.2": True, "TLSv1.3": True,
            },
            "cipher_suites": [{"name": "TLS_AES_256_GCM_SHA384", "strength": "strong"}],
            "pfs_supported": True,
            "hsts_preload": True,
            "certificate_chain": {"valid": True, "issues": []},
            "vulnerabilities": [],
        }
        recs = module._build_recommendations(result)
        # May still recommend TLS 1.3 if only TLS 1.2 is enabled, but shouldn't
        # recommend disabling protocols or removing ciphers
        for rec in recs:
            assert "SSLv3" not in rec
            assert "RC4" not in rec


# ---------------------------------------------------------------------------
# Full run() with mocked connections
# ---------------------------------------------------------------------------

class TestRun:
    @patch.object(SSLAudit, "_port_open", return_value=False)
    def test_run_unreachable_port(self, mock_port, module):
        """Grade F is assigned when port 443 is unreachable."""
        results = module.run({"domains": ["unreachable.invalid"], "networks": []})
        domain_result = results["results"]["unreachable.invalid"]
        assert domain_result["grade"] == "F"
        assert domain_result["error"] is not None

    def test_run_empty_domains(self, module):
        """run() handles empty domain list gracefully."""
        results = module.run({"domains": [], "networks": []})
        assert results["total_domains"] == 0
        assert results["results"] == {}

    @patch.object(SSLAudit, "_port_open", return_value=True)
    @patch.object(SSLAudit, "_check_protocol_support", return_value={
        "SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
        "TLSv1.2": True, "TLSv1.3": True,
    })
    @patch.object(SSLAudit, "_analyze_cipher_suites", return_value=[
        {"name": "TLS_AES_256_GCM_SHA384", "strength": "strong", "bits": 256}
    ])
    @patch.object(SSLAudit, "_check_forward_secrecy", return_value=True)
    @patch.object(SSLAudit, "_check_certificate_chain", return_value={
        "valid": True, "length": 3, "issues": []
    })
    @patch.object(SSLAudit, "_check_ocsp_stapling", return_value=None)
    @patch.object(SSLAudit, "_check_hsts_preload", return_value=True)
    @patch.object(SSLAudit, "_check_vulnerabilities", return_value=[])
    def test_run_complete_flow(
        self, mock_vulns, mock_hsts, mock_ocsp, mock_chain,
        mock_pfs, mock_ciphers, mock_proto, mock_port, module
    ):
        """run() produces a complete, well-structured result for a reachable domain."""
        results = module.run({"domains": ["example.com"], "networks": []})
        assert results["total_domains"] == 1
        assert results["graded_domains"] == 1

        domain_result = results["results"]["example.com"]
        assert domain_result["grade"] == "A+"
        assert domain_result["pfs_supported"] is True
        assert domain_result["hsts_preload"] is True
        assert domain_result["certificate_chain"]["valid"] is True
        assert domain_result["error"] is None
        assert isinstance(domain_result["recommendations"], list)

    def test_safe_run_captures_error(self, module):
        """safe_run() wraps errors from run()."""
        with patch.object(module, "run", side_effect=RuntimeError("crash")):
            result = module.safe_run({"domains": [], "networks": []})
        assert result["_meta"]["status"] == "error"
        assert "crash" in result["_meta"]["error"]


# ---------------------------------------------------------------------------
# Constants sanity checks
# ---------------------------------------------------------------------------

class TestConstants:
    def test_weak_ciphers_non_empty(self):
        assert len(WEAK_CIPHERS) > 0
        assert "RC4" in WEAK_CIPHERS
        assert "NULL" in WEAK_CIPHERS

    def test_pfs_exchanges_non_empty(self):
        assert len(PFS_KEY_EXCHANGES) > 0
        assert "ECDHE" in PFS_KEY_EXCHANGES
        assert "DHE" in PFS_KEY_EXCHANGES
