"""Tests for the Web Technology Fingerprinting module."""

import pytest
import requests
from unittest.mock import patch, MagicMock

from perimtr.core.config import DEFAULT_CONFIG
from perimtr.modules.web_tech import WebTechFingerprint, TECH_SIGNATURES, CMS_PROBE_PATHS


@pytest.fixture
def config():
    return dict(DEFAULT_CONFIG)


@pytest.fixture
def targets():
    return {"networks": [], "domains": ["example.com"]}


@pytest.fixture
def module(config):
    return WebTechFingerprint(config)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestWebTechInit:
    def test_name(self, module):
        assert module.name == "web_tech"

    def test_category(self, module):
        assert module.category == "web"

    def test_description(self, module):
        assert "fingerprint" in module.description.lower() or "technology" in module.description.lower()

    def test_is_enabled(self, config, module):
        assert module.is_enabled(config) is True


# ---------------------------------------------------------------------------
# Signature application
# ---------------------------------------------------------------------------

class TestApplySignature:
    def test_header_match(self, module):
        """Header-based detection for a technology."""
        sig = {
            "name": "Nginx",
            "category": "server",
            "confidence": "high",
            "checks": [{"type": "header", "header": "server", "pattern": r"nginx"}],
        }
        headers = {"server": "nginx/1.24.0"}
        result = module._apply_signature(sig, headers, "", MagicMock())
        assert result is not None
        assert result["name"] == "Nginx"
        assert result["category"] == "server"

    def test_header_version_extraction(self, module):
        """Version is extracted from the header pattern."""
        sig = {
            "name": "Nginx",
            "category": "server",
            "confidence": "high",
            "checks": [{"type": "header", "header": "server", "pattern": r"nginx"}],
            "version_pattern": r"nginx/([\d.]+)",
        }
        headers = {"server": "nginx/1.24.0"}
        cookies = MagicMock()
        cookies.keys.return_value = []
        result = module._apply_signature(sig, headers, "", cookies)
        assert result is not None
        assert result["version"] == "1.24.0"

    def test_body_match(self, module):
        """Body-based detection for a technology."""
        sig = {
            "name": "WordPress",
            "category": "cms",
            "confidence": "high",
            "checks": [{"type": "body", "pattern": r"/wp-content/"}],
        }
        body = '<script src="/wp-content/plugins/example.js"></script>'
        cookies = MagicMock()
        cookies.keys.return_value = []
        result = module._apply_signature(sig, {}, body, cookies)
        assert result is not None
        assert result["name"] == "WordPress"

    def test_cookie_match(self, module):
        """Cookie-based detection for a technology."""
        sig = {
            "name": "PHP",
            "category": "framework",
            "confidence": "high",
            "checks": [{"type": "cookie", "pattern": r"PHPSESSID"}],
        }
        cookies = MagicMock()
        cookies.keys.return_value = ["PHPSESSID", "other_cookie"]
        result = module._apply_signature(sig, {}, "", cookies)
        assert result is not None
        assert result["name"] == "PHP"

    def test_meta_tag_match(self, module):
        """Meta tag-based detection for a technology."""
        sig = {
            "name": "Joomla",
            "category": "cms",
            "confidence": "high",
            "checks": [{"type": "meta", "name": "generator", "pattern": r"Joomla"}],
        }
        body = '<meta name="generator" content="Joomla! - Open Source Content Management"/>'
        cookies = MagicMock()
        cookies.keys.return_value = []
        result = module._apply_signature(sig, {}, body, cookies)
        assert result is not None
        assert result["name"] == "Joomla"

    def test_no_match_returns_none(self, module):
        """Returns None when no check matches."""
        sig = {
            "name": "Drupal",
            "category": "cms",
            "confidence": "high",
            "checks": [{"type": "header", "header": "x-generator", "pattern": r"Drupal"}],
        }
        cookies = MagicMock()
        cookies.keys.return_value = []
        result = module._apply_signature(sig, {"server": "nginx"}, "<html></html>", cookies)
        assert result is None

    def test_case_insensitive_header_match(self, module):
        """Header patterns are case-insensitive."""
        sig = {
            "name": "Cloudflare",
            "category": "cdn",
            "confidence": "high",
            "checks": [{"type": "header", "header": "server", "pattern": r"cloudflare"}],
        }
        headers = {"server": "CLOUDFLARE"}
        cookies = MagicMock()
        cookies.keys.return_value = []
        result = module._apply_signature(sig, headers, "", cookies)
        assert result is not None

    def test_evidence_captured(self, module):
        """Evidence string is populated in the finding."""
        sig = {
            "name": "Nginx",
            "category": "server",
            "confidence": "high",
            "checks": [{"type": "header", "header": "server", "pattern": r"nginx"}],
        }
        headers = {"server": "nginx/1.24.0"}
        cookies = MagicMock()
        cookies.keys.return_value = []
        result = module._apply_signature(sig, headers, "", cookies)
        assert result is not None
        assert "server" in result["evidence"].lower()


# ---------------------------------------------------------------------------
# Technology classification
# ---------------------------------------------------------------------------

class TestMakeFinding:
    def test_finding_structure(self, module):
        """make_finding returns the correct structure."""
        sig = {"name": "React", "category": "framework", "confidence": "medium"}
        finding = module._make_finding(sig, "18.2.0", "body pattern: react.min.js")
        assert finding["name"] == "React"
        assert finding["version"] == "18.2.0"
        assert finding["category"] == "framework"
        assert finding["confidence"] == "medium"
        assert "body pattern" in finding["evidence"]

    def test_finding_no_version(self, module):
        """None version is preserved."""
        sig = {"name": "Cloudflare", "category": "cdn", "confidence": "high"}
        finding = module._make_finding(sig, None, "header cf-ray: abc123")
        assert finding["version"] is None


# ---------------------------------------------------------------------------
# Cipher classification (indirectly via TECH_SIGNATURES)
# ---------------------------------------------------------------------------

class TestTechSignatures:
    def test_minimum_technologies(self):
        """At least 30 technologies are defined."""
        assert len(TECH_SIGNATURES) >= 30

    def test_all_have_required_fields(self):
        """Every signature has name, category, confidence, and checks."""
        for sig in TECH_SIGNATURES:
            assert "name" in sig, f"Missing 'name': {sig}"
            assert "category" in sig, f"Missing 'category' in {sig['name']}"
            assert "confidence" in sig, f"Missing 'confidence' in {sig['name']}"
            assert "checks" in sig, f"Missing 'checks' in {sig['name']}"

    def test_categories_valid(self):
        """All category values are in the allowed set."""
        valid_categories = {"cms", "framework", "server", "cdn", "analytics", "library"}
        for sig in TECH_SIGNATURES:
            assert sig["category"] in valid_categories, (
                f"Invalid category '{sig['category']}' in {sig['name']}"
            )

    def test_confidence_values(self):
        """Confidence is one of high/medium/low."""
        for sig in TECH_SIGNATURES:
            assert sig["confidence"] in {"high", "medium", "low"}, (
                f"Invalid confidence in {sig['name']}"
            )

    def test_cms_platforms_present(self):
        """Core CMS platforms are all defined."""
        names = {s["name"] for s in TECH_SIGNATURES}
        for cms in ["WordPress", "Drupal", "Joomla", "Shopify", "Squarespace", "Wix"]:
            assert cms in names, f"Missing CMS: {cms}"

    def test_js_frameworks_present(self):
        """Core JS frameworks/libraries are defined."""
        names = {s["name"] for s in TECH_SIGNATURES}
        for fw in ["React", "Angular", "Vue.js", "Next.js", "jQuery", "Bootstrap"]:
            assert fw in names, f"Missing JS framework: {fw}"

    def test_cdn_providers_present(self):
        """CDN providers are defined."""
        names = {s["name"] for s in TECH_SIGNATURES}
        for cdn in ["Cloudflare", "AWS CloudFront", "Akamai"]:
            assert cdn in names, f"Missing CDN: {cdn}"

    def test_analytics_present(self):
        """Analytics tools are defined."""
        names = {s["name"] for s in TECH_SIGNATURES}
        for analytics in ["Google Analytics", "Google Tag Manager"]:
            assert analytics in names, f"Missing analytics: {analytics}"

    def test_servers_present(self):
        """Web server technologies are defined."""
        names = {s["name"] for s in TECH_SIGNATURES}
        for server in ["Nginx", "Apache", "IIS"]:
            assert server in names, f"Missing server: {server}"


# ---------------------------------------------------------------------------
# Full domain fingerprinting (mocked HTTP)
# ---------------------------------------------------------------------------

class TestFingerprintDomain:
    @patch("perimtr.modules.web_tech.requests.get")
    @patch("perimtr.modules.web_tech.requests.head")
    def test_wordpress_detected_from_body(self, mock_head, mock_get, module):
        """WordPress is detected when wp-content path appears in the body."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "nginx/1.24.0"}
        mock_resp.text = '<link rel="stylesheet" href="/wp-content/themes/test/style.css">'
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = []
        mock_get.return_value = mock_resp

        # HEAD probe returns 404 (path not found)
        mock_head.return_value = MagicMock(status_code=404)

        result = module._fingerprint_domain("example.com", timeout=10, delay=0)
        names = [t["name"] for t in result["technologies"]]
        assert "WordPress" in names

    @patch("perimtr.modules.web_tech.requests.get")
    @patch("perimtr.modules.web_tech.requests.head")
    def test_nginx_detected_from_server_header(self, mock_head, mock_get, module):
        """Nginx is detected from the Server header."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "nginx/1.24.0"}
        mock_resp.text = "<html><body>Hello</body></html>"
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = []
        mock_get.return_value = mock_resp

        # HEAD probe returns 404 for all paths
        mock_head_resp = MagicMock()
        mock_head_resp.status_code = 404
        mock_head.return_value = mock_head_resp

        result = module._fingerprint_domain("example.com", timeout=10, delay=0)

        names = [t["name"] for t in result["technologies"]]
        assert "Nginx" in names
        nginx = next(t for t in result["technologies"] if t["name"] == "Nginx")
        assert nginx["version"] == "1.24.0"

    @patch("perimtr.modules.web_tech.requests.get", side_effect=requests.RequestException("connect failed"))
    def test_unreachable_domain(self, mock_get, module):
        """Unreachable domain returns error with empty technologies list."""
        result = module._fingerprint_domain("unreachable.invalid", timeout=2, delay=0)
        assert result["error"] is not None
        assert result["technologies"] == []

    @patch("perimtr.modules.web_tech.requests.get")
    def test_tech_stack_populated(self, mock_get, module):
        """tech_stack dict is populated with detected technology names by category."""
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Server": "nginx",
            "X-Powered-By": "Express",
        }
        mock_resp.text = ""
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = []
        mock_get.return_value = mock_resp

        with patch("perimtr.modules.web_tech.requests.head", side_effect=requests.RequestException("no head")):
            result = module._fingerprint_domain("example.com", timeout=10, delay=0)

        assert "Nginx" in result["tech_stack"]["server"]

    @patch("perimtr.modules.web_tech.requests.get")
    def test_no_duplicate_technologies(self, mock_get, module):
        """A technology is only reported once even if multiple checks match."""
        mock_resp = MagicMock()
        # Both Server and body match Nginx
        mock_resp.headers = {"Server": "nginx/1.24.0"}
        mock_resp.text = "Powered by nginx"
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = []
        mock_get.return_value = mock_resp

        with patch("perimtr.modules.web_tech.requests.head", side_effect=requests.RequestException("no head")):
            result = module._fingerprint_domain("example.com", timeout=10, delay=0)

        nginx_count = sum(1 for t in result["technologies"] if t["name"] == "Nginx")
        assert nginx_count == 1


# ---------------------------------------------------------------------------
# Full run()
# ---------------------------------------------------------------------------

class TestRun:
    @patch("perimtr.modules.web_tech.requests.get")
    @patch("perimtr.modules.web_tech.requests.head", side_effect=requests.RequestException("no head"))
    def test_run_returns_correct_structure(self, mock_head, mock_get, module):
        """run() returns well-structured results dict."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Apache/2.4.51"}
        mock_resp.text = ""
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = []
        mock_get.return_value = mock_resp

        results = module.run({"domains": ["example.com"], "networks": []})

        assert "results" in results
        assert "total_domains" in results
        assert "technologies_found" in results
        assert "example.com" in results["results"]
        assert results["total_domains"] == 1

    @patch("perimtr.modules.web_tech.requests.get")
    @patch("perimtr.modules.web_tech.requests.head", side_effect=requests.RequestException("no head"))
    def test_run_multiple_domains(self, mock_head, mock_get, module):
        """run() processes all domains in targets."""
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.text = ""
        mock_resp.cookies = MagicMock()
        mock_resp.cookies.keys.return_value = []
        mock_get.return_value = mock_resp

        results = module.run({"domains": ["a.com", "b.com"], "networks": []})
        assert results["total_domains"] == 2
        assert "a.com" in results["results"]
        assert "b.com" in results["results"]

    def test_run_empty_domains(self, module):
        """run() handles empty domains list gracefully."""
        results = module.run({"domains": [], "networks": []})
        assert results["total_domains"] == 0
        assert results["results"] == {}

    def test_safe_run_captures_error(self, module):
        """safe_run() wraps errors from run()."""
        with patch.object(module, "run", side_effect=RuntimeError("boom")):
            result = module.safe_run({"domains": [], "networks": []})
        assert result["_meta"]["status"] == "error"
        assert "boom" in result["_meta"]["error"]
