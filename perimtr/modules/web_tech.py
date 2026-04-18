"""
Web Technology Fingerprinting Module.

Detects web technologies, frameworks, CMS platforms, CDNs, and analytics
services by analyzing HTTP responses, headers, cookies, HTML meta tags,
and JavaScript files.

Detection methods:
  - HTTP header patterns (X-Powered-By, Server, X-Generator, etc.)
  - HTML meta tag analysis (generator, framework markers)
  - Cookie name patterns (PHPSESSID, ASP.NET_SessionId, csrftoken, etc.)
  - JavaScript library detection (jQuery, React, Angular, Vue, etc.)
  - Favicon hash matching
  - Common URL path probing (/wp-admin, /administrator, /xmlrpc.php, etc.)

Data produced per domain:
  {
    "technologies": [
        {
            "name": str,
            "version": str | None,
            "category": str,        # cms/framework/server/cdn/analytics/library
            "confidence": str,      # high/medium/low
            "evidence": str
        },
        ...
    ],
    "tech_stack": {
        "cms": [...],
        "framework": [...],
        "server": [...],
        "cdn": [...],
        "analytics": [...],
        "library": [...],
    },
    "probed_paths": { path: status_code, ... },
    "error": str | None
  }
"""

import hashlib
import logging
import re
import time
from typing import Optional
from urllib.parse import urljoin

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")


# ---------------------------------------------------------------------------
# Technology signature database
# ---------------------------------------------------------------------------

# Each entry: (name, category, confidence, pattern_type, pattern)
# pattern_type: "header", "meta", "cookie", "body", "path_response"
TECH_SIGNATURES: list[dict] = [
    # ---- CMS ---------------------------------------------------------------
    {
        "name": "WordPress",
        "category": "cms",
        "confidence": "high",
        "checks": [
            {"type": "path", "path": "/wp-login.php", "expect_status": [200, 301, 302]},
            {"type": "path", "path": "/wp-admin/", "expect_status": [200, 301, 302]},
            {"type": "body", "pattern": r'content="WordPress\s*([\d.]+)?'},
            {"type": "body", "pattern": r"/wp-content/"},
            {"type": "header", "header": "link", "pattern": r'rel="https://api\.w\.org/"'},
        ],
        "version_pattern": r'content="WordPress\s*([\d.]+)',
    },
    {
        "name": "Drupal",
        "category": "cms",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-generator", "pattern": r"Drupal\s*([\d.]+)?"},
            {"type": "body", "pattern": r"Drupal\.settings"},
            {"type": "body", "pattern": r"/sites/default/files/"},
            {"type": "path", "path": "/user/login", "expect_status": [200]},
        ],
        "version_pattern": r"Drupal\s*([\d.]+)",
    },
    {
        "name": "Joomla",
        "category": "cms",
        "confidence": "high",
        "checks": [
            {"type": "path", "path": "/administrator/", "expect_status": [200, 301, 302]},
            {"type": "body", "pattern": r"/media/jui/"},
            {"type": "body", "pattern": r'content="Joomla'},
            {"type": "meta", "name": "generator", "pattern": r"Joomla"},
        ],
        "version_pattern": r"Joomla!\s*([\d.]+)",
    },
    {
        "name": "Shopify",
        "category": "cms",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-shopify-stage", "pattern": r".*"},
            {"type": "header", "header": "x-shopid", "pattern": r".*"},
            {"type": "body", "pattern": r"cdn\.shopify\.com"},
            {"type": "body", "pattern": r"Shopify\.theme"},
        ],
    },
    {
        "name": "Squarespace",
        "category": "cms",
        "confidence": "high",
        "checks": [
            {"type": "body", "pattern": r"static\.squarespace\.com"},
            {"type": "body", "pattern": r'"squarespace"'},
            {"type": "header", "header": "server", "pattern": r"Squarespace"},
        ],
    },
    {
        "name": "Wix",
        "category": "cms",
        "confidence": "high",
        "checks": [
            {"type": "body", "pattern": r"static\.wixstatic\.com"},
            {"type": "body", "pattern": r"wixsite\.com"},
            {"type": "header", "header": "x-wix-request-id", "pattern": r".*"},
        ],
    },
    # ---- JavaScript Frameworks / Libraries ----------------------------------
    {
        "name": "React",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "body", "pattern": r"react(?:\.min)?\.js"},
            {"type": "body", "pattern": r'data-reactroot'},
            {"type": "body", "pattern": r"__REACT_DEVTOOLS_GLOBAL_HOOK__"},
            {"type": "body", "pattern": r"_react\b"},
        ],
        "version_pattern": r'react[@/]([\d.]+)',
    },
    {
        "name": "Angular",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "body", "pattern": r"angular(?:\.min)?\.js"},
            {"type": "body", "pattern": r'ng-version="([\d.]+)"'},
            {"type": "body", "pattern": r"\bangular\.module\b"},
        ],
        "version_pattern": r'ng-version="([\d.]+)"',
    },
    {
        "name": "Vue.js",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "body", "pattern": r"vue(?:\.min)?\.js"},
            {"type": "body", "pattern": r"__vue__"},
            {"type": "body", "pattern": r"Vue\.config"},
        ],
        "version_pattern": r'vue[@/]([\d.]+)',
    },
    {
        "name": "Next.js",
        "category": "framework",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Next\.js"},
            {"type": "body", "pattern": r"__NEXT_DATA__"},
            {"type": "body", "pattern": r"/_next/static/"},
        ],
        "version_pattern": r'Next\.js ([\d.]+)',
    },
    {
        "name": "Nuxt.js",
        "category": "framework",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Nuxt\.?js"},
            {"type": "body", "pattern": r"__nuxt"},
            {"type": "body", "pattern": r"/_nuxt/"},
        ],
    },
    {
        "name": "jQuery",
        "category": "library",
        "confidence": "high",
        "checks": [
            {"type": "body", "pattern": r'jquery[.-]([\d.]+)(?:\.min)?\.js'},
            {"type": "body", "pattern": r"jQuery v([\d.]+)"},
        ],
        "version_pattern": r'jquery[.-]([\d.]+)',
    },
    {
        "name": "Bootstrap",
        "category": "library",
        "confidence": "medium",
        "checks": [
            {"type": "body", "pattern": r'bootstrap(?:\.min)?\.(?:css|js)'},
            {"type": "body", "pattern": r'class="(container|navbar|btn btn-)'},
        ],
        "version_pattern": r'bootstrap[@/]([\d.]+)',
    },
    {
        "name": "Tailwind CSS",
        "category": "library",
        "confidence": "medium",
        "checks": [
            {"type": "body", "pattern": r'tailwind(?:css)?(?:\.min)?\.css'},
            {"type": "body", "pattern": r'class="[^"]*(?:flex|grid|text-\w+-\d{3}|bg-\w+-\d{3}|p-\d|m-\d)[^"]*"'},
        ],
    },
    # ---- Backend Frameworks -------------------------------------------------
    {
        "name": "Express",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Express"},
        ],
        "version_pattern": r"Express/([\d.]+)",
    },
    {
        "name": "Django",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "cookie", "pattern": r"csrftoken"},
            {"type": "body", "pattern": r"csrfmiddlewaretoken"},
            {"type": "header", "header": "x-frame-options", "pattern": r"SAMEORIGIN"},
        ],
    },
    {
        "name": "Flask",
        "category": "framework",
        "confidence": "low",
        "checks": [
            {"type": "header", "header": "server", "pattern": r"Werkzeug"},
            {"type": "cookie", "pattern": r"session"},
        ],
        "version_pattern": r"Werkzeug/([\d.]+)",
    },
    {
        "name": "FastAPI",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "path", "path": "/docs", "expect_status": [200]},
            {"type": "path", "path": "/openapi.json", "expect_status": [200]},
            {"type": "body", "pattern": r'"openapi":\s*"3\.\d+'},
        ],
    },
    {
        "name": "Ruby on Rails",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Phusion Passenger"},
            {"type": "cookie", "pattern": r"_session_id"},
            {"type": "header", "header": "x-request-id", "pattern": r".*"},
            {"type": "body", "pattern": r'name="authenticity_token"'},
        ],
    },
    {
        "name": "Laravel",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "cookie", "pattern": r"laravel_session"},
            {"type": "cookie", "pattern": r"XSRF-TOKEN"},
            {"type": "header", "header": "x-powered-by", "pattern": r"PHP"},
        ],
    },
    {
        "name": "ASP.NET",
        "category": "framework",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET"},
            {"type": "header", "header": "x-aspnet-version", "pattern": r".*"},
            {"type": "cookie", "pattern": r"ASP\.NET_SessionId"},
        ],
        "version_pattern": r"ASP\.NET/([\d.]+)",
    },
    {
        "name": "Spring Boot",
        "category": "framework",
        "confidence": "medium",
        "checks": [
            {"type": "path", "path": "/actuator", "expect_status": [200]},
            {"type": "path", "path": "/actuator/health", "expect_status": [200]},
            {"type": "header", "header": "x-application-context", "pattern": r".*"},
        ],
    },
    # ---- PHP detection ------------------------------------------------------
    {
        "name": "PHP",
        "category": "framework",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"PHP/([\d.]+)"},
            {"type": "cookie", "pattern": r"PHPSESSID"},
        ],
        "version_pattern": r"PHP/([\d.]+)",
    },
    # ---- Web Servers --------------------------------------------------------
    {
        "name": "Nginx",
        "category": "server",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "server", "pattern": r"nginx"},
        ],
        "version_pattern": r"nginx/([\d.]+)",
    },
    {
        "name": "Apache",
        "category": "server",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "server", "pattern": r"Apache"},
        ],
        "version_pattern": r"Apache/([\d.]+)",
    },
    {
        "name": "IIS",
        "category": "server",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "server", "pattern": r"IIS/([\d.]+)"},
            {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET"},
        ],
        "version_pattern": r"IIS/([\d.]+)",
    },
    # ---- CDN / Infrastructure -----------------------------------------------
    {
        "name": "Cloudflare",
        "category": "cdn",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "cf-ray", "pattern": r".*"},
            {"type": "header", "header": "cf-cache-status", "pattern": r".*"},
            {"type": "header", "header": "server", "pattern": r"cloudflare"},
        ],
    },
    {
        "name": "AWS CloudFront",
        "category": "cdn",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-amz-cf-id", "pattern": r".*"},
            {"type": "header", "header": "via", "pattern": r"CloudFront"},
            {"type": "header", "header": "x-cache", "pattern": r"CloudFront"},
        ],
    },
    {
        "name": "Akamai",
        "category": "cdn",
        "confidence": "high",
        "checks": [
            {"type": "header", "header": "x-check-cacheable", "pattern": r".*"},
            {"type": "header", "header": "x-akamai-transformed", "pattern": r".*"},
            {"type": "header", "header": "server", "pattern": r"AkamaiGHost"},
        ],
    },
    # ---- Analytics / Tag Management -----------------------------------------
    {
        "name": "Google Analytics",
        "category": "analytics",
        "confidence": "high",
        "checks": [
            {"type": "body", "pattern": r"google-analytics\.com/(?:analytics\.js|ga\.js|gtag/js)"},
            {"type": "body", "pattern": r"UA-\d{4,10}-\d{1,4}"},
            {"type": "body", "pattern": r"G-[A-Z0-9]{10}"},
        ],
        "version_pattern": r"(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10})",
    },
    {
        "name": "Google Tag Manager",
        "category": "analytics",
        "confidence": "high",
        "checks": [
            {"type": "body", "pattern": r"googletagmanager\.com/gtm\.js"},
            {"type": "body", "pattern": r"GTM-[A-Z0-9]{4,8}"},
        ],
        "version_pattern": r"(GTM-[A-Z0-9]{4,8})",
    },
]

# CMS-specific paths to probe (path -> expected indicator)
CMS_PROBE_PATHS: list[dict] = [
    {"path": "/wp-login.php", "cms": "WordPress"},
    {"path": "/wp-admin/", "cms": "WordPress"},
    {"path": "/xmlrpc.php", "cms": "WordPress"},
    {"path": "/wp-json/", "cms": "WordPress"},
    {"path": "/administrator/", "cms": "Joomla"},
    {"path": "/administrator/index.php", "cms": "Joomla"},
    {"path": "/user/login", "cms": "Drupal"},
    {"path": "/sites/default/files/", "cms": "Drupal"},
    {"path": "/robots.txt", "cms": None},
    {"path": "/sitemap.xml", "cms": None},
    {"path": "/actuator/health", "cms": "Spring Boot"},
    {"path": "/openapi.json", "cms": "FastAPI"},
]


class WebTechFingerprint(ReconModule):
    """
    Web Technology Fingerprinting and CMS Detection Module.

    Analyzes HTTP responses from each target domain to identify the technology
    stack in use, including CMS platforms, server software, JavaScript libraries,
    CDN providers, and analytics tools.

    Detection is performed through multiple complementary methods:
      1. HTTP response headers (Server, X-Powered-By, X-Generator, CDN headers)
      2. HTML body analysis (meta tags, inline scripts, CSS class patterns)
      3. Cookie name matching (framework-specific session cookie names)
      4. Active path probing (CMS admin paths, framework-specific endpoints)

    Results are aggregated per domain into a ``tech_stack`` summary dict
    categorized by technology type.

    Example output::

        {
          "example.com": {
            "technologies": [
              {
                "name": "WordPress",
                "version": "6.4.1",
                "category": "cms",
                "confidence": "high",
                "evidence": "body contains /wp-content/"
              },
              ...
            ],
            "tech_stack": {
              "cms": ["WordPress"],
              "server": ["Nginx"],
              "cdn": ["Cloudflare"],
              ...
            },
            "probed_paths": {"/wp-login.php": 200, ...}
          }
        }
    """

    name = "web_tech"
    description = "Web technology fingerprinting and CMS detection"
    category = "web"

    def run(self, targets: dict) -> dict:
        """
        Run web technology fingerprinting against all target domains.

        Iterates over each domain in ``targets["domains"]``, fetches the root
        page, probes selected CMS-specific paths, and applies all technology
        signatures.

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to fingerprint
                - ``networks`` (list[str]): Ignored by this module

        Returns:
            dict with structure::

                {
                    "results": {
                        "<domain>": {
                            "technologies": [...],
                            "tech_stack": {...},
                            "probed_paths": {...},
                            "error": None
                        }
                    },
                    "total_domains": int,
                    "technologies_found": int
                }
        """
        results: dict = {
            "results": {},
            "total_domains": 0,
            "technologies_found": 0,
        }
        domains: list[str] = targets.get("domains", [])
        timeout: int = self.scan_settings.get("http_timeout", 15)
        rate: int = self.scan_settings.get("port_scan_rate", 10)
        delay: float = 1.0 / rate if rate > 0 else 0.1

        for domain in domains:
            self.logger.info(f"Web tech fingerprinting: {domain}")
            domain_result = self._fingerprint_domain(domain, timeout, delay)
            results["results"][domain] = domain_result
            results["total_domains"] += 1
            results["technologies_found"] += len(domain_result.get("technologies", []))

        return results

    def _fingerprint_domain(self, domain: str, timeout: int, delay: float) -> dict:
        """
        Fingerprint a single domain for web technologies.

        Fetches the root page over HTTPS (falls back to HTTP), then applies
        all technology signatures to headers, body, and cookies.  Follows up
        with targeted path probing for CMS-specific endpoints.

        Args:
            domain: Fully-qualified domain name (no scheme).
            timeout: HTTP request timeout in seconds.
            delay: Inter-request delay in seconds to respect rate limits.

        Returns:
            dict with keys ``technologies``, ``tech_stack``, ``probed_paths``,
            and ``error``.

        Raises:
            No exceptions are raised; errors are captured in the ``error`` key.
        """
        result: dict = {
            "technologies": [],
            "tech_stack": {
                "cms": [],
                "framework": [],
                "server": [],
                "cdn": [],
                "analytics": [],
                "library": [],
            },
            "probed_paths": {},
            "error": None,
        }

        # Fetch the root page
        response = self._fetch_page(domain, "/", timeout)
        if response is None:
            result["error"] = "Could not reach domain"
            return result

        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text
        cookies = response.cookies

        # Apply all signatures to the root response
        detected: dict[str, dict] = {}  # name -> finding dict (deduplicate)
        for sig in TECH_SIGNATURES:
            finding = self._apply_signature(sig, headers, body, cookies)
            if finding and finding["name"] not in detected:
                detected[finding["name"]] = finding

        # Probe CMS-specific paths (respecting rate limit)
        probed = self._probe_paths(domain, timeout, delay)
        result["probed_paths"] = {p: s for p, s in probed.items()}

        # Check path probe results against signatures
        for sig in TECH_SIGNATURES:
            if sig["name"] in detected:
                continue  # Already detected
            for check in sig.get("checks", []):
                if check.get("type") != "path":
                    continue
                path = check["path"]
                status = probed.get(path)
                if status and status in check.get("expect_status", []):
                    detected[sig["name"]] = {
                        "name": sig["name"],
                        "version": None,
                        "category": sig["category"],
                        "confidence": "medium",
                        "evidence": f"path {path} returned HTTP {status}",
                    }
                    break

        # Populate result
        for tech_name, finding in detected.items():
            result["technologies"].append(finding)
            cat = finding.get("category", "library")
            stack_list = result["tech_stack"].get(cat, [])
            if tech_name not in stack_list:
                stack_list.append(tech_name)

        return result

    def _apply_signature(
        self,
        sig: dict,
        headers: dict,
        body: str,
        cookies,
    ) -> Optional[dict]:
        """
        Apply a single technology signature against an HTTP response.

        Iterates through the signature's ``checks`` list.  Any matching check
        is sufficient to confirm the technology.  Version extraction is
        attempted via the optional ``version_pattern`` regex.

        Args:
            sig: Technology signature dict from ``TECH_SIGNATURES``.
            headers: Response headers as a lowercased-key dict.
            body: Response body as a string.
            cookies: ``requests.cookies.RequestsCookieJar`` object.

        Returns:
            A finding dict ``{"name", "version", "category", "confidence",
            "evidence"}`` if matched, or ``None``.
        """
        version: Optional[str] = None
        version_pattern: Optional[str] = sig.get("version_pattern")

        for check in sig.get("checks", []):
            check_type = check.get("type")

            if check_type == "header":
                header_val = headers.get(check["header"], "")
                if header_val and re.search(check["pattern"], header_val, re.IGNORECASE):
                    evidence = f"header {check['header']}: {header_val[:80]}"
                    if version_pattern:
                        m = re.search(version_pattern, header_val, re.IGNORECASE)
                        if m and m.lastindex:
                            version = m.group(1)
                    return self._make_finding(sig, version, evidence)

            elif check_type == "body":
                m = re.search(check["pattern"], body, re.IGNORECASE)
                if m:
                    snippet = m.group(0)[:80]
                    evidence = f"body pattern: {snippet}"
                    if version_pattern:
                        vm = re.search(version_pattern, body, re.IGNORECASE)
                        if vm:
                            try:
                                version = vm.group(1)
                            except IndexError:
                                pass
                    return self._make_finding(sig, version, evidence)

            elif check_type == "meta":
                meta_pattern = (
                    rf'<meta[^>]+name=["\']?{re.escape(check["name"])}["\']?'
                    rf'[^>]+content=["\']([^"\']*)["\']'
                )
                m = re.search(meta_pattern, body, re.IGNORECASE)
                if m and re.search(check["pattern"], m.group(1), re.IGNORECASE):
                    evidence = f"meta {check['name']}: {m.group(1)[:80]}"
                    if version_pattern:
                        vm = re.search(version_pattern, m.group(1), re.IGNORECASE)
                        if vm:
                            try:
                                version = vm.group(1)
                            except IndexError:
                                pass
                    return self._make_finding(sig, version, evidence)

            elif check_type == "cookie":
                for cookie_name in cookies.keys():
                    if re.search(check["pattern"], cookie_name, re.IGNORECASE):
                        evidence = f"cookie name: {cookie_name}"
                        return self._make_finding(sig, version, evidence)

        return None

    def _make_finding(self, sig: dict, version: Optional[str], evidence: str) -> dict:
        """
        Construct a normalized technology finding dict.

        Args:
            sig: The matching technology signature.
            version: Detected version string, or ``None``.
            evidence: Human-readable description of what matched.

        Returns:
            dict with keys ``name``, ``version``, ``category``,
            ``confidence``, and ``evidence``.
        """
        return {
            "name": sig["name"],
            "version": version,
            "category": sig["category"],
            "confidence": sig["confidence"],
            "evidence": evidence,
        }

    def _fetch_page(
        self, domain: str, path: str, timeout: int
    ) -> Optional[requests.Response]:
        """
        Fetch a page from the domain, trying HTTPS first then HTTP.

        Args:
            domain: Target domain (no scheme).
            path: URL path to fetch (e.g. ``"/"``, ``"/wp-login.php"``).
            timeout: Request timeout in seconds.

        Returns:
            ``requests.Response`` on success, or ``None`` if both schemes fail.
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}{path}"
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=True,
                    headers={"User-Agent": "Perimtr/1.0 Security Scanner"},
                )
                return resp
            except requests.exceptions.SSLError:
                # Try with verification disabled if cert is broken
                try:
                    import urllib3
                    urllib3.disable_warnings()
                    resp = requests.get(
                        url,
                        timeout=timeout,
                        allow_redirects=True,
                        verify=False,
                        # WARNING: Disabling TLS verification weakens security guarantees.
                        headers={"User-Agent": "Perimtr/1.0 Security Scanner"},
                    )
                    return resp
                except requests.RequestException:
                    continue
            except requests.RequestException as e:
                self.logger.debug(f"Fetch failed {url}: {e}")
                continue
        return None

    def _probe_paths(
        self, domain: str, timeout: int, delay: float
    ) -> dict[str, int]:
        """
        Probe a set of CMS-specific URL paths to detect installed platforms.

        Each path is requested with a HEAD method (falling back to GET) and the
        HTTP status code is recorded.  A rate limit delay is applied between
        requests.

        Args:
            domain: Target domain (no scheme).
            timeout: Per-request timeout in seconds.
            delay: Sleep duration between probes to avoid rate limiting.

        Returns:
            dict mapping ``path`` → ``status_code`` for all probed paths.
            Only paths that return a response are included.
        """
        results: dict[str, int] = {}
        probed_paths = {p["path"] for p in CMS_PROBE_PATHS}

        for path in probed_paths:
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}{path}"
                try:
                    resp = requests.head(
                        url,
                        timeout=max(timeout // 2, 5),
                        allow_redirects=True,
                        verify=False,
                        # WARNING: Disabling TLS verification weakens security guarantees.
                        headers={"User-Agent": "Perimtr/1.0 Security Scanner"},
                    )
                    results[path] = resp.status_code
                    break
                except requests.RequestException:
                    # Try GET if HEAD fails
                    try:
                        resp = requests.get(
                            url,
                            timeout=max(timeout // 2, 5),
                            allow_redirects=True,
                            verify=False,
                            # WARNING: Disabling TLS verification weakens security guarantees.
                            headers={"User-Agent": "Perimtr/1.0 Security Scanner"},
                            stream=True,  # Don't download body
                        )
                        results[path] = resp.status_code
                        resp.close()
                        break
                    except requests.RequestException:
                        continue
            time.sleep(delay * 0.5)

        return results
