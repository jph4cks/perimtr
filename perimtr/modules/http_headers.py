"""
HTTP Security Headers Module.

Checks web services for security headers and misconfigurations:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
  - Server header information leakage
  - Cookie security flags

How it works:
  For each domain in ``targets["domains"]``:
    1. An HTTP GET request is made (HTTPS first, HTTP fallback).
    2. The response headers are inspected for the presence of all
       ``SECURITY_HEADERS``, building lists of ``present_headers`` and
       ``missing_headers``.
    3. Information-leaking headers (Server, X-Powered-By, etc.) are flagged.
    4. ``Set-Cookie`` headers are analyzed for missing Secure, HttpOnly,
       and SameSite flags.
    5. Where applicable, additional validation is performed:
       - HSTS: max-age must be >= 31536000 (1 year), includeSubDomains recommended
       - CSP: dangerous directives (unsafe-inline, unsafe-eval, data:) are flagged
    6. TLS information is captured for HTTPS connections.

Data produced:
  {
    "results": {
        "<domain>": {
            "url": str,
            "status_code": int,
            "headers": {str: str},
            "missing_headers": [str],
            "present_headers": [{"header": str, "value": str}],
            "info_leaks": [{"header": str, "value": str, "severity": str, ...}],
            "cookie_issues": [{"cookie": str, "issues": [str], "severity": str}],
            "tls_info": {...},
            "redirect_chain": [{"url": str, "status": int}],
            "issues": [{"issue": str, "severity": str, "detail": str, ...}]
        }
    },
    "total_issues": int
  }
"""

import logging
import ssl
import socket
from typing import Optional
from urllib.parse import urlparse

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Security headers with descriptions and recommended configurations.
# Severity indicates the risk level of the header being absent.
SECURITY_HEADERS: dict = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "severity": "high",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    "Content-Security-Policy": {
        "description": "Controls resource loading to prevent XSS",
        "severity": "high",
        "recommendation": "Define a Content-Security-Policy that restricts script/style sources",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "medium",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "severity": "medium",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "low",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "severity": "low",
        "recommendation": "Define a Permissions-Policy restricting unnecessary APIs",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (still recommended for older browsers)",
        "severity": "low",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block'",
    },
}

# Headers that reveal technology or version information to potential attackers
INFO_LEAK_HEADERS: list[str] = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"
]


class HTTPHeaders(ReconModule):
    """
    HTTP Security Header Analyzer.

    Checks each target domain for the presence and correct configuration of
    HTTP security headers.  Results include a flat ``issues`` list with
    severity ratings and remediation recommendations.

    Attributes:
        name (str): Module identifier ``"http_headers"``.
        description (str): Human-readable description.
        category (str): Module category ``"web"``.
    """

    name = "http_headers"
    description = "HTTP security header analysis and misconfiguration detection"
    category = "web"

    def run(self, targets: dict) -> dict:
        """
        Check HTTP security headers for all target domains.

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to check.
                - ``networks`` (list[str]): Ignored by this module.

        Returns:
            dict with keys ``results`` (per-domain) and ``total_issues``
            (aggregate count of missing headers, info leaks, and cookie
            issues across all domains).
        """
        results: dict = {"results": {}, "total_issues": 0}
        domains = targets.get("domains", [])
        timeout = self.scan_settings.get("http_timeout", 15)

        for domain in domains:
            self.logger.info(f"Checking HTTP headers: {domain}")
            domain_results = self._check_domain(domain, timeout)
            results["results"][domain] = domain_results
            # Sum up issue counts across all categories
            results["total_issues"] += len(domain_results.get("missing_headers", []))
            results["total_issues"] += len(domain_results.get("info_leaks", []))
            results["total_issues"] += len(domain_results.get("cookie_issues", []))

        return results

    def _check_domain(self, domain: str, timeout: int) -> dict:
        """
        Check a single domain for HTTP security header issues.

        Attempts HTTPS first; if that fails, falls back to HTTP.  The
        redirect chain is recorded so that HTTP→HTTPS enforcement can be
        verified.

        Args:
            domain: Domain name to check (without scheme).
            timeout: HTTP request timeout in seconds.

        Returns:
            Per-domain result dict.  See module-level docstring for the
            full schema.  On complete connection failure, ``url`` will be
            ``None`` and ``issues`` will contain the connection error.

        Raises:
            No exceptions propagate — connection errors are captured as
            issues in the result dict.
        """
        result: dict = {
            "url": None,
            "status_code": None,
            "headers": {},
            "missing_headers": [],
            "present_headers": [],
            "info_leaks": [],
            "cookie_issues": [],
            "tls_info": {},
            "redirect_chain": [],
            "issues": [],
        }

        # Try HTTPS first, fall back to plain HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                resp = requests.get(
                    url, timeout=timeout, allow_redirects=True,
                    verify=True, headers={"User-Agent": "Perimtr/1.0 Security Scanner"}
                )
                result["url"] = resp.url
                result["status_code"] = resp.status_code
                result["headers"] = dict(resp.headers)

                # Record HTTP redirect chain for analysis
                for r in resp.history:
                    result["redirect_chain"].append({
                        "url": r.url,
                        "status": r.status_code,
                    })

                # Check for missing HTTP → HTTPS redirect
                if scheme == "http":
                    final_url = resp.url
                    if not final_url.startswith("https://"):
                        result["issues"].append({
                            "issue": "no_https_redirect",
                            "severity": "high",
                            "detail": "HTTP does not redirect to HTTPS",
                            "recommendation": "Configure HTTP to redirect all traffic to HTTPS",
                        })

                # Run all header checks
                self._check_security_headers(resp.headers, result)
                self._check_info_leaks(resp.headers, result)
                self._check_cookies(resp.headers, scheme, result)

                # Collect TLS metadata for HTTPS connections
                if scheme == "https":
                    result["tls_info"] = self._get_tls_info(domain)

                break  # Success — skip HTTP fallback

            except requests.exceptions.SSLError as e:
                result["issues"].append({
                    "issue": "ssl_error",
                    "severity": "critical",
                    "detail": f"SSL/TLS error: {str(e)[:200]}",
                    "recommendation": "Fix SSL/TLS configuration — ensure valid certificate and modern TLS",
                })
            except requests.RequestException as e:
                if scheme == "https":
                    continue  # Fall through to HTTP
                self.logger.warning(f"Could not reach {url}: {e}")

        return result

    def _check_security_headers(self, headers, result: dict) -> None:
        """
        Check the response headers for presence and configuration of security headers.

        Iterates over the ``SECURITY_HEADERS`` registry.  For each header:
          - If present, adds an entry to ``present_headers`` and performs
            additional validation (HSTS, CSP).
          - If absent, adds an entry to both ``missing_headers`` and ``issues``.

        Args:
            headers: ``requests.structures.CaseInsensitiveDict`` of response
                headers.
            result: Per-domain result dict to mutate in-place.

        Returns:
            None.  Modifies ``result["present_headers"]``, ``result["missing_headers"]``,
            and ``result["issues"]`` in-place.
        """
        for header_name, header_info in SECURITY_HEADERS.items():
            value = headers.get(header_name)
            if value:
                result["present_headers"].append({
                    "header": header_name,
                    "value": value,
                })
                # Validate quality of HSTS configuration
                if header_name == "Strict-Transport-Security":
                    self._validate_hsts(value, result)
                # Validate quality of CSP directives
                if header_name == "Content-Security-Policy":
                    self._validate_csp(value, result)
            else:
                result["missing_headers"].append(header_name)
                result["issues"].append({
                    "issue": f"missing_{header_name.lower().replace('-', '_')}",
                    "severity": header_info["severity"],
                    "detail": f"Missing {header_name}: {header_info['description']}",
                    "recommendation": header_info["recommendation"],
                })

    def _check_info_leaks(self, headers, result: dict) -> None:
        """
        Flag response headers that leak server technology or version information.

        Checks ``INFO_LEAK_HEADERS`` (Server, X-Powered-By, etc.) and records
        any that are present.  Information leakage helps attackers target
        known vulnerabilities in specific software versions.

        Args:
            headers: Response headers dict.
            result: Per-domain result dict to mutate in-place.

        Returns:
            None.  Adds entries to ``result["info_leaks"]``.
        """
        for header in INFO_LEAK_HEADERS:
            value = headers.get(header)
            if value:
                result["info_leaks"].append({
                    "header": header,
                    "value": value,
                    "severity": "low",
                    "recommendation": f"Remove or obscure the '{header}' header to reduce fingerprinting",
                })

    def _check_cookies(self, headers, scheme: str, result: dict) -> None:
        """
        Analyze ``Set-Cookie`` headers for missing security flags.

        Checks each cookie for:
          - ``Secure`` flag (required when served over HTTPS)
          - ``HttpOnly`` flag (prevents JavaScript access)
          - ``SameSite`` attribute (prevents CSRF)

        Args:
            headers: Response headers dict.
            scheme: Protocol scheme of the final response URL (``"https"``
                or ``"http"``).
            result: Per-domain result dict to mutate in-place.

        Returns:
            None.  Adds entries to ``result["cookie_issues"]``.

        Note:
            The ``Secure`` flag is only flagged as missing on HTTPS responses;
            HTTP cookies cannot carry this flag meaningfully.
        """
        set_cookies = headers.get("Set-Cookie", "")
        if not set_cookies:
            return

        # Multiple cookies in the response are comma-separated in some servers
        cookies = set_cookies.split(",") if "," in set_cookies else [set_cookies]
        for cookie in cookies:
            cookie = cookie.strip()
            issues: list[str] = []

            if scheme == "https" and "Secure" not in cookie:
                issues.append("missing Secure flag")
            if "HttpOnly" not in cookie:
                issues.append("missing HttpOnly flag")
            if "SameSite" not in cookie:
                issues.append("missing SameSite attribute")

            if issues:
                cookie_name = cookie.split("=")[0].strip() if "=" in cookie else cookie[:30]
                result["cookie_issues"].append({
                    "cookie": cookie_name,
                    "issues": issues,
                    "severity": "medium",
                })

    def _validate_hsts(self, value: str, result: dict) -> None:
        """
        Validate the quality of a Strict-Transport-Security header value.

        Checks:
          - ``max-age`` must be at least 31,536,000 seconds (1 year)
          - ``includeSubDomains`` directive should be present

        Args:
            value: Raw ``Strict-Transport-Security`` header value string.
            result: Per-domain result dict to mutate in-place.

        Returns:
            None.  Appends weak-HSTS issues to ``result["issues"]``.

        Example::

            # These values produce issues:
            "max-age=3600"                    # max-age too short
            "max-age=31536000"                # missing includeSubDomains
        """
        value_lower = value.lower()
        # Validate max-age value
        if "max-age=" in value_lower:
            try:
                max_age = int(value_lower.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:  # Less than 1 year
                    result["issues"].append({
                        "issue": "weak_hsts_max_age",
                        "severity": "medium",
                        "detail": f"HSTS max-age is {max_age}s (less than 1 year)",
                        "recommendation": "Set HSTS max-age to at least 31536000 (1 year)",
                    })
            except (ValueError, IndexError):
                pass  # Malformed max-age — can't parse

        # Check for includeSubDomains directive
        if "includesubdomains" not in value_lower:
            result["issues"].append({
                "issue": "hsts_no_includesubdomains",
                "severity": "low",
                "detail": "HSTS does not include subdomains",
                "recommendation": "Add includeSubDomains to HSTS header",
            })

    def _validate_csp(self, value: str, result: dict) -> None:
        """
        Validate a Content-Security-Policy header for dangerous directives.

        Checks for the following high-risk directives that significantly
        weaken the protection provided by CSP:
          - ``'unsafe-inline'``: allows inline scripts/styles
          - ``'unsafe-eval'``: allows ``eval()`` and related APIs
          - ``data:`` URIs in script/style sources

        Args:
            value: Raw ``Content-Security-Policy`` header value string.
            result: Per-domain result dict to mutate in-place.

        Returns:
            None.  Appends a ``weak_csp`` issue to ``result["issues"]``
            if any dangerous directive is found.
        """
        value_lower = value.lower()
        dangerous: list[str] = []

        if "'unsafe-inline'" in value_lower:
            dangerous.append("unsafe-inline")
        if "'unsafe-eval'" in value_lower:
            dangerous.append("unsafe-eval")
        if "data:" in value_lower:
            dangerous.append("data: URIs")

        if dangerous:
            result["issues"].append({
                "issue": "weak_csp",
                "severity": "medium",
                "detail": f"CSP contains dangerous directives: {', '.join(dangerous)}",
                "recommendation": "Remove unsafe-inline, unsafe-eval, and data: from CSP",
            })

    def _get_tls_info(self, domain: str) -> dict:
        """
        Retrieve TLS connection metadata for an HTTPS domain.

        Opens a raw TLS socket to port 443 and extracts:
          - Negotiated protocol version (e.g. ``"TLSv1.3"``)
          - Negotiated cipher suite name
          - Certificate subject and issuer
          - Certificate validity dates
          - Subject Alternative Names (SANs)

        Args:
            domain: Domain name to connect to on port 443.

        Returns:
            dict with TLS metadata fields, or a dict containing only
            ``{"error": str}`` if the connection fails.

        Example::

            {
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject": {"commonName": "example.com"},
                "issuer": {"organizationName": "Let's Encrypt"},
                "valid_from": "Jun  1 00:00:00 2024 GMT",
                "valid_until": "Aug 30 23:59:59 2024 GMT",
                "san": ["example.com", "www.example.com"]
            }
        """
        tls_info: dict = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_info = {
                        "protocol": ssock.version(),
                        "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "valid_from": cert.get("notBefore"),
                        "valid_until": cert.get("notAfter"),
                        "san": [
                            entry[1] for entry in cert.get("subjectAltName", [])
                        ],
                    }
        except Exception as e:
            tls_info["error"] = str(e)[:200]

        return tls_info
