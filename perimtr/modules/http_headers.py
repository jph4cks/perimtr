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
"""

import logging
import ssl
import socket
from typing import Any
from urllib.parse import urlparse

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

SECURITY_HEADERS = {
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

# Headers that leak information
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HTTPHeaders(ReconModule):
    """Checks HTTP security headers on web services."""

    name = "http_headers"
    description = "HTTP security header analysis and misconfiguration detection"
    category = "web"

    def run(self, targets: dict) -> dict:
        """Check HTTP headers for all target domains."""
        results = {"results": {}, "total_issues": 0}
        domains = targets.get("domains", [])
        timeout = self.scan_settings.get("http_timeout", 15)

        for domain in domains:
            self.logger.info(f"Checking HTTP headers: {domain}")
            domain_results = self._check_domain(domain, timeout)
            results["results"][domain] = domain_results
            results["total_issues"] += len(domain_results.get("missing_headers", []))
            results["total_issues"] += len(domain_results.get("info_leaks", []))
            results["total_issues"] += len(domain_results.get("cookie_issues", []))

        return results

    def _check_domain(self, domain: str, timeout: int) -> dict:
        """Check a single domain for header issues."""
        result = {
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

        # Try HTTPS first, then HTTP
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

                # Track redirects
                for r in resp.history:
                    result["redirect_chain"].append({
                        "url": r.url,
                        "status": r.status_code,
                    })

                # Check for HTTP -> HTTPS redirect
                if scheme == "http":
                    final_url = resp.url
                    if not final_url.startswith("https://"):
                        result["issues"].append({
                            "issue": "no_https_redirect",
                            "severity": "high",
                            "detail": "HTTP does not redirect to HTTPS",
                            "recommendation": "Configure HTTP to redirect all traffic to HTTPS",
                        })

                # Check security headers
                self._check_security_headers(resp.headers, result)

                # Check info leakage
                self._check_info_leaks(resp.headers, result)

                # Check cookie security
                self._check_cookies(resp.headers, scheme, result)

                # Get TLS info
                if scheme == "https":
                    result["tls_info"] = self._get_tls_info(domain)

                break  # Success, don't try HTTP

            except requests.exceptions.SSLError as e:
                result["issues"].append({
                    "issue": "ssl_error",
                    "severity": "critical",
                    "detail": f"SSL/TLS error: {str(e)[:200]}",
                    "recommendation": "Fix SSL/TLS configuration — ensure valid certificate and modern TLS",
                })
            except requests.RequestException as e:
                if scheme == "https":
                    continue  # Try HTTP
                self.logger.warning(f"Could not reach {url}: {e}")

        return result

    def _check_security_headers(self, headers, result: dict):
        """Check for presence and configuration of security headers."""
        for header_name, header_info in SECURITY_HEADERS.items():
            value = headers.get(header_name)
            if value:
                result["present_headers"].append({
                    "header": header_name,
                    "value": value,
                })
                # Check HSTS configuration quality
                if header_name == "Strict-Transport-Security":
                    self._validate_hsts(value, result)
                # Check CSP quality
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

    def _check_info_leaks(self, headers, result: dict):
        """Check for information leakage via headers."""
        for header in INFO_LEAK_HEADERS:
            value = headers.get(header)
            if value:
                result["info_leaks"].append({
                    "header": header,
                    "value": value,
                    "severity": "low",
                    "recommendation": f"Remove or obscure the '{header}' header to reduce fingerprinting",
                })

    def _check_cookies(self, headers, scheme: str, result: dict):
        """Check cookie security flags."""
        set_cookies = headers.get("Set-Cookie", "")
        if not set_cookies:
            return

        cookies = set_cookies.split(",") if "," in set_cookies else [set_cookies]
        for cookie in cookies:
            cookie = cookie.strip()
            issues = []

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

    def _validate_hsts(self, value: str, result: dict):
        """Validate HSTS header configuration."""
        value_lower = value.lower()
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
                pass

        if "includesubdomains" not in value_lower:
            result["issues"].append({
                "issue": "hsts_no_includesubdomains",
                "severity": "low",
                "detail": "HSTS does not include subdomains",
                "recommendation": "Add includeSubDomains to HSTS header",
            })

    def _validate_csp(self, value: str, result: dict):
        """Validate CSP header for dangerous directives."""
        value_lower = value.lower()
        dangerous = []

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
        """Get TLS certificate and protocol information."""
        tls_info = {}
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
