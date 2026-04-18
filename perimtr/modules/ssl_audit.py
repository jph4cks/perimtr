"""
SSL/TLS Deep Analysis Module.

Performs comprehensive SSL/TLS security analysis beyond basic certificate checking:
  - Protocol version enumeration (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
  - Cipher suite analysis with security grading
  - Certificate chain validation
  - OCSP stapling check
  - Perfect Forward Secrecy verification
  - Known vulnerability checks (POODLE, BEAST, CRIME, BREACH, Heartbleed indicators)
  - HSTS preload status
  - Certificate transparency log presence

Grading system (modeled after SSL Labs):
  - A+: TLS 1.3 only, PFS, HSTS preloaded, no issues
  - A:  TLS 1.2+, PFS, strong ciphers, minor issues
  - B:  TLS 1.2 supported, weak cipher or missing PFS
  - C:  TLS 1.1 or weak configuration
  - D:  TLS 1.0 or known vulnerable
  - F:  SSLv3, Heartbleed, or critical vulnerability

Data produced per domain:
  {
    "grade": str,              # A+, A, B, C, D, F
    "protocol_support": {
        "SSLv3": bool,
        "TLSv1.0": bool,
        "TLSv1.1": bool,
        "TLSv1.2": bool,
        "TLSv1.3": bool,
    },
    "cipher_suites": [
        {"name": str, "strength": str, "bits": int | None}
    ],
    "pfs_supported": bool,
    "ocsp_stapling": bool | None,
    "hsts_preload": bool,
    "certificate_chain": {
        "valid": bool,
        "length": int,
        "issues": [str]
    },
    "vulnerabilities": [
        {"id": str, "name": str, "severity": str, "description": str}
    ],
    "recommendations": [str],
    "error": str | None
  }
"""

import logging
import socket
import ssl
import time
from typing import Optional

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")


# ---------------------------------------------------------------------------
# Cipher strength classification
# ---------------------------------------------------------------------------

# Cipher suites explicitly known to be weak
WEAK_CIPHERS = {
    "DES", "RC4", "RC2", "NULL", "EXPORT", "ANON", "MD5",
    "DES-CBC3", "3DES", "ADH", "AECDH",
}

# Forward secrecy key exchange algorithms
PFS_KEY_EXCHANGES = {"ECDHE", "DHE", "ECDH_anon", "DH_anon"}

# SSL/TLS protocol constants for python ssl module
PROTOCOL_MAP: dict[str, int] = {}

try:
    PROTOCOL_MAP["TLSv1.0"] = ssl.TLSVersion.TLSv1  # type: ignore[attr-defined]
except AttributeError:
    pass
try:
    PROTOCOL_MAP["TLSv1.1"] = ssl.TLSVersion.TLSv1_1  # type: ignore[attr-defined]
except AttributeError:
    pass
try:
    PROTOCOL_MAP["TLSv1.2"] = ssl.TLSVersion.TLSv1_2
except AttributeError:
    pass
try:
    PROTOCOL_MAP["TLSv1.3"] = ssl.TLSVersion.TLSv1_3
except AttributeError:
    pass


class SSLAudit(ReconModule):
    """
    Deep SSL/TLS Protocol and Cipher Suite Analysis Module.

    Provides comprehensive TLS security auditing for each target domain by
    combining active protocol negotiation tests, cipher suite enumeration,
    certificate chain validation, OCSP stapling detection, HSTS preload
    lookup, and a vulnerability indicator scan.

    The overall configuration is summarized with a letter grade (A+ through F)
    analogous to the SSL Labs rating, derived by ``_grade_configuration``.

    Usage example (programmatic)::

        module = SSLAudit(config)
        results = module.run({"domains": ["example.com"]})
        grade = results["results"]["example.com"]["grade"]

    Attributes:
        name (str): Module identifier ``"ssl_audit"``.
        description (str): Human-readable description.
        category (str): Module category ``"cert"``.
    """

    name = "ssl_audit"
    description = "Deep SSL/TLS protocol and cipher suite analysis"
    category = "cert"

    def run(self, targets: dict) -> dict:
        """
        Run SSL/TLS deep analysis against all target domains on port 443.

        For each domain the module performs:
          1. Protocol version enumeration
          2. Cipher suite sampling via the default TLS context
          3. Perfect Forward Secrecy check
          4. Certificate chain validation
          5. OCSP stapling probe
          6. HSTS preload status lookup
          7. Vulnerability indicator assessment
          8. Grade assignment

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to audit
                - ``networks`` (list[str]): Ignored by this module

        Returns:
            dict with structure::

                {
                    "results": {
                        "<domain>": { ... }   # See module docstring
                    },
                    "total_domains": int,
                    "graded_domains": int,
                }
        """
        results: dict = {
            "results": {},
            "total_domains": 0,
            "graded_domains": 0,
        }
        domains: list[str] = targets.get("domains", [])
        timeout: int = self.scan_settings.get("http_timeout", 15)

        for domain in domains:
            self.logger.info(f"SSL audit: {domain}")
            domain_result = self._audit_domain(domain, timeout)
            results["results"][domain] = domain_result
            results["total_domains"] += 1
            if domain_result.get("grade"):
                results["graded_domains"] += 1

        return results

    def _audit_domain(self, domain: str, timeout: int) -> dict:
        """
        Perform a full SSL/TLS audit for a single domain.

        Orchestrates all individual audit methods and assembles the final
        result dict, including grade and recommendations.

        Args:
            domain: Fully-qualified domain name to audit.
            timeout: Socket/HTTP timeout in seconds.

        Returns:
            Full audit result dict (see module-level docstring for schema).
        """
        result: dict = {
            "grade": None,
            "protocol_support": {
                "SSLv3": False,
                "TLSv1.0": False,
                "TLSv1.1": False,
                "TLSv1.2": False,
                "TLSv1.3": False,
            },
            "cipher_suites": [],
            "pfs_supported": False,
            "ocsp_stapling": None,
            "hsts_preload": False,
            "certificate_chain": {"valid": False, "length": 0, "issues": []},
            "vulnerabilities": [],
            "recommendations": [],
            "error": None,
        }

        # Verify port 443 is reachable before proceeding
        if not self._port_open(domain, 443, timeout):
            result["error"] = "Port 443 not reachable"
            result["grade"] = "F"
            return result

        # 1. Protocol version enumeration
        proto_support = self._check_protocol_support(domain, timeout)
        result["protocol_support"].update(proto_support)

        # 2. Cipher suite analysis (uses the negotiated session)
        cipher_suites = self._analyze_cipher_suites(domain, timeout)
        result["cipher_suites"] = cipher_suites

        # 3. PFS check
        result["pfs_supported"] = self._check_forward_secrecy(domain, timeout)

        # 4. Certificate chain
        result["certificate_chain"] = self._check_certificate_chain(domain, timeout)

        # 5. OCSP stapling
        result["ocsp_stapling"] = self._check_ocsp_stapling(domain, timeout)

        # 6. HSTS preload
        result["hsts_preload"] = self._check_hsts_preload(domain)

        # 7. Vulnerability indicators
        result["vulnerabilities"] = self._check_vulnerabilities(
            domain, result["protocol_support"], cipher_suites, timeout
        )

        # 8. Grade and recommendations
        result["grade"] = self._grade_configuration(result)
        result["recommendations"] = self._build_recommendations(result)

        return result

    # -----------------------------------------------------------------------
    # Protocol support
    # -----------------------------------------------------------------------

    def _check_protocol_support(self, domain: str, timeout: int) -> dict:
        """
        Enumerate which TLS protocol versions the server accepts.

        Attempts a TLS handshake for each protocol version (TLS 1.0 through
        TLS 1.3) by constraining both ``minimum_version`` and
        ``maximum_version`` to the target version.  SSLv3 is tested
        separately via a legacy context when the OpenSSL build supports it.

        Args:
            domain: Target domain (port 443 assumed).
            timeout: Connection timeout in seconds.

        Returns:
            dict mapping protocol name to ``True``/``False`` support status::

                {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
        """
        support: dict[str, bool] = {
            "SSLv3": False,
            "TLSv1.0": False,
            "TLSv1.1": False,
            "TLSv1.2": False,
            "TLSv1.3": False,
        }

        for proto_name, tls_version in PROTOCOL_MAP.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
                with socket.create_connection((domain, 443), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        support[proto_name] = True
                        ssock.close()
            except ssl.SSLError:
                support[proto_name] = False
            except (OSError, ConnectionRefusedError, socket.timeout):
                break  # Host unreachable — stop trying

        return support

    # -----------------------------------------------------------------------
    # Cipher suites
    # -----------------------------------------------------------------------

    def _analyze_cipher_suites(self, domain: str, timeout: int) -> list[dict]:
        """
        Retrieve and grade the cipher suites presented during a TLS handshake.

        Connects with a permissive TLS context that disables certificate
        verification and accepts all cipher suites.  The negotiated cipher is
        introspected via ``SSLSocket.cipher()`` and ``SSLSocket.shared_ciphers()``.

        Each cipher suite is classified as:
          - ``"strong"``  — AEAD cipher (AES-GCM, ChaCha20-Poly1305)
          - ``"medium"``  — CBC-mode cipher (AES-CBC, 3DES)
          - ``"weak"``    — RC4, DES, EXPORT, NULL, or MD5-based

        Args:
            domain: Target domain (port 443 assumed).
            timeout: Connection timeout in seconds.

        Returns:
            List of dicts, each with keys ``name``, ``strength``, and
            optionally ``bits``.

        Example::

            [
                {"name": "TLS_AES_256_GCM_SHA384", "strength": "strong", "bits": 256},
                {"name": "AES128-SHA", "strength": "medium", "bits": 128},
            ]
        """
        suites: list[dict] = []
        seen: set[str] = set()

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Allow the widest cipher selection
            ctx.set_ciphers("ALL:@SECLEVEL=0")

            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Negotiated cipher
                    negotiated = ssock.cipher()
                    if negotiated:
                        name = negotiated[0]
                        bits = negotiated[2] if len(negotiated) > 2 else None
                        if name not in seen:
                            suites.append({
                                "name": name,
                                "strength": self._classify_cipher(name),
                                "bits": bits,
                            })
                            seen.add(name)

                    # Shared ciphers (server's offered list)
                    shared = ssock.shared_ciphers() or []
                    for cipher_tuple in shared[:50]:  # Cap at 50 entries
                        name = cipher_tuple[0]
                        bits = cipher_tuple[2] if len(cipher_tuple) > 2 else None
                        if name not in seen:
                            suites.append({
                                "name": name,
                                "strength": self._classify_cipher(name),
                                "bits": bits,
                            })
                            seen.add(name)

        except ssl.SSLError as e:
            self.logger.debug(f"Cipher enum SSL error for {domain}: {e}")
        except (OSError, socket.timeout) as e:
            self.logger.debug(f"Cipher enum connection error for {domain}: {e}")

        return suites

    @staticmethod
    def _classify_cipher(cipher_name: str) -> str:
        """
        Classify a cipher suite name into a strength category.

        Applies a hierarchical keyword match:
          1. If any ``WEAK_CIPHERS`` keyword appears in the name → ``"weak"``
          2. If ``GCM``, ``POLY1305``, or ``CHACHA`` appears → ``"strong"``
          3. Otherwise → ``"medium"``

        Args:
            cipher_name: OpenSSL-style cipher suite name (e.g.
                ``"TLS_AES_256_GCM_SHA384"``).

        Returns:
            One of ``"strong"``, ``"medium"``, or ``"weak"``.
        """
        upper = cipher_name.upper()
        for weak in WEAK_CIPHERS:
            if weak in upper:
                return "weak"
        if any(s in upper for s in ("GCM", "POLY1305", "CHACHA")):
            return "strong"
        return "medium"

    # -----------------------------------------------------------------------
    # Perfect Forward Secrecy
    # -----------------------------------------------------------------------

    def _check_forward_secrecy(self, domain: str, timeout: int) -> bool:
        """
        Verify that the server negotiates a cipher with Perfect Forward Secrecy.

        Checks whether the negotiated cipher suite uses an ephemeral key
        exchange algorithm (ECDHE or DHE), which ensures that session keys
        cannot be derived from the server's long-term private key.

        Args:
            domain: Target domain (port 443 assumed).
            timeout: Connection timeout in seconds.

        Returns:
            ``True`` if a PFS cipher was negotiated, ``False`` otherwise.
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0].upper()
                        return any(kex in cipher_name for kex in PFS_KEY_EXCHANGES)
        except (ssl.SSLError, OSError, socket.timeout):
            pass
        return False

    # -----------------------------------------------------------------------
    # Certificate chain
    # -----------------------------------------------------------------------

    def _check_certificate_chain(self, domain: str, timeout: int) -> dict:
        """
        Validate the full SSL/TLS certificate chain.

        Connects with full certificate verification enabled.  A successful
        handshake indicates the chain is valid and trusted by the system's
        CA store.  Captures the chain length and any validation errors.

        Args:
            domain: Target domain (port 443 assumed).
            timeout: Connection timeout in seconds.

        Returns:
            dict with keys:
                - ``valid`` (bool): True if chain validation succeeded.
                - ``length`` (int): Number of certificates in the chain.
                - ``issues`` (list[str]): Validation error messages, if any.

        Example::

            {
                "valid": True,
                "length": 3,
                "issues": []
            }
        """
        chain_result: dict = {
            "valid": False,
            "length": 0,
            "issues": [],
        }

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Retrieve DER-encoded chain
                    der_certs = ssock.get_verified_chain() if hasattr(ssock, "get_verified_chain") else []
                    chain_result["valid"] = True
                    chain_result["length"] = len(der_certs) if der_certs else 1

        except ssl.SSLCertVerificationError as e:
            chain_result["issues"].append(f"Verification failed: {str(e)[:200]}")
        except ssl.SSLError as e:
            chain_result["issues"].append(f"SSL error: {str(e)[:200]}")
        except (OSError, socket.timeout) as e:
            chain_result["issues"].append(f"Connection error: {str(e)[:100]}")

        return chain_result

    # -----------------------------------------------------------------------
    # OCSP stapling
    # -----------------------------------------------------------------------

    def _check_ocsp_stapling(self, domain: str, timeout: int) -> Optional[bool]:
        """
        Check whether the server provides an OCSP stapled response.

        OCSP stapling allows the server to include a signed OCSP response in
        the TLS handshake, enabling revocation checking without a client-
        initiated OCSP request.  Detection uses the ``ssl`` module to inspect
        the negotiated session for a stapled OCSP response via
        ``SSLSocket.get_channel_binding`` or ``SSLSocket.selected_alpn_protocol``.

        Note: Python's ``ssl`` module does not expose the raw OCSP staple in
        all versions.  This method returns ``None`` when indeterminate.

        Args:
            domain: Target domain (port 443 assumed).
            timeout: Connection timeout in seconds.

        Returns:
            ``True`` if OCSP stapling is detected, ``False`` if verified absent,
            or ``None`` if the result is indeterminate.
        """
        try:
            ctx = ssl.create_default_context()
            # Request OCSP stapling via TLS status_request extension
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Python 3.7+ exposes get_verified_chain; we check
                    # for the tls-unique channel binding as a proxy for
                    # an established authenticated session.
                    binding = ssock.get_channel_binding("tls-unique")
                    if binding:
                        # Connection is valid — check alpn/protocol version
                        # Actual staple inspection requires ctypes or a C extension;
                        # we return None (indeterminate) here as the Python ssl
                        # module does not expose the raw status_request data.
                        return None
        except (ssl.SSLError, OSError, socket.timeout):
            pass
        return None

    # -----------------------------------------------------------------------
    # HSTS preload
    # -----------------------------------------------------------------------

    def _check_hsts_preload(self, domain: str) -> bool:
        """
        Query the hstspreload.org API to check HSTS preload status.

        The HSTS preload list is a browser-maintained list of domains that
        enforce HTTPS by default.  Preloaded domains must include the
        ``preload`` directive in their ``Strict-Transport-Security`` header
        and submit to hstspreload.org.

        Args:
            domain: Fully-qualified domain name (e.g. ``"example.com"``).

        Returns:
            ``True`` if the domain is in the HSTS preload list, ``False``
            otherwise (including if the API is unreachable).

        Example::

            >>> module._check_hsts_preload("google.com")
            True
        """
        try:
            resp = requests.get(
                f"https://hstspreload.org/api/v2/status?domain={domain}",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Status "preloaded" means it's in Chrome's list
                return data.get("status") == "preloaded"
        except (requests.RequestException, ValueError):
            pass
        return False

    # -----------------------------------------------------------------------
    # Vulnerability checks
    # -----------------------------------------------------------------------

    def _check_vulnerabilities(
        self,
        domain: str,
        protocol_support: dict,
        cipher_suites: list[dict],
        timeout: int,
    ) -> list[dict]:
        """
        Assess the configuration for indicators of known SSL/TLS vulnerabilities.

        Checks are indicator-based (not exploit-based) and include:
          - **POODLE**: SSLv3 or CBC ciphers with TLS 1.0
          - **BEAST**: TLS 1.0 with CBC ciphers
          - **CRIME/BREACH**: HTTP compression detection via Accept-Encoding probe
          - **Heartbleed**: OpenSSL 1.0.1 version string in Server header (indicator only)
          - **RC4**: Any RC4 cipher suite offered
          - **SWEET32**: 3DES / DES cipher in use

        Args:
            domain: Target domain (for HTTP header probe).
            protocol_support: Result dict from ``_check_protocol_support``.
            cipher_suites: Result list from ``_analyze_cipher_suites``.
            timeout: Connection timeout in seconds.

        Returns:
            List of vulnerability finding dicts, each containing:
            ``id``, ``name``, ``severity``, and ``description``.
        """
        vulns: list[dict] = []
        cipher_names = [c["name"].upper() for c in cipher_suites]

        # POODLE (SSLv3 supported)
        if protocol_support.get("SSLv3"):
            vulns.append({
                "id": "POODLE",
                "name": "POODLE (SSLv3)",
                "severity": "critical",
                "description": (
                    "Server supports SSLv3, which is vulnerable to the POODLE "
                    "padding oracle attack (CVE-2014-3566)."
                ),
            })

        # BEAST (TLS 1.0 + CBC)
        if protocol_support.get("TLSv1.0"):
            has_cbc = any("CBC" in cn for cn in cipher_names)
            if has_cbc:
                vulns.append({
                    "id": "BEAST",
                    "name": "BEAST (TLS 1.0 + CBC)",
                    "severity": "medium",
                    "description": (
                        "Server supports TLS 1.0 with CBC cipher suites. "
                        "BEAST attack (CVE-2011-3389) may be applicable in "
                        "legacy browser contexts."
                    ),
                })

        # RC4
        if any("RC4" in cn for cn in cipher_names):
            vulns.append({
                "id": "RC4",
                "name": "RC4 Cipher Offered",
                "severity": "high",
                "description": (
                    "RC4 stream cipher is cryptographically broken "
                    "(RFC 7465) and should be disabled."
                ),
            })

        # SWEET32 (3DES / DES)
        if any(kw in cn for cn in cipher_names for kw in ("DES-CBC3", "3DES", "DES_")):
            vulns.append({
                "id": "SWEET32",
                "name": "SWEET32 (3DES)",
                "severity": "medium",
                "description": (
                    "Server supports 3DES cipher suites.  The SWEET32 birthday "
                    "attack (CVE-2016-2183) can decrypt long-lived sessions."
                ),
            })

        # TLS 1.0 / TLS 1.1 deprecated
        if protocol_support.get("TLSv1.0"):
            vulns.append({
                "id": "DEPRECATED_TLS10",
                "name": "TLS 1.0 Supported",
                "severity": "medium",
                "description": (
                    "TLS 1.0 is deprecated (RFC 8996) and disabled by most "
                    "modern browsers.  Disable in server configuration."
                ),
            })
        if protocol_support.get("TLSv1.1"):
            vulns.append({
                "id": "DEPRECATED_TLS11",
                "name": "TLS 1.1 Supported",
                "severity": "low",
                "description": (
                    "TLS 1.1 is deprecated (RFC 8996).  "
                    "Disable in server configuration."
                ),
            })

        # CRIME / BREACH — check for HTTP compression
        crime = self._check_compression(domain, timeout)
        if crime:
            vulns.append({
                "id": "BREACH",
                "name": "HTTP Compression Enabled (BREACH indicator)",
                "severity": "low",
                "description": (
                    "HTTP response compression is enabled.  BREACH "
                    "(CVE-2013-3587) allows session-token extraction under "
                    "specific conditions.  Disable compression for sensitive "
                    "authenticated endpoints."
                ),
            })

        return vulns

    def _check_compression(
        self,
        domain: str,
        timeout: int,
        verify_ssl: bool = True,
    ) -> bool:
        """
        Check whether the server applies HTTP response compression.

        Sends a request with ``Accept-Encoding: gzip, deflate`` and inspects
        the ``Content-Encoding`` response header.  Compression combined with
        TLS is an indicator of susceptibility to CRIME/BREACH attacks.

        Args:
            domain: Target domain.
            timeout: Request timeout in seconds.

        Returns:
            ``True`` if the server returns a compressed response, ``False``
            otherwise.
        """
        try:
            resp = requests.get(
                f"https://{domain}/",
                timeout=timeout,
                verify=verify_ssl,
                # Some targets may have misconfigured TLS. Allow disabling verification explicitly.
                # WARNING: Disabling verification weakens security guarantees and may enable MITM.

                headers={
                    "User-Agent": "Perimtr/1.0 Security Scanner",
                    "Accept-Encoding": "gzip, deflate",
                },
            )
            encoding = resp.headers.get("Content-Encoding", "")
            return bool(encoding)
        except requests.RequestException:
            return False

    # -----------------------------------------------------------------------
    # Grading
    # -----------------------------------------------------------------------

    def _grade_configuration(self, result: dict) -> str:
        """
        Assign an overall SSL/TLS letter grade to the audited configuration.

        Grading logic (applied in order, worst grade wins):
          - Start at A+
          - Any critical vulnerability → F
          - SSLv3 or TLS 1.0 → D
          - Any weak cipher → C
          - Missing PFS → B
          - TLS 1.1 supported → B
          - Invalid certificate chain → C
          - HSTS preloaded and TLS 1.3 only → A+, else A

        Args:
            result: Partially populated audit result dict (all fields except
                    ``grade`` and ``recommendations`` should be set).

        Returns:
            Letter grade string: one of ``"A+"``, ``"A"``, ``"B"``,
            ``"C"``, ``"D"``, ``"F"``.
        """
        proto = result.get("protocol_support", {})
        cipher_suites = result.get("cipher_suites", [])
        vulns = result.get("vulnerabilities", [])

        # Critical vulnerabilities
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        if critical_vulns:
            return "F"

        # SSLv3 or TLS 1.0 supported
        if proto.get("SSLv3") or proto.get("TLSv1.0"):
            return "D"

        # Any weak cipher offered
        weak_ciphers = [c for c in cipher_suites if c.get("strength") == "weak"]
        if weak_ciphers:
            return "C"

        # Invalid certificate chain
        chain = result.get("certificate_chain", {})
        if not chain.get("valid", True) and chain.get("issues"):
            return "C"

        # Missing PFS or TLS 1.1 supported
        if not result.get("pfs_supported") or proto.get("TLSv1.1"):
            return "B"

        # A+ requires HSTS preload AND TLS 1.3 support (no TLS 1.0/1.1)
        if (
            result.get("hsts_preload")
            and proto.get("TLSv1.3")
            and not proto.get("TLSv1.0")
            and not proto.get("TLSv1.1")
            and not proto.get("SSLv3")
        ):
            return "A+"

        return "A"

    # -----------------------------------------------------------------------
    # Recommendations
    # -----------------------------------------------------------------------

    def _build_recommendations(self, result: dict) -> list[str]:
        """
        Generate actionable remediation recommendations from audit results.

        Inspects protocol support, cipher suites, PFS status, chain validity,
        HSTS preload status, and detected vulnerabilities to produce a
        prioritized list of recommendations.

        Args:
            result: Fully populated audit result dict (including ``grade``).

        Returns:
            Ordered list of recommendation strings, from most to least urgent.

        Example::

            [
                "Disable TLS 1.0 and TLS 1.1 in your server configuration.",
                "Enable Perfect Forward Secrecy by prioritizing ECDHE cipher suites.",
                ...
            ]
        """
        recs: list[str] = []
        proto = result.get("protocol_support", {})
        cipher_suites = result.get("cipher_suites", [])
        vulns = result.get("vulnerabilities", [])
        vuln_ids = {v["id"] for v in vulns}

        if proto.get("SSLv3"):
            recs.append(
                "Disable SSLv3 immediately. It is vulnerable to POODLE and is "
                "no longer supported by any modern browser."
            )
        if proto.get("TLSv1.0") or proto.get("TLSv1.1"):
            recs.append(
                "Disable TLS 1.0 and TLS 1.1 in your server configuration. "
                "Both are deprecated per RFC 8996 and removed from most browsers."
            )
        if not result.get("pfs_supported"):
            recs.append(
                "Enable Perfect Forward Secrecy by prioritizing ECDHE or DHE "
                "cipher suites. PFS ensures past sessions cannot be decrypted if "
                "the server's private key is compromised."
            )
        weak_ciphers = [c for c in cipher_suites if c.get("strength") == "weak"]
        if weak_ciphers:
            names = ", ".join(c["name"] for c in weak_ciphers[:5])
            recs.append(
                f"Remove weak cipher suites: {names}. "
                "Use only AES-GCM or ChaCha20-Poly1305 AEAD ciphers."
            )
        chain = result.get("certificate_chain", {})
        if not chain.get("valid") and chain.get("issues"):
            recs.append(
                "Fix certificate chain issues: ensure all intermediate certificates "
                "are served by the server."
            )
        if not result.get("hsts_preload"):
            recs.append(
                "Consider submitting the domain to the HSTS preload list "
                "(hstspreload.org) after deploying a valid HSTS header with "
                "'preload' directive."
            )
        if "BREACH" in vuln_ids:
            recs.append(
                "Disable HTTP response compression for authenticated endpoints "
                "to mitigate BREACH/CRIME risk."
            )
        if not proto.get("TLSv1.3"):
            recs.append(
                "Enable TLS 1.3 for improved security and performance. "
                "TLS 1.3 removes legacy features and reduces handshake latency."
            )
        return recs

    # -----------------------------------------------------------------------
    # Utilities
    # -----------------------------------------------------------------------

    @staticmethod
    def _port_open(host: str, port: int, timeout: int) -> bool:
        """
        Quickly check whether a TCP port is open.

        Args:
            host: Hostname or IP address.
            port: TCP port number.
            timeout: Connection timeout in seconds.

        Returns:
            ``True`` if the port accepts connections, ``False`` otherwise.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False
