"""
Vulnerability Check Module.

Performs basic vulnerability checks against discovered services:
  - Known default/dangerous service versions
  - Common CVE checks for exposed services
  - Banner grabbing for version identification
  - Basic authentication checks (anonymous FTP, open relays, etc.)

How it works:
  1. Target domain names are resolved to IP addresses.
  2. For each (IP, domain) pair, every service in ``VULN_PATTERNS`` is
     checked: if the associated port is open (quick TCP connect), a banner
     is grabbed and the service-specific vulnerability checks are run.
  3. Each check function returns a finding dict or ``None`` (not vulnerable).
  4. All findings are collected and a severity summary is built.

Checks implemented:
  - FTP anonymous login (FTP-ANON)
  - FTP cleartext protocol (FTP-CLEAR)
  - SSH outdated version via banner (SSH-WEAK-ALGO)
  - Telnet exposed (TELNET-OPEN)
  - SMTP open relay (SMTP-OPEN-RELAY)
  - HTTP without TLS redirect (HTTP-CLEARTEXT)
  - RDP exposed to internet (RDP-EXPOSED)
  - Database servers exposed (MySQL, PostgreSQL, MongoDB)
  - Redis unauthenticated (REDIS-EXPOSED)
  - Elasticsearch unauthenticated (ELASTIC-EXPOSED)
  - VNC exposed (VNC-EXPOSED)
  - SNMP default community strings (SNMP-DEFAULT)

Data produced:
  {
    "findings": [
        {
            "id": str,
            "name": str,
            "severity": str,
            "detail": str,
            "recommendation": str,
            "host": str,
            "domain": str,
            "port": int,
            "banner": str | None
        }
    ],
    "banners": {
        "<ip>:<port>": str
    },
    "summary": {
        "total_findings": int,
        "severity_counts": {
            "critical": int, "high": int, "medium": int, "low": int, "info": int
        }
    }
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

# Vulnerability patterns: service name → port + list of checks to run.
# Each check specifies an ID, human name, severity, test type, and recommendation.
VULN_PATTERNS: dict = {
    "ftp": {
        "port": 21,
        "checks": [
            {
                "id": "FTP-ANON",
                "name": "Anonymous FTP Access",
                "severity": "high",
                "test": "anonymous_ftp",
                "recommendation": "Disable anonymous FTP access unless explicitly required",
            },
            {
                "id": "FTP-CLEAR",
                "name": "FTP Cleartext Protocol",
                "severity": "medium",
                "test": "cleartext_ftp",
                "recommendation": "Use SFTP or FTPS instead of plain FTP",
            },
        ],
    },
    "ssh": {
        "port": 22,
        "checks": [
            {
                "id": "SSH-WEAK-ALGO",
                "name": "SSH Weak Algorithms",
                "severity": "medium",
                "test": "ssh_banner",
                "recommendation": "Update SSH server and disable weak ciphers/key exchange algorithms",
            },
        ],
    },
    "telnet": {
        "port": 23,
        "checks": [
            {
                "id": "TELNET-OPEN",
                "name": "Telnet Service Exposed",
                "severity": "critical",
                "test": "telnet_open",
                "recommendation": "Disable Telnet and use SSH for remote administration",
            },
        ],
    },
    "smtp": {
        "port": 25,
        "checks": [
            {
                "id": "SMTP-OPEN-RELAY",
                "name": "SMTP Open Relay Check",
                "severity": "critical",
                "test": "smtp_relay",
                "recommendation": "Configure SMTP to reject unauthorized relaying",
            },
        ],
    },
    "http": {
        "port": 80,
        "checks": [
            {
                "id": "HTTP-CLEARTEXT",
                "name": "HTTP Without TLS",
                "severity": "medium",
                "test": "http_cleartext",
                "recommendation": "Redirect all HTTP traffic to HTTPS",
            },
        ],
    },
    "rdp": {
        "port": 3389,
        "checks": [
            {
                "id": "RDP-EXPOSED",
                "name": "RDP Exposed to Internet",
                "severity": "critical",
                "test": "rdp_exposed",
                "recommendation": "Place RDP behind VPN; never expose directly to the internet",
            },
        ],
    },
    "mysql": {
        "port": 3306,
        "checks": [
            {
                "id": "MYSQL-EXPOSED",
                "name": "MySQL Exposed to Internet",
                "severity": "critical",
                "test": "db_exposed",
                "recommendation": "Restrict database access to application servers only; use firewall rules",
            },
        ],
    },
    "postgresql": {
        "port": 5432,
        "checks": [
            {
                "id": "PGSQL-EXPOSED",
                "name": "PostgreSQL Exposed to Internet",
                "severity": "critical",
                "test": "db_exposed",
                "recommendation": "Restrict database access to application servers only; use firewall rules",
            },
        ],
    },
    "mongodb": {
        "port": 27017,
        "checks": [
            {
                "id": "MONGO-EXPOSED",
                "name": "MongoDB Exposed to Internet",
                "severity": "critical",
                "test": "db_exposed",
                "recommendation": "Restrict MongoDB access; enable authentication; bind to localhost",
            },
        ],
    },
    "redis": {
        "port": 6379,
        "checks": [
            {
                "id": "REDIS-EXPOSED",
                "name": "Redis Exposed Without Auth",
                "severity": "critical",
                "test": "redis_noauth",
                "recommendation": "Enable Redis AUTH, bind to localhost, and use firewall rules",
            },
        ],
    },
    "elasticsearch": {
        "port": 9200,
        "checks": [
            {
                "id": "ELASTIC-EXPOSED",
                "name": "Elasticsearch Exposed to Internet",
                "severity": "critical",
                "test": "elastic_exposed",
                "recommendation": "Restrict Elasticsearch access; enable X-Pack security or SearchGuard",
            },
        ],
    },
    "vnc": {
        "port": 5900,
        "checks": [
            {
                "id": "VNC-EXPOSED",
                "name": "VNC Exposed to Internet",
                "severity": "high",
                "test": "vnc_exposed",
                "recommendation": "Place VNC behind VPN; never expose directly to the internet",
            },
        ],
    },
    "snmp": {
        "port": 161,
        "checks": [
            {
                "id": "SNMP-DEFAULT",
                "name": "SNMP Default Community Strings",
                "severity": "high",
                "test": "snmp_default",
                "recommendation": "Change default SNMP community strings; use SNMPv3 with authentication",
            },
        ],
    },
}


class VulnCheck(ReconModule):
    """
    Basic Vulnerability Checker for Exposed Services.

    Resolves domain names to IPs and runs service-specific vulnerability
    checks against each open port matching the ``VULN_PATTERNS`` registry.
    Checks are designed to minimize false positives while being non-destructive.

    Attributes:
        name (str): Module identifier ``"vuln_check"``.
        description (str): Human-readable description.
        category (str): Module category ``"vuln"``.
    """

    name = "vuln_check"
    description = "Basic vulnerability and misconfiguration checks for exposed services"
    category = "vuln"

    def run(self, targets: dict) -> dict:
        """
        Run vulnerability checks against all target hosts.

        Resolves each domain to an IP, then iterates through all
        ``VULN_PATTERNS`` service definitions to check open ports and run
        associated vulnerability tests.

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to check.
                - ``networks`` (list[str]): Not directly scanned by this
                  module; port_scanner results would be needed for networks.

        Returns:
            dict with keys ``findings``, ``banners``, and ``summary``.
            See module-level docstring for the full schema.
        """
        results: dict = {"findings": [], "banners": {}, "summary": {}}
        networks = targets.get("networks", [])
        domains = targets.get("domains", [])
        rate = self.scan_settings.get("port_scan_rate", 10)
        delay = 1.0 / rate if rate > 0 else 0.1

        # Resolve domain names to IP addresses for checking
        hosts_to_check: set = set()
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                hosts_to_check.add((ip, domain))
            except socket.gaierror:
                pass

        # Note: this module works best when run after port_scanner, whose
        # results could be used to limit checks to known-open ports.

        for host_ip, host_domain in hosts_to_check:
            self.logger.info(f"Vulnerability checking: {host_ip} ({host_domain})")

            for service_name, service_info in VULN_PATTERNS.items():
                port = service_info["port"]

                # Only proceed if the port is actually open
                if self._is_port_open(host_ip, port):
                    self.logger.info(f"  Port {port} ({service_name}) is open on {host_ip}")

                    # Grab service banner for version analysis
                    banner = self._grab_banner(host_ip, port)
                    if banner:
                        results["banners"][f"{host_ip}:{port}"] = banner

                    # Run each configured check for this service
                    for check in service_info["checks"]:
                        finding = self._run_check(host_ip, host_domain, port, check, banner)
                        if finding:
                            results["findings"].append(finding)

                time.sleep(delay)

        # Build severity summary
        severity_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in results["findings"]:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        results["summary"] = {
            "total_findings": len(results["findings"]),
            "severity_counts": severity_counts,
        }

        return results

    def _is_port_open(self, host: str, port: int) -> bool:
        """
        Quick TCP connect check to determine if a port is open.

        Uses a 3-second timeout to avoid hanging on filtered (firewall-dropped)
        ports.

        Args:
            host: IP address or hostname to check.
            port: TCP port number to test.

        Returns:
            ``True`` if the port accepts a TCP connection, ``False`` otherwise.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            return result == 0
        except (socket.timeout, OSError):
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _grab_banner(self, host: str, port: int) -> str:
        """
        Grab a service banner from an open TCP port.

        Sends a minimal probe appropriate for the port (HEAD request for HTTP,
        no probe for banner-sending services like FTP/SMTP, CRLF for others)
        and reads up to 1024 bytes.

        Args:
            host: IP address of the target.
            port: TCP port to connect to.

        Returns:
            First 500 characters of the banner string, or an empty string
            if the banner cannot be read.

        Raises:
            No exceptions propagate; all errors return an empty string.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Service-specific probes: HTTP needs a request; banner services
            # (FTP, SMTP) send their banner immediately on connect.
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 25:
                pass  # SMTP sends banner on connect — no probe needed
            elif port == 21:
                pass  # FTP sends banner on connect — no probe needed
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:500]  # Truncate to avoid storing large responses
        except Exception:
            return ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _run_check(
        self, host: str, domain: str, port: int, check: dict, banner: str
    ) -> Optional[dict]:
        """
        Dispatch a single vulnerability check and return a finding or ``None``.

        Routes to the appropriate private check method based on the ``test``
        field of the check definition.  Enriches the finding with host/domain/
        port/banner context before returning.

        Args:
            host: IP address of the target.
            domain: Domain name associated with the host.
            port: Port number being checked.
            check: Check definition dict from ``VULN_PATTERNS``.
            banner: Service banner string (may be empty).

        Returns:
            Finding dict if the vulnerability is confirmed, or ``None``.
            The finding always includes ``host``, ``domain``, ``port``,
            and ``banner`` fields in addition to check-specific fields.
        """
        test_type = check["test"]
        finding = None

        if test_type == "anonymous_ftp":
            finding = self._check_anonymous_ftp(host, port, check)
        elif test_type == "cleartext_ftp":
            finding = self._check_cleartext_service(host, port, check, "FTP")
        elif test_type == "ssh_banner":
            finding = self._check_ssh_banner(host, port, check, banner)
        elif test_type == "telnet_open":
            finding = self._check_dangerous_service(host, port, check, "Telnet")
        elif test_type == "smtp_relay":
            finding = self._check_smtp_relay(host, port, check)
        elif test_type == "http_cleartext":
            finding = self._check_http_cleartext(host, domain, port, check)
        elif test_type == "rdp_exposed":
            finding = self._check_dangerous_service(host, port, check, "RDP")
        elif test_type == "db_exposed":
            finding = self._check_dangerous_service(host, port, check, check["name"].split(" ")[0])
        elif test_type == "redis_noauth":
            finding = self._check_redis_noauth(host, port, check)
        elif test_type == "elastic_exposed":
            finding = self._check_elasticsearch(host, port, check)
        elif test_type == "vnc_exposed":
            finding = self._check_dangerous_service(host, port, check, "VNC")
        elif test_type == "snmp_default":
            finding = self._check_snmp_default(host, port, check)

        # Enrich finding with context
        if finding:
            finding["host"] = host
            finding["domain"] = domain
            finding["port"] = port
            finding["banner"] = banner[:200] if banner else None

        return finding

    def _check_anonymous_ftp(self, host: str, port: int, check: dict) -> Optional[dict]:
        """
        Attempt an anonymous FTP login to verify open access.

        Uses the standard ``ftplib.FTP`` client with username ``"anonymous"``
        and a dummy email as the password.

        Args:
            host: IP address of the FTP server.
            port: FTP port (typically 21).
            check: Check definition dict.

        Returns:
            Finding dict if anonymous login succeeds, ``None`` otherwise.
        """
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login("anonymous", "test@test.com")
            ftp.quit()
            return {
                "id": check["id"],
                "name": check["name"],
                "severity": check["severity"],
                "detail": "Anonymous FTP login successful",
                "recommendation": check["recommendation"],
            }
        except Exception:
            return None

    def _check_cleartext_service(
        self, host: str, port: int, check: dict, service: str
    ) -> dict:
        """
        Flag a cleartext protocol as a finding (always positive when port is open).

        This check does not probe the service — the mere presence of FTP on
        port 21 is sufficient to flag it as a cleartext protocol risk.

        Args:
            host: IP address of the target.
            port: Port number.
            check: Check definition dict.
            service: Human-readable service name for the detail message.

        Returns:
            Finding dict (always non-None for this check type).
        """
        return {
            "id": check["id"],
            "name": check["name"],
            "severity": check["severity"],
            "detail": f"{service} service is running in cleartext on port {port}",
            "recommendation": check["recommendation"],
        }

    def _check_ssh_banner(
        self, host: str, port: int, check: dict, banner: str
    ) -> Optional[dict]:
        """
        Detect outdated SSH server versions from the service banner.

        Checks for SSH protocol version 1.x and known outdated OpenSSH
        versions (4.x, 5.x, 6.x) and Dropbear pre-release versions.

        Args:
            host: IP address of the SSH server.
            port: SSH port (typically 22).
            check: Check definition dict.
            banner: SSH banner string (e.g. ``"SSH-2.0-OpenSSH_5.3"``).

        Returns:
            Finding dict if a weak version indicator is present, ``None``
            if the version appears modern or the banner is empty.
        """
        if not banner:
            return None

        # Indicators of known-vulnerable SSH versions
        weak_indicators = ["SSH-1.", "dropbear_0.", "OpenSSH_4.", "OpenSSH_5.", "OpenSSH_6."]
        for indicator in weak_indicators:
            if indicator in banner:
                return {
                    "id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "detail": f"Outdated SSH version detected: {banner[:100]}",
                    "recommendation": check["recommendation"],
                }
        return None

    def _check_dangerous_service(
        self, host: str, port: int, check: dict, service: str
    ) -> dict:
        """
        Flag a high-risk service that should not be internet-exposed.

        This check is always positive when the port is open — the presence
        of RDP, VNC, or an exposed database server is itself the finding.

        Args:
            host: IP address of the target.
            port: Port number.
            check: Check definition dict.
            service: Human-readable service name.

        Returns:
            Finding dict (always non-None for this check type).
        """
        return {
            "id": check["id"],
            "name": check["name"],
            "severity": check["severity"],
            "detail": f"{service} is exposed on port {port} — high-risk service",
            "recommendation": check["recommendation"],
        }

    def _check_smtp_relay(self, host: str, port: int, check: dict) -> Optional[dict]:
        """
        Test for SMTP open relay by attempting to relay a test message.

        Sends EHLO, MAIL FROM, and RCPT TO commands using two different
        external-looking domains.  A positive response (250) to RCPT TO
        indicates the server may be acting as an open relay.

        Args:
            host: IP address of the SMTP server.
            port: SMTP port (typically 25).
            check: Check definition dict.

        Returns:
            Finding dict if relaying appears to be allowed, ``None``
            otherwise.

        Raises:
            No exceptions propagate; all SMTP errors return ``None``.
        """
        import smtplib

        smtp = None
        try:
            smtp = smtplib.SMTP(host, port, timeout=10)
            smtp.ehlo("test.local")
            code, _ = smtp.docmd("MAIL FROM:", "<test@test.com>")
            if code == 250:
                code2, _ = smtp.docmd("RCPT TO:", "<test@example.org>")
                if code2 == 250:
                    return {
                        "id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "detail": "SMTP server appears to allow open relaying",
                        "recommendation": check["recommendation"],
                    }
        except (OSError, smtplib.SMTPException):
            return None
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    # Best-effort cleanup; do not fail the scan on quit errors.
                    pass
        return None

    def _check_http_cleartext(
        self, host: str, domain: str, port: int, check: dict
    ) -> Optional[dict]:
        """
        Check if an HTTP service redirects to HTTPS.

        Makes a non-following GET request to verify whether the server
        sends a 3xx redirect to an HTTPS URL.  If the Location header is
        missing or does not start with ``https://``, the service is flagged.

        Args:
            host: IP address (used as fallback if domain is unavailable).
            domain: Domain name for the HTTP request.
            port: HTTP port (typically 80).
            check: Check definition dict.

        Returns:
            Finding dict if HTTP does not redirect to HTTPS, ``None``
            otherwise.
        """
        try:
            url = f"http://{domain or host}"
            with requests.get(url, timeout=10, allow_redirects=False, stream=True) as resp:
                location = resp.headers.get("Location", "")
                if not location.startswith("https://"):
                    return {
                        "id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "detail": "HTTP does not redirect to HTTPS",
                        "recommendation": check["recommendation"],
                    }
        except requests.RequestException:
            pass
        return None

    def _check_redis_noauth(self, host: str, port: int, check: dict) -> Optional[dict]:
        """
        Check if Redis accepts unauthenticated connections via the PING command.

        Sends a raw Redis ``PING`` command over TCP.  A ``+PONG`` response
        indicates no authentication is required.

        Args:
            host: IP address of the Redis server.
            port: Redis port (typically 6379).
            check: Check definition dict.

        Returns:
            Finding dict if Redis responds to unauthenticated PING, ``None``
            otherwise.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(b"PING\r\n")
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            if "+PONG" in response:
                return {
                    "id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "detail": "Redis accepts unauthenticated connections (PING → PONG)",
                    "recommendation": check["recommendation"],
                }
        except OSError:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    def _check_elasticsearch(self, host: str, port: int, check: dict) -> Optional[dict]:
        """
        Check if Elasticsearch is accessible without authentication.

        Makes an HTTP GET request to the Elasticsearch root endpoint.  A 200
        response containing ``cluster_name`` or ``version`` keys indicates
        the cluster is exposed without access controls.

        Args:
            host: IP address of the Elasticsearch node.
            port: Elasticsearch HTTP port (typically 9200).
            check: Check definition dict.

        Returns:
            Finding dict if Elasticsearch is unauthenticated, ``None``
            otherwise.
        """
        try:
            with requests.get(f"http://{host}:{port}/", timeout=5, stream=True) as resp:
                if resp.status_code == 200:
                    data = resp.json()
                    if "cluster_name" in data or "version" in data:
                        return {
                            "id": check["id"],
                            "name": check["name"],
                            "severity": check["severity"],
                            "detail": (
                                f"Elasticsearch accessible without authentication "
                                f"(cluster: {data.get('cluster_name', 'unknown')})"
                            ),
                            "recommendation": check["recommendation"],
                        }
        except (ValueError, requests.RequestException):
            pass
        return None

    def _check_snmp_default(self, host: str, port: int, check: dict) -> Optional[dict]:
        """
        Check for SNMP default community strings using SNMPv1 GET-REQUEST.

        Sends a minimal SNMPv1 GET-REQUEST for OID ``1.3.6.1.2.1.1.1.0``
        (sysDescr.0) using both ``"public"`` and ``"private"`` community
        strings.  Any response indicates the community string is accepted.

        Args:
            host: IP address of the SNMP device.
            port: SNMP UDP port (typically 161).
            check: Check definition dict.

        Returns:
            Finding dict if a default community string is accepted, ``None``
            otherwise.
        """
        try:
            for community in ["public", "private"]:
                # Build a minimal SNMPv1 GET-REQUEST packet
                packet = self._build_snmp_get(community)
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(3)
                    sock.sendto(packet, (host, port))
                    try:
                        data, _ = sock.recvfrom(1024)
                        if len(data) > 0:
                            return {
                                "id": check["id"],
                                "name": check["name"],
                                "severity": check["severity"],
                                "detail": f"SNMP responds to default community string '{community}'",
                                "recommendation": check["recommendation"],
                            }
                    except socket.timeout:
                        pass
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
        except Exception:
            pass
        return None

    @staticmethod
    def _build_snmp_get(community: str) -> bytes:
        """
        Build a minimal SNMPv1 GET-REQUEST PDU in BER encoding.

        Constructs the smallest valid SNMPv1 SEQUENCE that requests the
        sysDescr.0 MIB object (OID 1.3.6.1.2.1.1.1.0).  The packet uses
        the provided community string without any validation.

        Args:
            community: SNMP community string to embed (e.g. ``"public"``).

        Returns:
            Raw bytes of the SNMPv1 GET-REQUEST packet.

        Note:
            This implementation uses fixed-length BER encoding and is only
            suitable for short community strings and simple GET requests.
            For production SNMP work, use a dedicated library such as
            ``pysnmp``.
        """
        community_bytes = community.encode()
        # OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) in BER encoding
        oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
        # NULL value for the requested OID
        null_val = b"\x05\x00"
        # VarBind: SEQUENCE { OID, NULL }
        varbind = oid + null_val
        varbind_seq = b"\x30" + bytes([len(varbind)]) + varbind
        # VarBindList: SEQUENCE { VarBind }
        varbind_list = b"\x30" + bytes([len(varbind_seq)]) + varbind_seq
        # Request ID (integer 1)
        request_id = b"\x02\x01\x01"
        # Error status and error index (both 0)
        error = b"\x02\x01\x00\x02\x01\x00"
        # GetRequest-PDU (0xa0)
        pdu_content = request_id + error + varbind_list
        pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content
        # Community string OCTET STRING
        comm = b"\x04" + bytes([len(community_bytes)]) + community_bytes
        # Version: SNMPv1 = 0
        version = b"\x02\x01\x00"
        # Outer SEQUENCE
        msg_content = version + comm + pdu
        message = b"\x30" + bytes([len(msg_content)]) + msg_content
        return message
