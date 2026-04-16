"""
Vulnerability Check Module.

Performs basic vulnerability checks against discovered services:
  - Known default/dangerous service versions
  - Common CVE checks for exposed services
  - Banner grabbing for version identification
  - Basic authentication checks (anonymous FTP, open relays, etc.)
"""

import logging
import socket
import ssl
import time
from typing import Any

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Known vulnerable service patterns
VULN_PATTERNS = {
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
    """Performs basic vulnerability checks on discovered services."""

    name = "vuln_check"
    description = "Basic vulnerability and misconfiguration checks for exposed services"
    category = "vuln"

    def run(self, targets: dict) -> dict:
        """Run vulnerability checks against targets."""
        results = {"findings": [], "banners": {}, "summary": {}}
        networks = targets.get("networks", [])
        domains = targets.get("domains", [])
        rate = self.scan_settings.get("port_scan_rate", 10)
        delay = 1.0 / rate if rate > 0 else 0.1

        # Collect IPs to check from domains
        hosts_to_check = set()
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                hosts_to_check.add((ip, domain))
            except socket.gaierror:
                pass

        # Add network hosts (we check discovered ports from port_scanner results)
        # This module works best when run after port_scanner

        for host_ip, host_domain in hosts_to_check:
            self.logger.info(f"Vulnerability checking: {host_ip} ({host_domain})")

            for service_name, service_info in VULN_PATTERNS.items():
                port = service_info["port"]

                # Check if port is open
                if self._is_port_open(host_ip, port):
                    self.logger.info(f"  Port {port} ({service_name}) is open on {host_ip}")

                    # Grab banner
                    banner = self._grab_banner(host_ip, port)
                    if banner:
                        results["banners"][f"{host_ip}:{port}"] = banner

                    # Run vulnerability checks for this service
                    for check in service_info["checks"]:
                        finding = self._run_check(host_ip, host_domain, port, check, banner)
                        if finding:
                            results["findings"].append(finding)

                time.sleep(delay)

        # Build summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in results["findings"]:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        results["summary"] = {
            "total_findings": len(results["findings"]),
            "severity_counts": severity_counts,
        }

        return results

    def _is_port_open(self, host: str, port: int) -> bool:
        """Quick check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.timeout, OSError):
            return False

    def _grab_banner(self, host: str, port: int) -> str:
        """Grab service banner from a port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Some services send banner immediately, others need a prompt
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 25:
                pass  # SMTP sends banner on connect
            elif port == 21:
                pass  # FTP sends banner on connect
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:500]  # Limit banner length
        except Exception:
            return ""

    def _run_check(self, host: str, domain: str, port: int, check: dict, banner: str) -> dict:
        """Run a specific vulnerability check."""
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

        if finding:
            finding["host"] = host
            finding["domain"] = domain
            finding["port"] = port
            finding["banner"] = banner[:200] if banner else None

        return finding

    def _check_anonymous_ftp(self, host: str, port: int, check: dict) -> dict:
        """Check for anonymous FTP access."""
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

    def _check_cleartext_service(self, host: str, port: int, check: dict, service: str) -> dict:
        """Flag cleartext protocol usage."""
        return {
            "id": check["id"],
            "name": check["name"],
            "severity": check["severity"],
            "detail": f"{service} service is running in cleartext on port {port}",
            "recommendation": check["recommendation"],
        }

    def _check_ssh_banner(self, host: str, port: int, check: dict, banner: str) -> dict:
        """Check SSH banner for known weak versions."""
        if not banner:
            return None

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

    def _check_dangerous_service(self, host: str, port: int, check: dict, service: str) -> dict:
        """Flag dangerous services exposed to the internet."""
        return {
            "id": check["id"],
            "name": check["name"],
            "severity": check["severity"],
            "detail": f"{service} is exposed on port {port} — high-risk service",
            "recommendation": check["recommendation"],
        }

    def _check_smtp_relay(self, host: str, port: int, check: dict) -> dict:
        """Basic SMTP open relay check."""
        try:
            import smtplib
            smtp = smtplib.SMTP(host, port, timeout=10)
            smtp.ehlo("test.local")
            code, _ = smtp.docmd("MAIL FROM:", "<test@test.com>")
            if code == 250:
                code2, _ = smtp.docmd("RCPT TO:", "<test@example.org>")
                smtp.quit()
                if code2 == 250:
                    return {
                        "id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "detail": "SMTP server appears to allow open relaying",
                        "recommendation": check["recommendation"],
                    }
            smtp.quit()
        except Exception:
            pass
        return None

    def _check_http_cleartext(self, host: str, domain: str, port: int, check: dict) -> dict:
        """Check if HTTP on port 80 redirects to HTTPS."""
        try:
            url = f"http://{domain or host}"
            resp = requests.get(url, timeout=10, allow_redirects=False)
            location = resp.headers.get("Location", "")
            if not location.startswith("https://"):
                return {
                    "id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "detail": "HTTP does not redirect to HTTPS",
                    "recommendation": check["recommendation"],
                }
        except Exception:
            pass
        return None

    def _check_redis_noauth(self, host: str, port: int, check: dict) -> dict:
        """Check if Redis accepts unauthenticated connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(b"PING\r\n")
            response = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            if "+PONG" in response:
                return {
                    "id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "detail": "Redis accepts unauthenticated connections (PING → PONG)",
                    "recommendation": check["recommendation"],
                }
        except Exception:
            pass
        return None

    def _check_elasticsearch(self, host: str, port: int, check: dict) -> dict:
        """Check if Elasticsearch is accessible without auth."""
        try:
            resp = requests.get(f"http://{host}:{port}/", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if "cluster_name" in data or "version" in data:
                    return {
                        "id": check["id"],
                        "name": check["name"],
                        "severity": check["severity"],
                        "detail": f"Elasticsearch accessible without authentication (cluster: {data.get('cluster_name', 'unknown')})",
                        "recommendation": check["recommendation"],
                    }
        except Exception:
            pass
        return None

    def _check_snmp_default(self, host: str, port: int, check: dict) -> dict:
        """Check for SNMP default community strings."""
        # Basic UDP SNMP check with common community strings
        try:
            for community in ["public", "private"]:
                # Build SNMP GET request for sysDescr.0
                # This is a minimal SNMPv1 GET-REQUEST
                packet = self._build_snmp_get(community)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(packet, (host, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    if len(data) > 0:
                        sock.close()
                        return {
                            "id": check["id"],
                            "name": check["name"],
                            "severity": check["severity"],
                            "detail": f"SNMP responds to default community string '{community}'",
                            "recommendation": check["recommendation"],
                        }
                except socket.timeout:
                    pass
                sock.close()
        except Exception:
            pass
        return None

    @staticmethod
    def _build_snmp_get(community: str) -> bytes:
        """Build a minimal SNMPv1 GET-REQUEST for sysDescr.0."""
        community_bytes = community.encode()
        # OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) in BER encoding
        oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
        # NULL value
        null_val = b"\x05\x00"
        # VarBind
        varbind = oid + null_val
        varbind_seq = b"\x30" + bytes([len(varbind)]) + varbind
        # VarBindList
        varbind_list = b"\x30" + bytes([len(varbind_seq)]) + varbind_seq
        # Request ID
        request_id = b"\x02\x01\x01"
        # Error status and index
        error = b"\x02\x01\x00\x02\x01\x00"
        # PDU
        pdu_content = request_id + error + varbind_list
        pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content
        # Community string
        comm = b"\x04" + bytes([len(community_bytes)]) + community_bytes
        # Version (SNMPv1 = 0)
        version = b"\x02\x01\x00"
        # Message
        msg_content = version + comm + pdu
        message = b"\x30" + bytes([len(msg_content)]) + msg_content
        return message
