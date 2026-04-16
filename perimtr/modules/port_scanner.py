"""
Port Scanner Module.

Performs slow, stealthy SYN scans of well-known ports on target networks.
Uses python-nmap with rate limiting to avoid being blocked.
"""

import ipaddress
import logging
import socket
import time
from typing import Any

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Well-known ports commonly found on perimeters
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 500, 587, 636, 993, 995, 1433, 1434, 1723, 3306, 3389, 5060,
    5432, 5900, 5985, 5986, 8000, 8080, 8443, 8888, 9090, 9200, 9443, 27017
]


class PortScanner(ReconModule):
    """Scans network ranges for open ports using slow, stealthy techniques."""

    name = "port_scanner"
    description = "Network port scanning with rate limiting to avoid detection"
    category = "network"

    def run(self, targets: dict) -> dict:
        """Scan all target networks for open ports."""
        results = {"hosts": {}, "total_hosts_scanned": 0, "total_open_ports": 0}
        networks = targets.get("networks", [])
        domains = targets.get("domains", [])

        # Also resolve domains to IPs for scanning
        domain_ips = {}
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                domain_ips[domain] = ip
                self.logger.info(f"Resolved {domain} -> {ip}")
            except socket.gaierror:
                self.logger.warning(f"Could not resolve {domain}")

        # Try nmap first, fall back to socket scanning
        try:
            results = self._scan_with_nmap(networks, domain_ips, results)
        except Exception as e:
            self.logger.warning(f"Nmap scan failed ({e}), falling back to socket scan")
            results = self._scan_with_sockets(networks, domain_ips, results)

        return results

    def _scan_with_nmap(self, networks: list, domain_ips: dict, results: dict) -> dict:
        """Scan using python-nmap for more accurate results."""
        import nmap

        nm = nmap.PortScanner()
        rate = self.scan_settings.get("port_scan_rate", 10)
        ports_str = ",".join(str(p) for p in TOP_PORTS)

        # Scan networks
        for network in networks:
            self.logger.info(f"Scanning network: {network}")
            try:
                nm.scan(
                    hosts=network,
                    ports=ports_str,
                    arguments=f"-sS -T2 --max-rate {rate} --open -n",
                    sudo=True,
                )
            except nmap.PortScannerError:
                # Try without sudo (TCP connect scan)
                nm.scan(
                    hosts=network,
                    ports=ports_str,
                    arguments=f"-sT -T2 --max-rate {rate} --open -n",
                )

            for host in nm.all_hosts():
                host_info = self._parse_nmap_host(nm, host)
                if host_info["ports"]:
                    results["hosts"][host] = host_info
                    results["total_open_ports"] += len(host_info["ports"])
                results["total_hosts_scanned"] += 1

        # Scan domain IPs
        for domain, ip in domain_ips.items():
            if ip not in results["hosts"]:
                self.logger.info(f"Scanning domain IP: {ip} ({domain})")
                try:
                    nm.scan(
                        hosts=ip,
                        ports=ports_str,
                        arguments=f"-sS -T2 --max-rate {rate} --open -sV",
                        sudo=True,
                    )
                except nmap.PortScannerError:
                    nm.scan(
                        hosts=ip,
                        ports=ports_str,
                        arguments=f"-sT -T2 --max-rate {rate} --open -sV",
                    )

                if ip in nm.all_hosts():
                    host_info = self._parse_nmap_host(nm, ip)
                    host_info["domain"] = domain
                    results["hosts"][ip] = host_info
                    results["total_open_ports"] += len(host_info["ports"])
                results["total_hosts_scanned"] += 1

        return results

    def _scan_with_sockets(self, networks: list, domain_ips: dict, results: dict) -> dict:
        """Fallback: scan using raw sockets (no nmap required)."""
        rate = self.scan_settings.get("port_scan_rate", 10)
        delay = 1.0 / rate if rate > 0 else 0.1

        # Collect all IPs to scan
        all_ips = []
        for network in networks:
            try:
                net = ipaddress.ip_network(network, strict=False)
                all_ips.extend([str(ip) for ip in net.hosts()])
            except ValueError:
                self.logger.warning(f"Invalid network: {network}")

        for domain, ip in domain_ips.items():
            if ip not in all_ips:
                all_ips.append(ip)

        # Scan each host
        for ip in all_ips:
            open_ports = []
            for port in TOP_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self._get_service_name(port)
                        open_ports.append({
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service,
                        })
                    sock.close()
                    time.sleep(delay)
                except (socket.timeout, OSError):
                    pass

            results["total_hosts_scanned"] += 1
            if open_ports:
                results["hosts"][ip] = {
                    "ports": open_ports,
                    "hostname": self._reverse_lookup(ip),
                    "domain": domain_ips.get(ip),
                }
                results["total_open_ports"] += len(open_ports)

        return results

    @staticmethod
    def _parse_nmap_host(nm, host: str) -> dict:
        """Parse nmap results for a single host."""
        ports = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_info = nm[host][proto][port]
                if port_info.get("state") == "open":
                    ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": "open",
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                    })
        return {
            "ports": ports,
            "hostname": nm[host].hostname() if nm[host].hostname() else None,
        }

    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get common service name for a port."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
            443: "https", 445: "microsoft-ds", 465: "smtps", 500: "isakmp",
            587: "submission", 636: "ldapssl", 993: "imaps", 995: "pop3s",
            1433: "ms-sql-s", 1434: "ms-sql-m", 1723: "pptp", 3306: "mysql",
            3389: "ms-wbt-server", 5060: "sip", 5432: "postgresql",
            5900: "vnc", 5985: "wsman", 5986: "wsmans", 8000: "http-alt",
            8080: "http-proxy", 8443: "https-alt", 8888: "sun-answerbook",
            9090: "zeus-admin", 9200: "elasticsearch", 9443: "tungsten-https",
            27017: "mongodb",
        }
        return services.get(port, "unknown")

    @staticmethod
    def _reverse_lookup(ip: str) -> str:
        """Attempt reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""
