"""
Diff / Change Detection Engine.

Compares two assessment results and produces a structured change report
showing new, removed, and changed findings across all modules.
"""

import logging
from typing import Any, Optional

logger = logging.getLogger("perimtr")


class DiffEngine:
    """Compares assessments to detect changes in the attack surface."""

    def __init__(self):
        self.changes = {
            "new": [],
            "removed": [],
            "changed": [],
            "summary": {},
        }

    def compare(self, current: dict, previous: dict) -> dict:
        """
        Compare current assessment with previous one.

        Returns a structured diff with new, removed, and changed items.
        """
        self.changes = {"new": [], "removed": [], "changed": [], "summary": {}}

        # Compare each module's results
        current_modules = {k: v for k, v in current.items() if not k.startswith("_")}
        previous_modules = {k: v for k, v in previous.items() if not k.startswith("_")}

        for module_name in set(list(current_modules.keys()) + list(previous_modules.keys())):
            curr_data = current_modules.get(module_name, {})
            prev_data = previous_modules.get(module_name, {})

            if module_name == "port_scanner":
                self._diff_ports(curr_data, prev_data)
            elif module_name == "dns_enum":
                self._diff_dns(curr_data, prev_data)
            elif module_name == "http_headers":
                self._diff_headers(curr_data, prev_data)
            elif module_name == "whois_cert":
                self._diff_certs(curr_data, prev_data)
            elif module_name == "vuln_check":
                self._diff_vulns(curr_data, prev_data)
            elif module_name == "domain_security":
                self._diff_domain_security(curr_data, prev_data)

        # Build summary
        self.changes["summary"] = {
            "total_new": len(self.changes["new"]),
            "total_removed": len(self.changes["removed"]),
            "total_changed": len(self.changes["changed"]),
            "has_changes": bool(
                self.changes["new"] or self.changes["removed"] or self.changes["changed"]
            ),
        }

        return self.changes

    def _diff_ports(self, current: dict, previous: dict):
        """Compare port scan results."""
        curr_hosts = self._extract_host_ports(current)
        prev_hosts = self._extract_host_ports(previous)

        for host, ports in curr_hosts.items():
            prev_ports = prev_hosts.get(host, set())
            new_ports = ports - prev_ports
            for port in new_ports:
                self.changes["new"].append({
                    "module": "port_scanner",
                    "type": "new_port",
                    "severity": "high",
                    "host": host,
                    "detail": f"New open port: {port}",
                })

        for host, ports in prev_hosts.items():
            curr_ports = curr_hosts.get(host, set())
            removed_ports = ports - curr_ports
            for port in removed_ports:
                self.changes["removed"].append({
                    "module": "port_scanner",
                    "type": "closed_port",
                    "severity": "info",
                    "host": host,
                    "detail": f"Port closed: {port}",
                })

            if host not in curr_hosts:
                self.changes["removed"].append({
                    "module": "port_scanner",
                    "type": "host_gone",
                    "severity": "medium",
                    "host": host,
                    "detail": "Host no longer responding",
                })

        for host in curr_hosts:
            if host not in prev_hosts:
                self.changes["new"].append({
                    "module": "port_scanner",
                    "type": "new_host",
                    "severity": "high",
                    "host": host,
                    "detail": f"New host discovered with ports: {', '.join(str(p) for p in curr_hosts[host])}",
                })

    def _diff_dns(self, current: dict, previous: dict):
        """Compare DNS enumeration results."""
        curr_subs = set(current.get("subdomains", []))
        prev_subs = set(previous.get("subdomains", []))

        for sub in curr_subs - prev_subs:
            self.changes["new"].append({
                "module": "dns_enum",
                "type": "new_subdomain",
                "severity": "medium",
                "detail": f"New subdomain: {sub}",
            })

        for sub in prev_subs - curr_subs:
            self.changes["removed"].append({
                "module": "dns_enum",
                "type": "removed_subdomain",
                "severity": "low",
                "detail": f"Subdomain removed: {sub}",
            })

        # Check for DNS record changes
        curr_records = current.get("records", {})
        prev_records = previous.get("records", {})
        for domain in set(list(curr_records.keys()) + list(prev_records.keys())):
            curr_recs = set(str(r) for r in curr_records.get(domain, []))
            prev_recs = set(str(r) for r in prev_records.get(domain, []))
            if curr_recs != prev_recs:
                self.changes["changed"].append({
                    "module": "dns_enum",
                    "type": "dns_record_changed",
                    "severity": "medium",
                    "detail": f"DNS records changed for {domain}",
                    "old": list(prev_recs),
                    "new": list(curr_recs),
                })

    def _diff_headers(self, current: dict, previous: dict):
        """Compare HTTP header results."""
        curr_missing = set()
        prev_missing = set()

        for domain, data in current.get("results", {}).items():
            for h in data.get("missing_headers", []):
                curr_missing.add(f"{domain}:{h}")

        for domain, data in previous.get("results", {}).items():
            for h in data.get("missing_headers", []):
                prev_missing.add(f"{domain}:{h}")

        for item in curr_missing - prev_missing:
            domain, header = item.split(":", 1)
            self.changes["new"].append({
                "module": "http_headers",
                "type": "new_missing_header",
                "severity": "medium",
                "detail": f"Security header now missing on {domain}: {header}",
            })

        for item in prev_missing - curr_missing:
            domain, header = item.split(":", 1)
            self.changes["removed"].append({
                "module": "http_headers",
                "type": "header_fixed",
                "severity": "info",
                "detail": f"Security header added on {domain}: {header}",
            })

    def _diff_certs(self, current: dict, previous: dict):
        """Compare certificate and WHOIS results."""
        for domain in set(
            list(current.get("certificates", {}).keys()) +
            list(previous.get("certificates", {}).keys())
        ):
            curr_cert = current.get("certificates", {}).get(domain, {})
            prev_cert = previous.get("certificates", {}).get(domain, {})

            if curr_cert.get("issuer") != prev_cert.get("issuer"):
                if curr_cert.get("issuer") and prev_cert.get("issuer"):
                    self.changes["changed"].append({
                        "module": "whois_cert",
                        "type": "cert_issuer_changed",
                        "severity": "high",
                        "detail": f"Certificate issuer changed for {domain}",
                        "old": prev_cert.get("issuer"),
                        "new": curr_cert.get("issuer"),
                    })

            if curr_cert.get("expiry") != prev_cert.get("expiry"):
                self.changes["changed"].append({
                    "module": "whois_cert",
                    "type": "cert_expiry_changed",
                    "severity": "info",
                    "detail": f"Certificate expiry changed for {domain}: {curr_cert.get('expiry')}",
                })

    def _diff_vulns(self, current: dict, previous: dict):
        """Compare vulnerability findings."""
        curr_vulns = set()
        prev_vulns = set()

        for vuln in current.get("findings", []):
            curr_vulns.add(f"{vuln.get('host', '')}:{vuln.get('id', '')}:{vuln.get('port', '')}")

        for vuln in previous.get("findings", []):
            prev_vulns.add(f"{vuln.get('host', '')}:{vuln.get('id', '')}:{vuln.get('port', '')}")

        for item in curr_vulns - prev_vulns:
            parts = item.split(":")
            self.changes["new"].append({
                "module": "vuln_check",
                "type": "new_vulnerability",
                "severity": "critical",
                "detail": f"New vulnerability on {parts[0]}: {parts[1]} (port {parts[2]})",
            })

        for item in prev_vulns - curr_vulns:
            parts = item.split(":")
            self.changes["removed"].append({
                "module": "vuln_check",
                "type": "vuln_remediated",
                "severity": "info",
                "detail": f"Vulnerability remediated on {parts[0]}: {parts[1]}",
            })

    def _diff_domain_security(self, current: dict, previous: dict):
        """Compare domain security results."""
        for domain in set(
            list(current.get("results", {}).keys()) +
            list(previous.get("results", {}).keys())
        ):
            curr_issues = set(
                i.get("issue", "") for i in current.get("results", {}).get(domain, {}).get("issues", [])
            )
            prev_issues = set(
                i.get("issue", "") for i in previous.get("results", {}).get(domain, {}).get("issues", [])
            )

            for issue in curr_issues - prev_issues:
                self.changes["new"].append({
                    "module": "domain_security",
                    "type": "new_domain_issue",
                    "severity": "medium",
                    "detail": f"New domain security issue for {domain}: {issue}",
                })

            for issue in prev_issues - curr_issues:
                self.changes["removed"].append({
                    "module": "domain_security",
                    "type": "domain_issue_fixed",
                    "severity": "info",
                    "detail": f"Domain security issue fixed for {domain}: {issue}",
                })

    @staticmethod
    def _extract_host_ports(data: dict) -> dict:
        """Extract host -> set of ports from port scan results."""
        host_ports = {}
        for host, info in data.get("hosts", {}).items():
            ports = set()
            for port_info in info.get("ports", []):
                if isinstance(port_info, dict):
                    ports.add(port_info.get("port", 0))
                else:
                    ports.add(port_info)
            host_ports[host] = ports
        return host_ports
