"""
DNS Enumeration Module.

Combines passive and active subdomain discovery:
  - Certificate Transparency logs (crt.sh — no API key needed)
  - DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - DNS brute-force with a focused wordlist
  - Reverse DNS lookups
"""

import json
import logging
import socket
import time
from typing import Any

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Focused subdomain wordlist for brute-force
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "admin", "portal", "vpn", "remote", "api", "dev", "staging",
    "test", "uat", "app", "apps", "blog", "shop", "store", "cdn",
    "static", "assets", "img", "images", "media", "video", "docs",
    "wiki", "help", "support", "status", "monitor", "grafana",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "jira", "confluence", "slack", "teams", "zoom", "meet",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "search", "kibana", "prometheus", "nagios", "zabbix",
    "mx", "mx1", "mx2", "ns3", "ns4", "dns", "dns1", "dns2",
    "intranet", "extranet", "sso", "auth", "login", "signin",
    "backup", "bak", "old", "new", "beta", "alpha", "sandbox",
    "m", "mobile", "wap", "api-v2", "api-v1", "v1", "v2",
    "crm", "erp", "hr", "finance", "billing", "payment", "pay",
    "internal", "private", "public", "external", "gateway", "proxy",
    "lb", "loadbalancer", "edge", "node", "worker", "web",
    "exchange", "autodiscover", "owa", "cpanel", "whm", "webdisk",
]


class DNSEnum(ReconModule):
    """Enumerates DNS records and discovers subdomains."""

    name = "dns_enum"
    description = "Passive and active DNS enumeration with subdomain discovery"
    category = "dns"

    def run(self, targets: dict) -> dict:
        """Run DNS enumeration on target domains."""
        results = {
            "subdomains": [],
            "records": {},
            "zone_transfer": {},
            "reverse_dns": {},
        }

        domains = targets.get("domains", [])
        timeout = self.scan_settings.get("dns_timeout", 10)

        for domain in domains:
            self.logger.info(f"Enumerating DNS for: {domain}")

            # 1. Enumerate standard DNS records
            records = self._enumerate_records(domain, timeout)
            results["records"][domain] = records

            # 2. Passive subdomain discovery via crt.sh
            ct_subs = self._crtsh_subdomains(domain)
            self.logger.info(f"crt.sh found {len(ct_subs)} subdomains for {domain}")

            # 3. Active brute-force subdomain discovery
            brute_subs = self._brute_force_subdomains(domain, timeout)
            self.logger.info(f"Brute-force found {len(brute_subs)} subdomains for {domain}")

            # 4. Attempt zone transfer (usually blocked, but worth trying)
            zt_result = self._try_zone_transfer(domain, timeout)
            if zt_result:
                results["zone_transfer"][domain] = zt_result

            # Merge all subdomains
            all_subs = sorted(set(ct_subs + brute_subs))
            results["subdomains"].extend(all_subs)

            # 5. Resolve and get details for each subdomain
            for sub in all_subs:
                sub_records = self._resolve_subdomain(sub, timeout)
                if sub_records:
                    results["records"][sub] = sub_records

        # Deduplicate
        results["subdomains"] = sorted(set(results["subdomains"]))
        return results

    def _enumerate_records(self, domain: str, timeout: int) -> dict:
        """Get all DNS record types for a domain."""
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception as e:
                self.logger.debug(f"DNS query {rtype} for {domain}: {e}")

        return records

    def _crtsh_subdomains(self, domain: str) -> list:
        """Query certificate transparency logs via crt.sh."""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Handle wildcard and multi-line entries
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub.lower())
        except requests.RequestException as e:
            self.logger.warning(f"crt.sh query failed for {domain}: {e}")
        except (json.JSONDecodeError, ValueError):
            self.logger.warning(f"crt.sh returned invalid JSON for {domain}")

        return sorted(subdomains)

    def _brute_force_subdomains(self, domain: str, timeout: int) -> list:
        """Brute-force common subdomain names."""
        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        rate = self.scan_settings.get("port_scan_rate", 10)
        delay = 1.0 / rate if rate > 0 else 0.1

        for prefix in SUBDOMAIN_WORDLIST:
            subdomain = f"{prefix}.{domain}"
            try:
                answers = resolver.resolve(subdomain, "A")
                if answers:
                    found.append(subdomain)
                    self.logger.debug(f"Found: {subdomain}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass
            time.sleep(delay * 0.5)  # Slow down to avoid rate limiting

        return found

    def _try_zone_transfer(self, domain: str, timeout: int) -> dict:
        """Attempt DNS zone transfer (AXFR)."""
        result = {"attempted": True, "successful": False, "records": []}
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_host = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_host, domain, timeout=timeout)
                    )
                    result["successful"] = True
                    result["nameserver"] = ns_host
                    result["records"] = [
                        {"name": str(name), "ttl": str(node.to_text())}
                        for name, node in zone.nodes.items()
                    ]
                    self.logger.warning(
                        f"ZONE TRANSFER SUCCESSFUL for {domain} via {ns_host}!"
                    )
                    break
                except Exception:
                    pass
        except Exception:
            pass
        return result

    def _resolve_subdomain(self, subdomain: str, timeout: int) -> dict:
        """Resolve a subdomain to IP and get basic records."""
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        for rtype in ["A", "AAAA", "CNAME"]:
            try:
                answers = resolver.resolve(subdomain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except Exception:
                pass

        return records
