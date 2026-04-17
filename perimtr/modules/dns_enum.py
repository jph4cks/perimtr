"""
DNS Enumeration Module.

Combines passive and active subdomain discovery:
  - Certificate Transparency logs (crt.sh — no API key needed)
  - DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - DNS brute-force with a focused wordlist
  - Reverse DNS lookups

How it works:
  For each domain in ``targets["domains"]``:
    1. Standard DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) are queried
       and stored under ``results["records"][domain]``.
    2. crt.sh (Certificate Transparency) is queried for all certificates
       issued for ``*.domain`` to passively discover subdomains without
       generating any DNS traffic.
    3. A focused wordlist (``SUBDOMAIN_WORDLIST``) is resolved against the
       domain to discover additional subdomains via brute force.
    4. A DNS zone transfer (AXFR) is attempted against each authoritative
       nameserver — this almost always fails but is flagged as a critical
       finding when it succeeds.
    5. All discovered subdomains are resolved for their A/AAAA/CNAME records.

Data produced:
  {
    "subdomains": [str, ...],          # Deduplicated, sorted list
    "records": {
        "<domain>": {"A": [...], "MX": [...], ...},
        "<subdomain>": {"A": [...], "CNAME": [...]}
    },
    "zone_transfer": {
        "<domain>": {
            "attempted": bool,
            "successful": bool,
            "nameserver": str,     # Only when successful
            "records": [...]
        }
    },
    "reverse_dns": {}               # Reserved for future use
  }

Rate limiting:
  Brute-force subdomain probing respects ``scan_settings.port_scan_rate``.
  The inter-query delay is set to ``0.5 / rate`` to avoid overloading the
  authoritative server.
"""

import json
import logging
import socket
import time
from typing import Optional

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Focused subdomain wordlist for brute-force discovery
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
    """
    Passive and active DNS enumeration module.

    Discovers subdomains and enumerates DNS records for each target domain
    through a combination of:
      - Passive certificate transparency log query (crt.sh)
      - Active brute-force subdomain resolution
      - Full DNS record type enumeration
      - Zone transfer attempt

    The module is designed to be safe for use against production systems:
    brute-force queries are rate-limited and the zone transfer attempt uses
    the standard AXFR mechanism (which is almost always rejected).

    Attributes:
        name (str): Module identifier ``"dns_enum"``.
        description (str): Human-readable description.
        category (str): Module category ``"dns"``.
    """

    name = "dns_enum"
    description = "Passive and active DNS enumeration with subdomain discovery"
    category = "dns"

    def run(self, targets: dict) -> dict:
        """
        Run DNS enumeration on all target domains.

        For each domain:
          1. Enumerate standard DNS record types
          2. Query crt.sh for CT log subdomains
          3. Brute-force subdomain discovery
          4. Attempt zone transfer
          5. Resolve discovered subdomains

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to enumerate.
                - ``networks`` (list[str]): Ignored by this module.

        Returns:
            dict with keys ``subdomains``, ``records``, ``zone_transfer``,
            and ``reverse_dns``.  See module docstring for the full schema.
        """
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

            # Merge all subdomains, deduplicate, and sort
            all_subs = sorted(set(ct_subs + brute_subs))
            results["subdomains"].extend(all_subs)

            # 5. Resolve and get details for each subdomain
            for sub in all_subs:
                sub_records = self._resolve_subdomain(sub, timeout)
                if sub_records:
                    results["records"][sub] = sub_records

        # Final deduplication across all domains
        results["subdomains"] = sorted(set(results["subdomains"]))
        return results

    def _enumerate_records(self, domain: str, timeout: int) -> dict:
        """
        Query all standard DNS record types for a domain.

        Queries A, AAAA, MX, NS, TXT, CNAME, and SOA record types using
        dnspython.  Missing/non-existent record types are silently skipped.

        Args:
            domain: Fully-qualified domain name to query.
            timeout: DNS resolver timeout and lifetime in seconds.

        Returns:
            dict mapping record type string to a list of string values::

                {
                    "A": ["93.184.216.34"],
                    "MX": ["0 aspmx.l.google.com."],
                    "TXT": ["v=spf1 -all"],
                    ...
                }

        Raises:
            No exceptions propagate; individual record type failures are
            logged at DEBUG level.
        """
        records: dict = {}
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
                pass  # Record type simply doesn't exist — not an error
            except Exception as e:
                self.logger.debug(f"DNS query {rtype} for {domain}: {e}")

        return records

    def _crtsh_subdomains(self, domain: str) -> list:
        """
        Query Certificate Transparency logs via crt.sh for subdomain discovery.

        crt.sh aggregates certificate data from multiple CT logs.  Querying
        for ``%.domain`` returns all certificates that include the domain as
        a Subject Alternative Name (SAN), which often reveals subdomains that
        have never been publicly advertised.

        This is a passive technique — it generates no DNS traffic.

        Args:
            domain: Apex domain to search (e.g. ``"example.com"``).

        Returns:
            Sorted list of unique subdomain strings discovered in CT logs.
            Returns an empty list on API failure.

        Raises:
            No exceptions propagate; failures are logged as warnings.

        Example::

            >>> module._crtsh_subdomains("example.com")
            ['api.example.com', 'mail.example.com', 'www.example.com']
        """
        subdomains: set = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Handle wildcard entries ("*.example.com") and multi-value
                    # entries (newline-separated when multiple SANs in one cert)
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
        """
        Discover subdomains by resolving common prefixes from ``SUBDOMAIN_WORDLIST``.

        Each word in the wordlist is prefixed to the domain and resolved via
        an A record query.  Positive resolutions are collected.  A short
        delay between queries reduces the risk of rate limiting by the
        authoritative nameserver.

        Args:
            domain: Apex domain to brute-force (e.g. ``"example.com"``).
            timeout: DNS resolver timeout and lifetime in seconds (per query
                the per-query timeout is hard-coded to 3 seconds).

        Returns:
            List of successfully resolved subdomain strings.

        Raises:
            No exceptions propagate; individual query failures are silently
            ignored (NXDOMAIN is the expected negative result).
        """
        found: list = []
        resolver = dns.resolver.Resolver()
        # Use shorter per-query timeout for brute-force to keep it fast
        resolver.timeout = 3
        resolver.lifetime = 3
        rate = self.scan_settings.get("port_scan_rate", 10)
        # Use half the rate for subdomain brute-force to be less aggressive
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
                pass  # Expected — subdomain doesn't exist
            except Exception:
                pass
            time.sleep(delay * 0.5)  # Slow down to avoid rate limiting

        return found

    def _try_zone_transfer(self, domain: str, timeout: int) -> dict:
        """
        Attempt a DNS zone transfer (AXFR) against each authoritative nameserver.

        Zone transfers are almost universally blocked on public-facing DNS
        servers, but their success constitutes a critical finding.  This
        method attempts AXFR against every NS record for the domain.

        Args:
            domain: Domain to attempt zone transfer for.
            timeout: DNS query/transfer timeout in seconds.

        Returns:
            dict with keys:
                - ``attempted`` (bool): Always ``True``.
                - ``successful`` (bool): ``True`` if AXFR succeeded.
                - ``nameserver`` (str): NS that allowed transfer (if any).
                - ``records`` (list): List of ``{"name": str, "ttl": str}``
                  dicts from the zone (if successful).

        Raises:
            No exceptions propagate; all errors are silently caught.
        """
        result: dict = {"attempted": True, "successful": False, "records": []}
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_host = str(ns).rstrip(".")
                try:
                    # AXFR returns a generator; from_xfr materializes it
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
                    break  # Stop at first successful transfer
                except Exception:
                    pass  # AXFR refused/failed — expected
        except Exception:
            pass
        return result

    def _resolve_subdomain(self, subdomain: str, timeout: int) -> dict:
        """
        Resolve a subdomain to its IP and CNAME records.

        Queries A, AAAA, and CNAME record types for the given subdomain.
        Used to enrich the results for all discovered subdomains.

        Args:
            subdomain: Fully-qualified subdomain to resolve.
            timeout: DNS resolver timeout/lifetime in seconds (per-query
                timeout is hard-coded to 3 seconds for performance).

        Returns:
            dict mapping record type to list of string values.
            Returns an empty dict if the subdomain resolves to nothing.

        Example::

            >>> module._resolve_subdomain("www.example.com", 10)
            {"A": ["93.184.216.34"]}
        """
        records: dict = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        for rtype in ["A", "AAAA", "CNAME"]:
            try:
                answers = resolver.resolve(subdomain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except Exception:
                pass  # Record type missing — not an error

        return records
