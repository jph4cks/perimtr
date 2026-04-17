"""
Domain Security Module.

Checks email and DNS security configurations:
  - SPF record validation
  - DKIM selector discovery
  - DMARC policy analysis
  - DNSSEC validation
  - CAA record checking
  - MX security analysis
  - Email spoofing susceptibility

How it works:
  For each domain in ``targets["domains"]``:
    1. The TXT records are queried for a ``v=spf1`` record.  The record is
       analyzed for dangerous qualifiers (+all, ~all) and excessive DNS
       lookup counts (SPF spec limits to 10).
    2. The ``_dmarc.<domain>`` TXT record is queried.  Policy strength
       (none/quarantine/reject), percentage coverage (pct=), and aggregate
       reporting (rua=) are evaluated.
    3. A list of common DKIM selectors (``DKIM_SELECTORS``) is resolved as
       TXT records at ``<selector>._domainkey.<domain>``.
    4. DNSKEY and DS records are checked to determine DNSSEC status.
    5. CAA records are queried to see if certificate issuance is restricted.
    6. MX records are enumerated and each mail server is tested for STARTTLS
       support.
    7. All per-check issues are aggregated into the top-level ``issues`` list.

Data produced:
  {
    "results": {
        "<domain>": {
            "spf": {
                "exists": bool,
                "record": str | None,
                "issues": [...]
            },
            "dmarc": {
                "exists": bool,
                "record": str | None,
                "policy": str | None,
                "report_uri": str,
                "pct": str,
                "subdomain_policy": str,
                "issues": [...]
            },
            "dkim": {
                "found_selectors": [{"selector": str, "record": str}],
                "issues": [...]
            },
            "dnssec": {
                "enabled": bool,
                "keys": int,
                "ds_records": int,
                "issues": [...]
            },
            "caa": {
                "exists": bool,
                "records": [str],
                "issues": [...]
            },
            "mx_security": {
                "records": [{"priority": int, "host": str}],
                "issues": [...]
            },
            "issues": [
                {
                    "issue": str,
                    "severity": str,
                    "detail": str,
                    "recommendation": str,
                    "domain": str,
                    "check": str
                }
            ]
        }
    }
  }
"""

import logging
import time
from typing import Optional

import dns.resolver
import dns.rdatatype

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Common DKIM selectors to check — ordered from most to least common.
# Mail providers typically use a well-known selector name.
DKIM_SELECTORS: list[str] = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "dkim", "mail", "s1", "s2", "sig1", "smtp", "mandrill", "mxvault",
    "everlytickey1", "everlytickey2", "mailjet", "protonmail",
    "protonmail2", "protonmail3", "sendgrid", "zendesk1", "zendesk2",
    "cm", "mailchimp", "amazonses", "ses", "hubspot", "hs1", "hs2",
]


class DomainSecurity(ReconModule):
    """
    Email and DNS Security Configuration Checker.

    Evaluates each target domain's SPF, DKIM, DMARC, DNSSEC, CAA, and MX
    configuration for security weaknesses.  Results include per-check issue
    lists that are also aggregated into a flat top-level ``issues`` list with
    check context.

    Attributes:
        name (str): Module identifier ``"domain_security"``.
        description (str): Human-readable description.
        category (str): Module category ``"domain"``.
    """

    name = "domain_security"
    description = "SPF, DKIM, DMARC, DNSSEC, and CAA validation"
    category = "domain"

    def run(self, targets: dict) -> dict:
        """
        Run domain security checks for all target domains.

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to check.
                - ``networks`` (list[str]): Ignored by this module.

        Returns:
            dict with a single key ``results`` containing per-domain
            assessment dicts.  See module-level docstring for the schema.
        """
        results: dict = {"results": {}}
        domains = targets.get("domains", [])
        timeout = self.scan_settings.get("dns_timeout", 10)

        for domain in domains:
            self.logger.info(f"Checking domain security: {domain}")
            domain_result = {
                "spf": self._check_spf(domain, timeout),
                "dmarc": self._check_dmarc(domain, timeout),
                "dkim": self._check_dkim(domain, timeout),
                "dnssec": self._check_dnssec(domain, timeout),
                "caa": self._check_caa(domain, timeout),
                "mx_security": self._check_mx_security(domain, timeout),
                "issues": [],
            }

            # Aggregate all sub-check issues into the top-level list
            self._analyze_issues(domain, domain_result)
            results["results"][domain] = domain_result

        return results

    def _check_spf(self, domain: str, timeout: int) -> dict:
        """
        Check the SPF (Sender Policy Framework) TXT record for a domain.

        Looks for a ``v=spf1`` TXT record and evaluates:
          - Presence of the record at all
          - Whether ``+all`` (any server allowed) is used — critical
          - Whether ``~all`` (soft fail) is used — medium
          - Whether ``?all`` (neutral) is used — high
          - Excessive DNS lookup count (SPF spec: max 10 mechanisms that
            require DNS lookups)

        Args:
            domain: Domain to query for the SPF TXT record.
            timeout: DNS resolver timeout and lifetime in seconds.

        Returns:
            dict with keys ``exists``, ``record``, and ``issues``.
        """
        result: dict = {"exists": False, "record": None, "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["exists"] = True
                    result["record"] = txt

                    # Flag dangerous qualifiers
                    if "+all" in txt:
                        result["issues"].append({
                            "issue": "spf_plus_all",
                            "severity": "critical",
                            "detail": "SPF record uses '+all' — allows any server to send email",
                            "recommendation": "Change '+all' to '-all' to reject unauthorized senders",
                        })
                    elif "~all" in txt:
                        result["issues"].append({
                            "issue": "spf_softfail",
                            "severity": "medium",
                            "detail": "SPF record uses '~all' (soft fail) — unauthorized emails may still be delivered",
                            "recommendation": "Change '~all' to '-all' for strict SPF enforcement",
                        })
                    elif "?all" in txt:
                        result["issues"].append({
                            "issue": "spf_neutral",
                            "severity": "high",
                            "detail": "SPF record uses '?all' (neutral) — provides no real protection",
                            "recommendation": "Change '?all' to '-all' for strict SPF enforcement",
                        })

                    # Count mechanisms that require additional DNS lookups.
                    # RFC 7208 §4.6.4 limits SPF to 10 DNS-querying mechanisms.
                    lookup_count = txt.count("include:") + txt.count("a:") + txt.count("mx:")
                    lookup_count += txt.count("redirect=") + txt.count("exists:")
                    if lookup_count > 10:
                        result["issues"].append({
                            "issue": "spf_too_many_lookups",
                            "severity": "medium",
                            "detail": f"SPF record requires {lookup_count} DNS lookups (max 10)",
                            "recommendation": "Flatten SPF record to reduce DNS lookup count below 10",
                        })

                    break  # Only process the first v=spf1 record

            if not result["exists"]:
                result["issues"].append({
                    "issue": "no_spf",
                    "severity": "high",
                    "detail": "No SPF record found — domain is vulnerable to email spoofing",
                    "recommendation": "Add an SPF TXT record (e.g., 'v=spf1 include:_spf.google.com -all')",
                })

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["issues"].append({
                "issue": "no_spf",
                "severity": "high",
                "detail": "No SPF record found",
                "recommendation": "Add an SPF TXT record to prevent email spoofing",
            })
        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_dmarc(self, domain: str, timeout: int) -> dict:
        """
        Check the DMARC (Domain-based Message Authentication) policy.

        Queries the ``_dmarc.<domain>`` TXT record and parses:
          - Policy (p=none/quarantine/reject)
          - Subdomain policy (sp=)
          - Aggregate reporting URI (rua=)
          - Policy percentage (pct=)

        DMARC issues flagged:
          - Missing DMARC record
          - ``p=none`` policy (monitoring only, no enforcement)
          - ``p=quarantine`` (weaker than reject)
          - ``pct`` less than 100
          - Missing aggregate reporting URI

        Args:
            domain: Apex domain to check.
            timeout: DNS resolver timeout in seconds.

        Returns:
            dict with keys ``exists``, ``record``, ``policy``,
            ``report_uri``, ``pct``, ``subdomain_policy``, and ``issues``.
        """
        result: dict = {"exists": False, "record": None, "policy": None, "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    result["exists"] = True
                    result["record"] = txt

                    # Parse semicolon-separated DMARC tags
                    for part in txt.split(";"):
                        part = part.strip()
                        if part.startswith("p="):
                            result["policy"] = part.split("=")[1].strip()
                        elif part.startswith("rua="):
                            result["report_uri"] = part.split("=", 1)[1].strip()
                        elif part.startswith("pct="):
                            result["pct"] = part.split("=")[1].strip()
                        elif part.startswith("sp="):
                            result["subdomain_policy"] = part.split("=")[1].strip()

                    # Analyze policy strength
                    policy = result.get("policy", "none")
                    if policy == "none":
                        result["issues"].append({
                            "issue": "dmarc_none_policy",
                            "severity": "high",
                            "detail": "DMARC policy is set to 'none' — no enforcement",
                            "recommendation": "Move to 'p=quarantine' or 'p=reject' after monitoring",
                        })
                    elif policy == "quarantine":
                        result["issues"].append({
                            "issue": "dmarc_quarantine",
                            "severity": "low",
                            "detail": "DMARC policy is 'quarantine' — good, but 'reject' is stronger",
                            "recommendation": "Consider upgrading to 'p=reject' for maximum protection",
                        })

                    # Check percentage coverage
                    pct = result.get("pct", "100")
                    if pct != "100":
                        result["issues"].append({
                            "issue": "dmarc_low_pct",
                            "severity": "medium",
                            "detail": f"DMARC only applies to {pct}% of messages",
                            "recommendation": "Set pct=100 for full coverage",
                        })

                    # Reporting is required to gain visibility
                    if not result.get("report_uri"):
                        result["issues"].append({
                            "issue": "dmarc_no_reporting",
                            "severity": "medium",
                            "detail": "DMARC has no aggregate reporting URI (rua=)",
                            "recommendation": "Add 'rua=mailto:dmarc@yourdomain.com' for visibility",
                        })

                    break

            if not result["exists"]:
                result["issues"].append({
                    "issue": "no_dmarc",
                    "severity": "high",
                    "detail": "No DMARC record found — domain is vulnerable to email spoofing",
                    "recommendation": "Add a DMARC TXT record at _dmarc.domain.com",
                })

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["issues"].append({
                "issue": "no_dmarc",
                "severity": "high",
                "detail": "No DMARC record found",
                "recommendation": "Add a DMARC TXT record at _dmarc.domain.com",
            })
        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_dkim(self, domain: str, timeout: int) -> dict:
        """
        Discover DKIM selectors by resolving common ``<selector>._domainkey.<domain>`` TXT records.

        Iterates through ``DKIM_SELECTORS`` and queries each ``selector._domainkey.domain``
        for a TXT record containing ``v=DKIM1`` or ``k=``.  This reveals which
        mail sending services have been configured.

        Args:
            domain: Domain to check for DKIM records.
            timeout: Per-query DNS timeout (3 seconds hardcoded for performance).

        Returns:
            dict with keys ``found_selectors`` (list of matching selectors)
            and ``issues`` (flagged if no selectors are found).
        """
        result: dict = {"found_selectors": [], "issues": []}
        resolver = dns.resolver.Resolver()
        # Short timeout per query to keep brute-force fast
        resolver.timeout = 3
        resolver.lifetime = 3
        rate = self.scan_settings.get("port_scan_rate", 10)
        delay = 1.0 / rate if rate > 0 else 0.1

        for selector in DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    # Valid DKIM record contains v=DKIM1 or at minimum a k= tag
                    if "v=DKIM1" in txt or "k=" in txt:
                        result["found_selectors"].append({
                            "selector": selector,
                            "record": txt[:200],  # Truncate long keys
                        })
                        break
            except Exception:
                pass  # Selector doesn't exist — expected
            time.sleep(delay * 0.3)

        if not result["found_selectors"]:
            result["issues"].append({
                "issue": "no_dkim",
                "severity": "medium",
                "detail": "No DKIM selectors found (checked common selectors)",
                "recommendation": "Configure DKIM signing for outbound email",
            })

        return result

    def _check_dnssec(self, domain: str, timeout: int) -> dict:
        """
        Verify whether DNSSEC is enabled for the domain.

        Checks for DNSKEY records (zone signing keys) and DS records
        (delegation signer records at the parent zone).  Either confirms
        DNSSEC is active.

        DNSSEC protects against DNS cache poisoning (Kaminsky attack) and
        ensures responses have not been tampered with in transit.

        Args:
            domain: Domain to check for DNSSEC.
            timeout: DNS resolver timeout in seconds.

        Returns:
            dict with keys ``enabled`` (bool), optionally ``keys`` (int)
            and ``ds_records`` (int), and ``issues``.
        """
        result: dict = {"enabled": False, "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            # Check for DNSKEY record (zone's own signing keys)
            try:
                answers = resolver.resolve(domain, "DNSKEY")
                if answers:
                    result["enabled"] = True
                    result["keys"] = len(list(answers))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # Check for DS record at parent zone (delegation chain)
            try:
                answers = resolver.resolve(domain, "DS")
                if answers:
                    result["enabled"] = True
                    result["ds_records"] = len(list(answers))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            if not result["enabled"]:
                result["issues"].append({
                    "issue": "no_dnssec",
                    "severity": "medium",
                    "detail": "DNSSEC is not enabled — DNS responses can be spoofed",
                    "recommendation": "Enable DNSSEC to protect against DNS cache poisoning",
                })

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_caa(self, domain: str, timeout: int) -> dict:
        """
        Check for CAA (Certificate Authority Authorization) DNS records.

        CAA records restrict which Certificate Authorities are permitted to
        issue certificates for a domain.  Without CAA records, any trusted CA
        can issue a certificate for the domain, increasing the risk of
        mis-issuance.

        Args:
            domain: Domain to query for CAA records.
            timeout: DNS resolver timeout in seconds.

        Returns:
            dict with keys ``exists`` (bool), ``records`` (list of raw
            record strings), and ``issues``.
        """
        result: dict = {"exists": False, "records": [], "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            answers = resolver.resolve(domain, "CAA")
            result["exists"] = True
            for rdata in answers:
                result["records"].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result["issues"].append({
                "issue": "no_caa",
                "severity": "low",
                "detail": "No CAA records found — any CA can issue certificates for this domain",
                "recommendation": "Add CAA records to restrict which CAs can issue certificates",
            })
        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_mx_security(self, domain: str, timeout: int) -> dict:
        """
        Enumerate MX records and check each mail server for STARTTLS support.

        MX records identify mail servers for the domain.  STARTTLS is the
        standard mechanism for encrypting SMTP connections in transit.  Mail
        servers that do not support STARTTLS transmit email in cleartext.

        Args:
            domain: Domain to query for MX records.
            timeout: DNS resolver timeout in seconds.

        Returns:
            dict with keys ``records`` (list of ``{"priority": int, "host": str}``)
            and ``issues`` (flagged for STARTTLS absence).
        """
        result: dict = {"records": [], "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip(".")
                result["records"].append({
                    "priority": rdata.preference,
                    "host": mx_host,
                })

                # Attempt STARTTLS check against the MX host
                try:
                    import smtplib
                    smtp = smtplib.SMTP(mx_host, 25, timeout=10)
                    smtp.ehlo()
                    # EHLO response features are lowercase by smtplib
                    if "starttls" not in [ext.lower() for ext in smtp.esmtp_features]:
                        result["issues"].append({
                            "issue": "mx_no_starttls",
                            "severity": "medium",
                            "host": mx_host,
                            "detail": f"MX server {mx_host} does not support STARTTLS",
                            "recommendation": "Enable STARTTLS on mail server for encrypted email transit",
                        })
                    smtp.quit()
                except Exception:
                    pass  # SMTP unreachable — not a finding

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # Domain has no MX records — not necessarily an issue
        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_issues(self, domain: str, domain_result: dict) -> None:
        """
        Aggregate per-check issues into the domain's top-level ``issues`` list.

        Copies all ``issues`` entries from each sub-check (spf, dmarc, dkim,
        dnssec, caa, mx_security) to the domain's flat ``issues`` list,
        adding ``domain`` and ``check`` keys for context.

        Args:
            domain: Domain name, added to each aggregated issue.
            domain_result: Domain result dict with per-check sub-results and
                an empty ``issues`` list to populate.

        Returns:
            None.  Mutates ``domain_result["issues"]`` in-place.
        """
        all_issues = domain_result["issues"]

        for check_name in ["spf", "dmarc", "dkim", "dnssec", "caa", "mx_security"]:
            check_data = domain_result.get(check_name, {})
            for issue in check_data.get("issues", []):
                # Enrich with context before appending to the aggregate list
                issue["domain"] = domain
                issue["check"] = check_name
                all_issues.append(issue)
