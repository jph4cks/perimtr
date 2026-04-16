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
"""

import logging
import time
from typing import Any

import dns.resolver
import dns.rdatatype

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")

# Common DKIM selectors to check
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "dkim", "mail", "s1", "s2", "sig1", "smtp", "mandrill", "mxvault",
    "everlytickey1", "everlytickey2", "mailjet", "protonmail",
    "protonmail2", "protonmail3", "sendgrid", "zendesk1", "zendesk2",
    "cm", "mailchimp", "amazonses", "ses", "hubspot", "hs1", "hs2",
]


class DomainSecurity(ReconModule):
    """Checks domain email security and DNS security configurations."""

    name = "domain_security"
    description = "SPF, DKIM, DMARC, DNSSEC, and CAA validation"
    category = "domain"

    def run(self, targets: dict) -> dict:
        """Run domain security checks."""
        results = {"results": {}}
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

            # Analyze and flag issues
            self._analyze_issues(domain, domain_result)
            results["results"][domain] = domain_result

        return results

    def _check_spf(self, domain: str, timeout: int) -> dict:
        """Check SPF record configuration."""
        result = {"exists": False, "record": None, "issues": []}
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

                    # Analyze SPF record
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

                    # Check for too many DNS lookups (max 10)
                    lookup_count = txt.count("include:") + txt.count("a:") + txt.count("mx:")
                    lookup_count += txt.count("redirect=") + txt.count("exists:")
                    if lookup_count > 10:
                        result["issues"].append({
                            "issue": "spf_too_many_lookups",
                            "severity": "medium",
                            "detail": f"SPF record requires {lookup_count} DNS lookups (max 10)",
                            "recommendation": "Flatten SPF record to reduce DNS lookup count below 10",
                        })

                    break

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
        """Check DMARC policy configuration."""
        result = {"exists": False, "record": None, "policy": None, "issues": []}
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

                    # Parse policy
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

                    # Analyze policy
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

                    pct = result.get("pct", "100")
                    if pct != "100":
                        result["issues"].append({
                            "issue": "dmarc_low_pct",
                            "severity": "medium",
                            "detail": f"DMARC only applies to {pct}% of messages",
                            "recommendation": "Set pct=100 for full coverage",
                        })

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
        """Check for DKIM records using common selectors."""
        result = {"found_selectors": [], "issues": []}
        resolver = dns.resolver.Resolver()
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
                    if "v=DKIM1" in txt or "k=" in txt:
                        result["found_selectors"].append({
                            "selector": selector,
                            "record": txt[:200],
                        })
                        break
            except Exception:
                pass
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
        """Check if DNSSEC is enabled for the domain."""
        result = {"enabled": False, "issues": []}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            # Check for DNSKEY records
            try:
                answers = resolver.resolve(domain, "DNSKEY")
                if answers:
                    result["enabled"] = True
                    result["keys"] = len(list(answers))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

            # Check for DS records at parent
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
        """Check CAA (Certificate Authority Authorization) records."""
        result = {"exists": False, "records": [], "issues": []}
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
        """Check MX record security."""
        result = {"records": [], "issues": []}
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

                # Check if MX supports STARTTLS
                try:
                    import smtplib
                    smtp = smtplib.SMTP(mx_host, 25, timeout=10)
                    smtp.ehlo()
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
                    pass

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_issues(self, domain: str, domain_result: dict):
        """Aggregate all issues from sub-checks into the main issues list."""
        all_issues = domain_result["issues"]

        for check_name in ["spf", "dmarc", "dkim", "dnssec", "caa", "mx_security"]:
            check_data = domain_result.get(check_name, {})
            for issue in check_data.get("issues", []):
                issue["domain"] = domain
                issue["check"] = check_name
                all_issues.append(issue)
