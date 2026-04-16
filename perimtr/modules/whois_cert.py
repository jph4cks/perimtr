"""
WHOIS & Certificate Intelligence Module.

Gathers registration and certificate data for domains:
  - WHOIS registration details (registrar, dates, nameservers)
  - SSL/TLS certificate analysis (expiry, issuer, SANs, key strength)
  - Certificate Transparency monitoring
"""

import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Any

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")


class WhoisCert(ReconModule):
    """Gathers WHOIS and certificate intelligence for domains."""

    name = "whois_cert"
    description = "WHOIS registration and SSL/TLS certificate analysis"
    category = "cert"

    def run(self, targets: dict) -> dict:
        """Run WHOIS and cert checks on target domains."""
        results = {
            "whois": {},
            "certificates": {},
            "ct_entries": {},
            "issues": [],
        }

        domains = targets.get("domains", [])

        for domain in domains:
            self.logger.info(f"Checking WHOIS & certs: {domain}")

            # WHOIS lookup
            whois_data = self._whois_lookup(domain)
            if whois_data:
                results["whois"][domain] = whois_data

            # Certificate analysis
            cert_data = self._analyze_certificate(domain)
            if cert_data:
                results["certificates"][domain] = cert_data

                # Check for cert issues
                self._check_cert_issues(domain, cert_data, results)

            # CT log check for additional subdomains
            ct_data = self._check_ct_logs(domain)
            if ct_data:
                results["ct_entries"][domain] = ct_data

        return results

    def _whois_lookup(self, domain: str) -> dict:
        """Perform WHOIS lookup for a domain."""
        try:
            import whois
            w = whois.whois(domain)

            # Normalize dates
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]

            result = {
                "registrar": w.registrar,
                "creation_date": str(creation) if creation else None,
                "expiration_date": str(expiration) if expiration else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "nameservers": list(set(ns.lower() for ns in (w.name_servers or []) if ns)),
                "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                "registrant_country": getattr(w, "country", None),
                "dnssec": getattr(w, "dnssec", None),
            }

            # Check for expiring domains
            if expiration:
                try:
                    if isinstance(expiration, str):
                        expiration = datetime.fromisoformat(expiration)
                    days_until_expiry = (expiration - datetime.now()).days
                    result["days_until_expiry"] = days_until_expiry
                except (ValueError, TypeError):
                    pass

            return result

        except Exception as e:
            self.logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {"error": str(e)}

    def _analyze_certificate(self, domain: str) -> dict:
        """Analyze SSL/TLS certificate for a domain."""
        try:
            context = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=10)
            ssock = context.wrap_socket(conn, server_hostname=domain)

            cert = ssock.getpeercert()
            cert_bin = ssock.getpeercert(binary_form=True)

            # Parse certificate details
            subject = {}
            for field in cert.get("subject", []):
                for key, value in field:
                    subject[key] = value

            issuer = {}
            for field in cert.get("issuer", []):
                for key, value in field:
                    issuer[key] = value

            san = [entry[1] for entry in cert.get("subjectAltName", [])]

            # Parse dates
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")

            # Calculate days until expiry
            days_until_expiry = None
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry - datetime.now()).days
            except (ValueError, TypeError):
                pass

            # Get key info using cryptography
            key_info = self._get_key_info(cert_bin)

            result = {
                "subject": subject,
                "issuer": issuer,
                "san": san,
                "valid_from": not_before,
                "expiry": not_after,
                "days_until_expiry": days_until_expiry,
                "serial_number": cert.get("serialNumber"),
                "version": cert.get("version"),
                "protocol": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                "key_info": key_info,
            }

            ssock.close()
            conn.close()
            return result

        except ssl.SSLCertVerificationError as e:
            return {
                "error": "certificate_verification_failed",
                "detail": str(e)[:300],
                "self_signed": "self-signed" in str(e).lower() or "self signed" in str(e).lower(),
            }
        except Exception as e:
            self.logger.warning(f"Certificate analysis failed for {domain}: {e}")
            return {"error": str(e)[:200]}

    def _get_key_info(self, cert_der: bytes) -> dict:
        """Extract key algorithm and size from certificate."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

            cert = x509.load_der_x509_certificate(cert_der)
            pub_key = cert.public_key()

            key_info = {"algorithm": type(pub_key).__name__}

            if isinstance(pub_key, rsa.RSAPublicKey):
                key_info["algorithm"] = "RSA"
                key_info["key_size"] = pub_key.key_size
                if pub_key.key_size < 2048:
                    key_info["weak"] = True
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                key_info["algorithm"] = "ECDSA"
                key_info["curve"] = pub_key.curve.name
                key_info["key_size"] = pub_key.key_size
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                key_info["algorithm"] = "Ed25519"

            # Signature algorithm
            key_info["signature_algorithm"] = cert.signature_algorithm_oid._name

            return key_info

        except Exception as e:
            return {"error": str(e)[:100]}

    def _check_cert_issues(self, domain: str, cert_data: dict, results: dict):
        """Check for certificate-related security issues."""
        issues = results["issues"]

        # Self-signed certificate
        if cert_data.get("self_signed"):
            issues.append({
                "domain": domain,
                "issue": "self_signed_certificate",
                "severity": "critical",
                "detail": "Certificate is self-signed and will not be trusted by browsers",
                "recommendation": "Obtain a certificate from a trusted CA (e.g., Let's Encrypt)",
            })

        # Certificate verification failure
        if cert_data.get("error") == "certificate_verification_failed":
            issues.append({
                "domain": domain,
                "issue": "cert_verification_failed",
                "severity": "critical",
                "detail": cert_data.get("detail", "Certificate verification failed"),
                "recommendation": "Fix certificate chain — ensure intermediate certs are served",
            })

        # Expiring soon (within 30 days)
        days = cert_data.get("days_until_expiry")
        if days is not None:
            if days < 0:
                issues.append({
                    "domain": domain,
                    "issue": "cert_expired",
                    "severity": "critical",
                    "detail": f"Certificate expired {abs(days)} days ago",
                    "recommendation": "Renew the SSL/TLS certificate immediately",
                })
            elif days < 30:
                issues.append({
                    "domain": domain,
                    "issue": "cert_expiring_soon",
                    "severity": "high",
                    "detail": f"Certificate expires in {days} days",
                    "recommendation": "Renew the SSL/TLS certificate before expiry",
                })

        # Weak key
        key_info = cert_data.get("key_info", {})
        if key_info.get("weak"):
            issues.append({
                "domain": domain,
                "issue": "weak_cert_key",
                "severity": "high",
                "detail": f"Certificate uses weak {key_info.get('algorithm')} key ({key_info.get('key_size')} bits)",
                "recommendation": "Use at least RSA 2048-bit or ECDSA P-256 keys",
            })

        # Old TLS protocol
        protocol = cert_data.get("protocol", "")
        if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            issues.append({
                "domain": domain,
                "issue": "deprecated_tls",
                "severity": "high",
                "detail": f"Server supports deprecated protocol: {protocol}",
                "recommendation": "Disable TLS 1.0, TLS 1.1, and all SSL versions; use TLS 1.2+ only",
            })

    def _check_ct_logs(self, domain: str) -> dict:
        """Check Certificate Transparency logs for the domain."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                entries = resp.json()
                # Summarize
                issuers = set()
                names = set()
                for entry in entries:
                    issuer = entry.get("issuer_name", "")
                    if issuer:
                        # Extract CN from issuer
                        for part in issuer.split(","):
                            if "CN=" in part:
                                issuers.add(part.split("CN=")[1].strip())
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub:
                            names.add(sub.lower())

                return {
                    "total_certificates": len(entries),
                    "unique_subdomains": sorted(names),
                    "issuers": sorted(issuers),
                }
        except Exception as e:
            self.logger.warning(f"CT log check failed for {domain}: {e}")
            return {"error": str(e)}
