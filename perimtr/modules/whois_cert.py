"""
WHOIS & Certificate Intelligence Module.

Gathers registration and certificate data for domains:
  - WHOIS registration details (registrar, dates, nameservers)
  - SSL/TLS certificate analysis (expiry, issuer, SANs, key strength)
  - Certificate Transparency monitoring

How it works:
  For each domain in ``targets["domains"]``:
    1. A WHOIS lookup is performed using the ``python-whois`` library,
       normalizing dates and extracting registration metadata.
    2. The SSL/TLS certificate on port 443 is inspected for:
       - Subject and issuer fields
       - Subject Alternative Names (SANs)
       - Expiry date and days-until-expiry
       - Key algorithm and strength (via ``cryptography`` library)
       - Negotiated protocol version and cipher suite
    3. The crt.sh API is queried to enumerate CT log entries for the domain,
       providing a list of unique subdomains and historical issuers.
    4. Certificate issues (expiry, self-signed, weak key, deprecated protocol)
       are flagged in ``results["issues"]``.

Data produced:
  {
    "whois": {
        "<domain>": {
            "registrar": str,
            "creation_date": str,
            "expiration_date": str,
            "updated_date": str,
            "nameservers": [str],
            "status": [str],
            "registrant_country": str | None,
            "dnssec": str | None,
            "days_until_expiry": int | None
        }
    },
    "certificates": {
        "<domain>": {
            "subject": {str: str},
            "issuer": {str: str},
            "san": [str],
            "valid_from": str,
            "expiry": str,
            "days_until_expiry": int | None,
            "serial_number": str,
            "version": int,
            "protocol": str,
            "cipher": str | None,
            "key_info": {"algorithm": str, "key_size": int, "weak": bool}
        }
    },
    "ct_entries": {
        "<domain>": {
            "total_certificates": int,
            "unique_subdomains": [str],
            "issuers": [str]
        }
    },
    "issues": [
        {
            "domain": str,
            "issue": str,
            "severity": str,
            "detail": str,
            "recommendation": str
        }
    ]
  }
"""

import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

import requests

from perimtr.core.module_base import ReconModule

logger = logging.getLogger("perimtr")


class WhoisCert(ReconModule):
    """
    WHOIS Registration and SSL/TLS Certificate Intelligence Module.

    Collects domain registration metadata via WHOIS and inspects SSL/TLS
    certificates for security issues.  Certificate Transparency log data
    from crt.sh supplements subdomain discovery performed by ``dns_enum``.

    Attributes:
        name (str): Module identifier ``"whois_cert"``.
        description (str): Human-readable description.
        category (str): Module category ``"cert"``.
    """

    name = "whois_cert"
    description = "WHOIS registration and SSL/TLS certificate analysis"
    category = "cert"

    def run(self, targets: dict) -> dict:
        """
        Run WHOIS and certificate checks on all target domains.

        Args:
            targets: dict with keys:
                - ``domains`` (list[str]): FQDNs to investigate.
                - ``networks`` (list[str]): Ignored by this module.

        Returns:
            dict with keys ``whois``, ``certificates``, ``ct_entries``,
            and ``issues``.  See module-level docstring for the full schema.
        """
        results: dict = {
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
                # Flag certificate security issues
                self._check_cert_issues(domain, cert_data, results)

            # CT log entry check for additional subdomain coverage
            ct_data = self._check_ct_logs(domain)
            if ct_data:
                results["ct_entries"][domain] = ct_data

        return results

    def _whois_lookup(self, domain: str) -> dict:
        """
        Perform a WHOIS lookup for a domain using python-whois.

        Normalizes date fields (which may be returned as lists by some TLDs)
        and computes ``days_until_expiry`` from the expiration date.

        Args:
            domain: Domain name to query (e.g. ``"example.com"``).

        Returns:
            dict with registration metadata fields, or a dict containing
            only ``{"error": str}`` if the lookup fails.

        Raises:
            No exceptions propagate; failures are logged as warnings.

        Example::

            {
                "registrar": "MarkMonitor Inc.",
                "creation_date": "1995-08-14 04:00:00",
                "expiration_date": "2025-08-13 04:00:00",
                "nameservers": ["ns1.example.com", "ns2.example.com"],
                "days_until_expiry": 180
            }
        """
        try:
            import whois
            w = whois.whois(domain)

            # Normalize dates — some TLDs return a list when there are multiple
            # registration events; take the earliest/only value.
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]

            result: dict = {
                "registrar": w.registrar,
                "creation_date": str(creation) if creation else None,
                "expiration_date": str(expiration) if expiration else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                # Deduplicate and lowercase nameservers
                "nameservers": list(set(ns.lower() for ns in (w.name_servers or []) if ns)),
                "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                "registrant_country": getattr(w, "country", None),
                "dnssec": getattr(w, "dnssec", None),
            }

            # Compute days until domain registration expires
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
        """
        Inspect the live SSL/TLS certificate served by a domain on port 443.

        Opens a TLS socket connection, retrieves the certificate in both
        parsed and DER form, and extracts:
          - Subject and issuer distinguished names
          - Subject Alternative Names (SANs)
          - Validity window
          - Days until certificate expires
          - Public key algorithm and size (via ``cryptography`` library)
          - Negotiated TLS version and cipher suite

        Args:
            domain: Domain name to connect to on port 443.

        Returns:
            dict with certificate metadata, or a dict with error information
            if the certificate is self-signed, verification fails, or
            the connection cannot be established.

        Raises:
            No exceptions propagate; errors are returned in the result dict.
        """
        try:
            context = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=10)
            ssock = context.wrap_socket(conn, server_hostname=domain)

            cert = ssock.getpeercert()
            cert_bin = ssock.getpeercert(binary_form=True)

            # Flatten the RFC 2459 RDN structure into a simple dict
            subject: dict = {}
            for field in cert.get("subject", []):
                for key, value in field:
                    subject[key] = value

            issuer: dict = {}
            for field in cert.get("issuer", []):
                for key, value in field:
                    issuer[key] = value

            # SAN entries are tuples of (type, value) e.g. ("DNS", "example.com")
            san: list = [entry[1] for entry in cert.get("subjectAltName", [])]

            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")

            # Compute remaining validity days
            days_until_expiry: Optional[int] = None
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry - datetime.now()).days
            except (ValueError, TypeError):
                pass

            # Extract key details using the cryptography library
            key_info = self._get_key_info(cert_bin)

            result: dict = {
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
            # Return a partial result so that _check_cert_issues can flag it
            return {
                "error": "certificate_verification_failed",
                "detail": str(e)[:300],
                "self_signed": "self-signed" in str(e).lower() or "self signed" in str(e).lower(),
            }
        except Exception as e:
            self.logger.warning(f"Certificate analysis failed for {domain}: {e}")
            return {"error": str(e)[:200]}

    def _get_key_info(self, cert_der: bytes) -> dict:
        """
        Extract public key algorithm and strength from a DER-encoded certificate.

        Uses the ``cryptography`` library to parse the certificate and inspect
        the public key.  For RSA keys, ``key_size < 2048`` sets ``weak = True``.

        Args:
            cert_der: DER-encoded certificate bytes (from
                ``SSLSocket.getpeercert(binary_form=True)``).

        Returns:
            dict with keys:
                - ``algorithm`` (str): ``"RSA"``, ``"ECDSA"``, ``"Ed25519"``, etc.
                - ``key_size`` (int): Key bit length (RSA/ECDSA).
                - ``curve`` (str): Curve name for ECDSA keys.
                - ``weak`` (bool): ``True`` if RSA < 2048 bits.
                - ``signature_algorithm`` (str): Signature hash algorithm OID name.

        Raises:
            No exceptions propagate; errors are returned as ``{"error": str}``.
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

            cert = x509.load_der_x509_certificate(cert_der)
            pub_key = cert.public_key()

            key_info: dict = {"algorithm": type(pub_key).__name__}

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

            # Signature algorithm is stored as an OID; the _name attribute is
            # a human-readable representation provided by the cryptography library.
            key_info["signature_algorithm"] = cert.signature_algorithm_oid._name

            return key_info

        except Exception as e:
            return {"error": str(e)[:100]}

    def _check_cert_issues(
        self, domain: str, cert_data: dict, results: dict
    ) -> None:
        """
        Evaluate certificate data for security issues and append them to results.

        Checks for:
          - Self-signed certificate
          - Certificate verification failure (chain issues)
          - Expired certificate (days_until_expiry < 0)
          - Certificate expiring within 30 days
          - Weak public key (RSA < 2048 bits)
          - Deprecated TLS protocol (TLS 1.0, TLS 1.1, SSLv3)

        Args:
            domain: Domain associated with the certificate.
            cert_data: Certificate analysis result dict from
                ``_analyze_certificate``.
            results: Top-level results dict; issues are appended to
                ``results["issues"]``.

        Returns:
            None.  Mutates ``results["issues"]`` in-place.
        """
        issues = results["issues"]

        # Self-signed certificate — browsers will display an error
        if cert_data.get("self_signed"):
            issues.append({
                "domain": domain,
                "issue": "self_signed_certificate",
                "severity": "critical",
                "detail": "Certificate is self-signed and will not be trusted by browsers",
                "recommendation": "Obtain a certificate from a trusted CA (e.g., Let's Encrypt)",
            })

        # Certificate verification failure (e.g., incomplete chain)
        if cert_data.get("error") == "certificate_verification_failed":
            issues.append({
                "domain": domain,
                "issue": "cert_verification_failed",
                "severity": "critical",
                "detail": cert_data.get("detail", "Certificate verification failed"),
                "recommendation": "Fix certificate chain — ensure intermediate certs are served",
            })

        # Certificate expiry checks (within 30 days = high, already expired = critical)
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

        # Weak RSA key — less than 2048 bits is no longer considered secure
        key_info = cert_data.get("key_info", {})
        if key_info.get("weak"):
            issues.append({
                "domain": domain,
                "issue": "weak_cert_key",
                "severity": "high",
                "detail": (
                    f"Certificate uses weak {key_info.get('algorithm')} key "
                    f"({key_info.get('key_size')} bits)"
                ),
                "recommendation": "Use at least RSA 2048-bit or ECDSA P-256 keys",
            })

        # Deprecated protocol — TLS 1.0, TLS 1.1, SSLv3, SSLv2 are all obsolete
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
        """
        Query Certificate Transparency logs via crt.sh for historical certificate data.

        Retrieves all certificates issued for the domain from CT logs and
        summarizes unique subdomains and issuing CAs.  Useful for identifying
        unauthorized certificate issuance and discovering hidden subdomains.

        Args:
            domain: Apex domain to query (e.g. ``"example.com"``).

        Returns:
            dict with keys:
                - ``total_certificates`` (int): Number of CT log entries.
                - ``unique_subdomains`` (list[str]): All unique names in SANs.
                - ``issuers`` (list[str]): Distinct CA Common Names.

            Returns ``{"error": str}`` on API failure.

        Raises:
            No exceptions propagate; failures are logged as warnings.
        """
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                entries = resp.json()
                issuers: set = set()
                names: set = set()

                for entry in entries:
                    # Extract CA Common Name from X.509 issuer string
                    issuer = entry.get("issuer_name", "")
                    if issuer:
                        for part in issuer.split(","):
                            if "CN=" in part:
                                issuers.add(part.split("CN=")[1].strip())

                    # Collect all subdomain names (newline-separated SANs)
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
