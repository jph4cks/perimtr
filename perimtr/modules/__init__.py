"""
Recon modules for Perimtr.

Each module is a self-contained reconnaissance capability that can be
enabled/disabled independently. The plugin architecture allows new
modules to be added by simply creating a new file that inherits from
ReconModule.

Module registry:
  - PortScanner    — network port scanning
  - DNSEnum        — DNS enumeration and subdomain discovery
  - HTTPHeaders    — HTTP security header analysis
  - WhoisCert      — WHOIS and SSL/TLS certificate intelligence
  - VulnCheck      — basic vulnerability checks for exposed services
  - DomainSecurity — SPF, DKIM, DMARC, DNSSEC, and CAA validation
  - WebTechFingerprint — web technology and CMS detection
  - SSLAudit       — deep SSL/TLS protocol and cipher analysis
"""

from perimtr.modules.port_scanner import PortScanner
from perimtr.modules.dns_enum import DNSEnum
from perimtr.modules.http_headers import HTTPHeaders
from perimtr.modules.whois_cert import WhoisCert
from perimtr.modules.vuln_check import VulnCheck
from perimtr.modules.domain_security import DomainSecurity
from perimtr.modules.web_tech import WebTechFingerprint
from perimtr.modules.ssl_audit import SSLAudit

# Module registry — add new modules here to make them available to the engine.
# The engine instantiates all enabled modules from this list.
MODULES = [
    PortScanner,
    DNSEnum,
    HTTPHeaders,
    WhoisCert,
    VulnCheck,
    DomainSecurity,
    WebTechFingerprint,
    SSLAudit,
]

__all__ = [
    "MODULES",
    "PortScanner",
    "DNSEnum",
    "HTTPHeaders",
    "WhoisCert",
    "VulnCheck",
    "DomainSecurity",
    "WebTechFingerprint",
    "SSLAudit",
]
