"""
Recon modules for Perimtr.

Each module is a self-contained reconnaissance capability that can be
enabled/disabled independently. The plugin architecture allows new
modules to be added by simply creating a new file that inherits from
ReconModule.
"""

from perimtr.modules.port_scanner import PortScanner
from perimtr.modules.dns_enum import DNSEnum
from perimtr.modules.http_headers import HTTPHeaders
from perimtr.modules.whois_cert import WhoisCert
from perimtr.modules.vuln_check import VulnCheck
from perimtr.modules.domain_security import DomainSecurity

# Module registry — add new modules here
MODULES = [
    PortScanner,
    DNSEnum,
    HTTPHeaders,
    WhoisCert,
    VulnCheck,
    DomainSecurity,
]

__all__ = ["MODULES", "PortScanner", "DNSEnum", "HTTPHeaders", "WhoisCert", "VulnCheck", "DomainSecurity"]
