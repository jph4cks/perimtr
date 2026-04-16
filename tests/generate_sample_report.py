"""Generate a sample report for visual verification."""
import sys
sys.path.insert(0, ".")

from perimtr.core.config import DEFAULT_CONFIG
from perimtr.core.llm_engine import LLMEngine
from perimtr.reports.html_report import HTMLReportGenerator

config = dict(DEFAULT_CONFIG)
config["project_name"] = "Acme Corp Perimeter"

assessment = {
    "_assessment": {"timestamp": "2026-04-16T11:30:00", "version": "1.0.0"},
    "port_scanner": {
        "hosts": {
            "203.0.113.10": {
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "8.9p1", "product": "OpenSSH"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "2.4.52", "product": "Apache"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "", "product": ""},
                    {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy", "version": "", "product": ""},
                ],
                "hostname": "web1.acme.com",
            },
            "203.0.113.11": {
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "8.2p1", "product": "OpenSSH"},
                    {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "8.0.33", "product": "MySQL"},
                    {"port": 5432, "protocol": "tcp", "state": "open", "service": "postgresql", "version": "14.2", "product": "PostgreSQL"},
                ],
                "hostname": "db1.acme.com",
            },
            "203.0.113.12": {
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "1.21.0", "product": "nginx"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "", "product": "nginx"},
                    {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server", "version": "", "product": ""},
                ],
                "hostname": "app1.acme.com",
            },
        },
        "total_hosts_scanned": 256,
        "total_open_ports": 10,
    },
    "dns_enum": {
        "subdomains": [
            "www.acme.com", "api.acme.com", "dev.acme.com", "staging.acme.com",
            "mail.acme.com", "vpn.acme.com", "portal.acme.com", "admin.acme.com",
            "jenkins.acme.com", "grafana.acme.com", "gitlab.acme.com", "k8s.acme.com",
        ],
        "records": {
            "acme.com": {
                "A": ["203.0.113.10"],
                "MX": ["10 mail.acme.com"],
                "NS": ["ns1.acme.com", "ns2.acme.com"],
                "TXT": ["v=spf1 include:_spf.google.com -all"],
                "SOA": ["ns1.acme.com admin.acme.com 2024040101 3600 900 604800 86400"],
            },
            "www.acme.com": {"A": ["203.0.113.10"], "CNAME": ["acme.com"]},
            "api.acme.com": {"A": ["203.0.113.10"]},
        },
        "zone_transfer": {"acme.com": {"attempted": True, "successful": False}},
    },
    "http_headers": {
        "total_issues": 12,
        "results": {
            "acme.com": {
                "url": "https://acme.com",
                "status_code": 200,
                "headers": {},
                "present_headers": [
                    {"header": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains"},
                    {"header": "X-Content-Type-Options", "value": "nosniff"},
                    {"header": "X-XSS-Protection", "value": "1; mode=block"},
                ],
                "missing_headers": [
                    "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy", "X-Frame-Options"
                ],
                "info_leaks": [
                    {"header": "Server", "value": "Apache/2.4.52 (Ubuntu)", "severity": "low", "recommendation": "Remove Server header"},
                    {"header": "X-Powered-By", "value": "Express", "severity": "low", "recommendation": "Remove X-Powered-By"},
                ],
                "cookie_issues": [
                    {"cookie": "session_id", "issues": ["missing Secure flag", "missing SameSite attribute"], "severity": "medium"},
                ],
                "tls_info": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
                "redirect_chain": [{"url": "http://acme.com", "status": 301}],
                "issues": [
                    {"issue": "missing_content_security_policy", "severity": "high", "detail": "Missing Content-Security-Policy: Controls resource loading to prevent XSS", "recommendation": "Define a Content-Security-Policy that restricts script/style sources"},
                    {"issue": "missing_x_frame_options", "severity": "medium", "detail": "Missing X-Frame-Options: Prevents clickjacking attacks", "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"},
                    {"issue": "missing_referrer_policy", "severity": "low", "detail": "Missing Referrer-Policy: Controls referrer information leakage", "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'"},
                    {"issue": "missing_permissions_policy", "severity": "low", "detail": "Missing Permissions-Policy: Controls browser feature access", "recommendation": "Define a Permissions-Policy restricting unnecessary APIs"},
                ],
            },
        },
    },
    "whois_cert": {
        "certificates": {
            "acme.com": {
                "subject": {"commonName": "acme.com"},
                "issuer": {"organizationName": "Let's Encrypt", "commonName": "R3"},
                "san": ["acme.com", "www.acme.com", "api.acme.com"],
                "valid_from": "Jan 15 00:00:00 2026 GMT",
                "expiry": "Apr 15 23:59:59 2026 GMT",
                "days_until_expiry": -1,
                "serial_number": "03A6B5CF2E",
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "key_info": {"algorithm": "RSA", "key_size": 2048, "signature_algorithm": "sha256WithRSAEncryption"},
            },
        },
        "whois": {
            "acme.com": {
                "registrar": "Namecheap Inc.",
                "creation_date": "2018-03-15",
                "expiration_date": "2027-03-15",
                "nameservers": ["ns1.acme.com", "ns2.acme.com"],
                "status": ["clientTransferProhibited"],
                "dnssec": "unsigned",
                "days_until_expiry": 333,
            },
        },
        "ct_entries": {
            "acme.com": {"total_certificates": 47, "unique_subdomains": ["acme.com", "www.acme.com", "api.acme.com", "dev.acme.com"], "issuers": ["Let's Encrypt", "R3"]},
        },
        "issues": [
            {"domain": "acme.com", "issue": "cert_expired", "severity": "critical", "detail": "Certificate expired 1 days ago", "recommendation": "Renew the SSL/TLS certificate immediately"},
        ],
    },
    "vuln_check": {
        "findings": [
            {"id": "MYSQL-EXPOSED", "name": "MySQL Exposed to Internet", "severity": "critical", "detail": "MySQL exposed on port 3306 — high-risk service", "recommendation": "Restrict database access to application servers only; use firewall rules", "host": "203.0.113.11", "domain": "db1.acme.com", "port": 3306, "banner": "MySQL 8.0.33"},
            {"id": "PGSQL-EXPOSED", "name": "PostgreSQL Exposed to Internet", "severity": "critical", "detail": "PostgreSQL exposed on port 5432 — high-risk service", "recommendation": "Restrict database access to application servers only; use firewall rules", "host": "203.0.113.11", "domain": "db1.acme.com", "port": 5432, "banner": ""},
            {"id": "RDP-EXPOSED", "name": "RDP Exposed to Internet", "severity": "critical", "detail": "RDP is exposed on port 3389 — high-risk service", "recommendation": "Place RDP behind VPN; never expose directly to the internet", "host": "203.0.113.12", "domain": "app1.acme.com", "port": 3389, "banner": ""},
            {"id": "HTTP-CLEARTEXT", "name": "HTTP Without TLS", "severity": "medium", "detail": "HTTP does not redirect to HTTPS", "recommendation": "Redirect all HTTP traffic to HTTPS", "host": "203.0.113.12", "domain": "app1.acme.com", "port": 80, "banner": ""},
            {"id": "SSH-WEAK-ALGO", "name": "SSH Weak Algorithms", "severity": "medium", "detail": "Outdated SSH version detected: SSH-2.0-OpenSSH_8.2p1", "recommendation": "Update SSH server and disable weak ciphers/key exchange algorithms", "host": "203.0.113.11", "domain": "db1.acme.com", "port": 22, "banner": "SSH-2.0-OpenSSH_8.2p1"},
        ],
        "banners": {"203.0.113.11:3306": "MySQL 8.0.33", "203.0.113.11:22": "SSH-2.0-OpenSSH_8.2p1"},
        "summary": {"total_findings": 5, "severity_counts": {"critical": 3, "high": 0, "medium": 2, "low": 0, "info": 0}},
    },
    "domain_security": {
        "results": {
            "acme.com": {
                "spf": {"exists": True, "record": "v=spf1 include:_spf.google.com -all", "issues": []},
                "dmarc": {"exists": True, "policy": "none", "record": "v=DMARC1; p=none; rua=mailto:dmarc@acme.com", "report_uri": "mailto:dmarc@acme.com", "issues": [
                    {"issue": "dmarc_none_policy", "severity": "high", "detail": "DMARC policy is set to 'none' — no enforcement", "recommendation": "Move to 'p=quarantine' or 'p=reject' after monitoring"},
                ]},
                "dkim": {"found_selectors": [{"selector": "google", "record": "v=DKIM1; k=rsa; p=MIGf..."}], "issues": []},
                "dnssec": {"enabled": False, "issues": [
                    {"issue": "no_dnssec", "severity": "medium", "detail": "DNSSEC is not enabled — DNS responses can be spoofed", "recommendation": "Enable DNSSEC to protect against DNS cache poisoning"},
                ]},
                "caa": {"exists": False, "records": [], "issues": [
                    {"issue": "no_caa", "severity": "low", "detail": "No CAA records found — any CA can issue certificates for this domain", "recommendation": "Add CAA records to restrict which CAs can issue certificates"},
                ]},
                "mx_security": {"records": [{"priority": 10, "host": "mail.acme.com"}], "issues": []},
                "issues": [],
            },
        },
    },
}

# Add diff data
diff = {
    "new": [
        {"module": "port_scanner", "type": "new_port", "severity": "high", "host": "203.0.113.12", "detail": "New open port: 3389 (RDP)"},
        {"module": "port_scanner", "type": "new_port", "severity": "high", "host": "203.0.113.10", "detail": "New open port: 8080"},
        {"module": "dns_enum", "type": "new_subdomain", "severity": "medium", "detail": "New subdomain: k8s.acme.com"},
        {"module": "vuln_check", "type": "new_vulnerability", "severity": "critical", "detail": "New vulnerability on 203.0.113.12: RDP-EXPOSED (port 3389)"},
    ],
    "removed": [
        {"module": "port_scanner", "type": "closed_port", "severity": "info", "host": "203.0.113.10", "detail": "Port closed: 21 (FTP)"},
        {"module": "vuln_check", "type": "vuln_remediated", "severity": "info", "detail": "Vulnerability remediated on 203.0.113.10: FTP-ANON"},
    ],
    "changed": [
        {"module": "whois_cert", "type": "cert_expiry_changed", "severity": "info", "detail": "Certificate expiry changed for acme.com: expired"},
    ],
    "summary": {"total_new": 4, "total_removed": 2, "total_changed": 1, "has_changes": True},
}

# Generate LLM analysis (basic mode)
llm_engine = LLMEngine(config)
analysis = llm_engine.analyze(assessment, diff)

# Generate report
generator = HTMLReportGenerator(config)
report_path = generator.generate(assessment, diff, analysis, "sample_report.html")
print(f"Sample report generated: {report_path}")
