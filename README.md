# <img src="https://raw.githubusercontent.com/jph4cks/perimtr/main/docs/favicon.svg" width="32" height="32" alt=""> Perimtr

**Perimeter Intelligence Platform** — Automated attack surface reconnaissance and change detection for real-world enterprise environments.

Give it your perimeter network ranges and domains, and Perimtr will investigate, inventory findings, and track changes over time. Optionally integrates with LLMs to provide AI-powered security recommendations.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-78%20passed-brightgreen.svg)]()

**[Website](https://jph4cks.github.io/perimtr/)** · **[Documentation](#quick-start)** · **[Roadmap](ROADMAP.md)** · **[Changelog](CHANGELOG.md)**

---

## What It Does

```
$ perimtr scan

🔍 Perimtr Assessment — Acme Corp Perimeter
   Networks: 203.0.113.0/24
   Domains:  acme.com, api.acme.com
   Modules:  6 enabled

 ✓ Port Scanner .............. 3 hosts, 10 open ports     (42.1s)
 ✓ DNS Enumeration ........... 12 subdomains found        (18.3s)
 ✓ HTTP Security Headers ..... 4 missing headers          (3.2s)
 ✓ WHOIS & Certificates ...... 1 cert expiring soon       (5.7s)
 ✓ Vulnerability Checks ...... 3 critical findings        (12.4s)
 ✓ Domain Security ........... SPF ✓  DKIM ✓  DMARC ✗    (8.1s)

 Changes Since Last Assessment:
   NEW .......... 4
   Resolved ..... 2
   Changed ...... 1

 Risk Score: 72/100 (HIGH)

 ✓ Report generated: data/acme-corp/report_20260416.html
 ✓ Assessment complete in 89.8s
```

Perimtr is a comprehensive perimeter security assessment tool designed for security teams at real companies. It combines six specialized reconnaissance modules with change tracking, LLM-powered analysis, and interactive HTML reports.

### Core Capabilities

| Capability | Description |
|-----------|-------------|
| **Network Port Scanning** | Slow, stealthy SYN scans of well-known ports with nmap integration and socket fallback |
| **DNS Enumeration** | Passive (crt.sh CT logs) and active (brute-force) subdomain discovery, DNS records, zone transfer testing |
| **HTTP Security Headers** | HSTS, CSP, X-Frame-Options, cookie security, TLS configuration, information leakage |
| **WHOIS & Certificate Intelligence** | Domain registration tracking, SSL/TLS certificate analysis, expiry and key strength |
| **Vulnerability Checks** | Exposed databases, open RDP, anonymous FTP, default SNMP, weak SSH, SMTP open relays |
| **Domain Security** | SPF, DKIM, DMARC, DNSSEC, and CAA record validation with policy analysis |
| **Change Detection** | Automatic diffing against previous assessments — new ports, subdomains, vulnerabilities |
| **LLM Analysis** | AI-powered executive summaries, risk scoring, and prioritized remediation (optional) |
| **Interactive Reports** | Self-contained HTML dashboards with charts, filtering, search, and tabbed navigation |

---

## Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/jph4cks/perimtr.git
cd perimtr
pip install -e .

# With LLM support (OpenAI, Anthropic, etc.)
pip install -e ".[llm]"

# With development tools
pip install -e ".[dev]"
```

**Prerequisites:** Python 3.9+ and optionally nmap for more accurate port scanning.

### First Run

```bash
perimtr
```

On first run, Perimtr walks you through interactive setup:

1. **Project name** — identifier for this assessment scope
2. **Network ranges** — CIDR notation (e.g., `203.0.113.0/24`)
3. **Domains** — your domain names (e.g., `example.com, api.example.com`)
4. **Schedule** — how often to run (daily, weekly, monthly)
5. **LLM integration** — optional AI-powered analysis

This creates a `perimtr.yaml` configuration file. Then it runs the first assessment automatically.

### CLI Commands

```bash
perimtr scan                    # Run full assessment
perimtr scan -v                 # Verbose output
perimtr scan -c custom.yaml     # Use specific config
perimtr report                  # Generate HTML report from latest
perimtr report -o report.html   # Custom output path
perimtr diff                    # Show changes between assessments
perimtr history                 # List all stored assessments
perimtr schedule                # Start recurring scheduler
perimtr setup                   # Re-run interactive setup
perimtr version                 # Show version
```

---

## Architecture

```
perimtr/
├── cli.py                  # CLI entry point
├── engine.py               # Orchestration — runs modules, saves, diffs, reports
├── core/
│   ├── config.py           # YAML config with interactive first-run setup
│   ├── module_base.py      # Abstract base class for all recon modules
│   ├── datastore.py        # JSON-based local assessment storage
│   ├── diff_engine.py      # Change detection across all module types
│   ├── scheduler.py        # Recurring assessment scheduling (daily/weekly/monthly)
│   └── llm_engine.py       # LLM integration (OpenAI, Anthropic, OpenRouter, local)
├── modules/
│   ├── port_scanner.py     # Network port scanning (nmap + socket fallback)
│   ├── dns_enum.py         # DNS enumeration (crt.sh + brute-force + records)
│   ├── http_headers.py     # HTTP security header analysis
│   ├── whois_cert.py       # WHOIS & certificate intelligence
│   ├── vuln_check.py       # Vulnerability & misconfiguration checks
│   └── domain_security.py  # SPF/DKIM/DMARC/DNSSEC/CAA validation
├── reports/
│   └── html_report.py      # HTML report generator with Jinja2
└── templates/
    └── report.html         # Interactive dashboard template
```

### Scan Flow

```
Configure → Scan → Inventory → Compare → Analyze → Report
    │          │        │          │         │         │
 YAML      6 modules  JSON     Diff      LLM or     HTML
 config    concurrent storage  engine    built-in   dashboard
```

1. **Configure** — Reads targets, settings, and module config from `perimtr.yaml`
2. **Scan** — Executes enabled modules concurrently with rate limiting
3. **Inventory** — Stores complete results as timestamped JSON
4. **Compare** — Diff engine detects new, removed, and changed findings
5. **Analyze** — LLM generates executive summary and risk score (or falls back to predefined analysis)
6. **Report** — Produces interactive HTML dashboard with all findings

---

## Modules

### Port Scanner

Performs slow, rate-limited port scans using nmap (with socket fallback when nmap isn't available). Scans 40 commonly-exposed ports by default at 10 packets/second to avoid triggering IDS/IPS.

```yaml
scan_settings:
  port_scan_rate: 10   # packets per second
```

### DNS Enumeration

Combines passive and active techniques:
- **Certificate Transparency** — Queries crt.sh for all certificates issued for the domain (no API key needed)
- **Brute-force** — Tests 90+ common subdomain prefixes (www, api, dev, staging, vpn, admin, etc.)
- **DNS Records** — Enumerates A, AAAA, MX, NS, TXT, CNAME, SOA for every discovered domain
- **Zone Transfer** — Tests all nameservers for AXFR misconfiguration

### HTTP Security Headers

Checks every domain for:
- Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Information leakage (Server, X-Powered-By, X-AspNet-Version headers)
- HSTS configuration quality (max-age, includeSubDomains, preload)
- CSP dangerous directives (unsafe-inline, unsafe-eval, data:)
- Cookie security flags (Secure, HttpOnly, SameSite)
- HTTP → HTTPS redirect behavior
- TLS protocol and cipher information

### WHOIS & Certificate Intelligence

- WHOIS registration details (registrar, dates, nameservers)
- SSL/TLS certificate analysis (issuer, expiry, SANs, key algorithm and size)
- Certificate Transparency monitoring for new certs
- Alerts for: expired certs, expiring within 30 days, weak keys (<2048-bit RSA), deprecated TLS, self-signed certs

### Vulnerability Checks

Tests for real-world misconfigurations:
- **Exposed databases** — MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch accessible from the internet
- **Dangerous services** — RDP, VNC, Telnet exposed without VPN
- **Anonymous FTP** — Tests login with anonymous credentials
- **SNMP defaults** — Checks for public/private community strings
- **SSH versions** — Flags outdated OpenSSH versions
- **SMTP relay** — Tests for open mail relay configuration
- **Service banners** — Grabs banners for version identification

### Domain Security

Validates email authentication and DNS security:
- **SPF** — Record existence, policy strength (+all, ~all, -all), DNS lookup count
- **DKIM** — Tests 30+ common selectors (google, selector1, default, etc.)
- **DMARC** — Policy analysis (none/quarantine/reject), reporting URIs, percentage coverage
- **DNSSEC** — DNSKEY and DS record validation
- **CAA** — Certificate Authority Authorization records
- **MX Security** — STARTTLS support on mail servers

---

## Change Detection

The diff engine compares every assessment with the previous one and surfaces changes:

| Change Type | Severity | Example |
|-------------|----------|---------|
| New open port | **High** | Port 8080 appeared on web server |
| Port closed | Info | Port 21 (FTP) no longer responding |
| New host discovered | **High** | New host at 10.0.0.5 with 3 open ports |
| Host gone | Medium | Host 10.0.0.3 stopped responding |
| New subdomain | Medium | dev.example.com discovered via CT logs |
| DNS record changed | Medium | A record for api.example.com points to new IP |
| New vulnerability | **Critical** | MySQL exposed without authentication |
| Vulnerability fixed | Info | Anonymous FTP access removed |
| Certificate issuer changed | **High** | SSL cert issuer changed unexpectedly |
| Header removed | Medium | HSTS header no longer present |
| New domain security issue | Medium | SPF record changed to +all |

---

## Configuration

Full `perimtr.yaml` reference:

```yaml
project_name: my-company-perimeter

targets:
  networks:
    - 203.0.113.0/24        # CIDR notation
    - 198.51.100.0/28
  domains:
    - example.com
    - api.example.com

schedule:
  frequency: weekly         # daily, weekly, monthly
  enabled: false

scan_settings:
  port_scan_rate: 10        # max packets/sec (slow to avoid blocks)
  top_ports: 1000           # number of well-known ports
  dns_timeout: 10           # seconds
  http_timeout: 15          # seconds
  threads: 5                # concurrent module execution

modules:
  port_scanner:
    enabled: true
  dns_enum:
    enabled: true
  http_headers:
    enabled: true
  whois_cert:
    enabled: true
  vuln_check:
    enabled: true
  domain_security:
    enabled: true

llm:
  provider: openai          # openai, anthropic, openrouter, local
  api_key: sk-...
  model: gpt-4o-mini
  base_url: null            # for local LLMs (e.g., http://localhost:11434/v1)

data_dir: data
```

### LLM Providers

| Provider | Setup | Example Model |
|----------|-------|---------------|
| **OpenAI** | API key from platform.openai.com | `gpt-4o-mini`, `gpt-4o` |
| **Anthropic** | API key from console.anthropic.com | `claude-sonnet-4-20250514` |
| **OpenRouter** | API key from openrouter.ai | `anthropic/claude-3.5-sonnet` |
| **Local** | Ollama, vLLM, or any OpenAI-compatible server | `llama3`, `mistral` |

When no LLM is configured, Perimtr still generates reports with predefined recommendations based on findings. The LLM layer elevates reports with executive summaries, risk scoring, and actionable remediation steps.

---

## Data Storage

All assessment data is stored locally as JSON files:

```
data/
└── my-company-perimeter/
    ├── assessment_20260416_110000.json
    ├── assessment_20260423_110000.json
    ├── report_20260416_110000.html
    ├── report_20260423_110000.html
    └── report_latest.html
```

Each assessment JSON contains complete results from all modules with timestamps and metadata. No data leaves your machine unless LLM integration is configured.

---

## Report Dashboard

Reports are self-contained HTML files with an interactive JavaScript dashboard:

| Tab | Contents |
|-----|----------|
| **Overview** | Summary stats, severity breakdown, service distribution charts |
| **Network** | Host and port table with service names and versions |
| **DNS** | Subdomain grid, DNS records by type, zone transfer results |
| **Web Security** | Per-domain header analysis — present, missing, leaking |
| **Certificates** | Cert details, WHOIS registration, expiry countdown |
| **Domain Security** | SPF/DKIM/DMARC/DNSSEC/CAA status cards with issue details |
| **Vulnerabilities** | Filterable findings table with severity badges |
| **Changes** | Diff view — new, resolved, and changed findings |
| **AI Analysis** | Risk score meter, executive summary, priority actions, recommendations |
| **All Issues** | Searchable, filterable master table of every issue found |

---

## Plugin Architecture

Every recon module inherits from `ReconModule` and implements a `run(targets)` method. To add a new module:

```python
from perimtr.core.module_base import ReconModule

class MyModule(ReconModule):
    name = "my_module"
    description = "My custom recon module"
    category = "custom"
    
    def run(self, targets: dict) -> dict:
        results = {}
        for domain in targets.get("domains", []):
            # Your reconnaissance logic here
            results[domain] = {"findings": [...]}
        return results
```

Then register it in `perimtr/modules/__init__.py`:

```python
from perimtr.modules.my_module import MyModule
MODULES.append(MyModule)
```

The engine handles concurrency, error handling, timing, data storage, and reporting automatically.

---

## Testing

```bash
# Run all 78 tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=perimtr --cov-report=term-missing

# Run specific module tests
pytest tests/test_modules.py -v
pytest tests/test_diff_engine.py -v
```

Test coverage includes configuration management, data storage, the diff engine, all 6 recon modules (with mocked network calls), the LLM engine, and HTML report generation.

---

## Stealth Scanning

Port scans are deliberately slow to avoid detection:

- Default rate: **10 packets/second** (configurable)
- SYN scan with `-T2` timing template (nmap)
- Only well-known ports — no full 65k range
- DNS brute-force uses the same rate limiter
- All timeouts are configurable

For internal network assessments where stealth isn't needed, increase `port_scan_rate` to 100+ and `threads` to 10+.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Add your module following the [plugin architecture](#plugin-architecture)
4. Write tests for your module
5. Submit a pull request

See [ROADMAP.md](ROADMAP.md) for planned features and contribution ideas.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**Jesus A. Perez Duerto** — [Red Hound Information Security](https://redhound.us)
