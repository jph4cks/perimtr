# Perimtr

**Perimeter Intelligence Platform** — Automated attack surface reconnaissance and change detection for real-world enterprise environments.

Give it your perimeter network ranges and domains, and Perimtr will investigate, inventory findings, and track changes over time. Optionally integrates with LLMs to provide AI-powered security recommendations.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-78%20passed-brightgreen.svg)]()

---

## What It Does

Perimtr is a comprehensive perimeter security assessment tool designed for security teams at real companies. It performs:

- **Network Port Scanning** — Slow, stealthy SYN scans of well-known ports to discover exposed services
- **DNS Enumeration** — Passive (Certificate Transparency via crt.sh) and active (brute-force) subdomain discovery, full DNS record enumeration, zone transfer testing
- **HTTP Security Headers** — Checks for HSTS, CSP, X-Frame-Options, cookie security, TLS configuration, and information leakage
- **WHOIS & Certificate Intelligence** — Domain registration tracking, SSL/TLS certificate analysis (expiry, key strength, SAN), Certificate Transparency monitoring
- **Vulnerability Checks** — Detects exposed databases (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch), open RDP, anonymous FTP, default SNMP, SSH weak versions, SMTP open relays
- **Domain Security** — SPF, DKIM, DMARC, DNSSEC, and CAA record validation with policy analysis
- **Change Detection** — Automatically compares against previous assessments to surface new ports, subdomains, vulnerabilities, and configuration changes
- **LLM Analysis** — Optional AI-powered executive summaries, risk scoring, and prioritized remediation recommendations
- **Interactive HTML Reports** — JavaScript-powered dashboards with severity charts, filtering, search, and tabbed navigation

## Architecture

```
perimtr/
├── cli.py                  # CLI entry point (scan, setup, report, diff, history, schedule)
├── engine.py               # Orchestration engine — runs modules, saves, diffs, reports
├── core/
│   ├── config.py           # YAML config with interactive first-run setup
│   ├── module_base.py      # Abstract base class for all recon modules
│   ├── datastore.py        # JSON-based local assessment storage
│   ├── diff_engine.py      # Change detection across all module types
│   ├── scheduler.py        # Recurring assessment scheduling
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

### Plugin Architecture

Every recon module inherits from `ReconModule` and implements a `run(targets)` method. To add a new module:

1. Create a new file in `perimtr/modules/`
2. Inherit from `perimtr.core.module_base.ReconModule`
3. Define `name`, `description`, and `category`
4. Implement the `run(targets) -> dict` method
5. Register it in `perimtr/modules/__init__.py`

## Installation

### Prerequisites

- Python 3.9 or higher
- nmap (optional but recommended for more accurate port scanning)

### Install from source

```bash
git clone https://github.com/jph4cks/perimtr.git
cd perimtr
pip install -e .
```

### With LLM support

```bash
pip install -e ".[llm]"
```

### With development tools

```bash
pip install -e ".[dev]"
```

## Quick Start

### First Run

```bash
perimtr
```

On first run, Perimtr will walk you through interactive setup:

1. **Project name** — identifier for this assessment scope
2. **Network ranges** — CIDR notation (e.g., `203.0.113.0/24`)
3. **Domains** — your domain names (e.g., `example.com, api.example.com`)
4. **Schedule** — how often to run (daily, weekly, monthly)
5. **LLM integration** — optional AI-powered analysis

This creates a `perimtr.yaml` configuration file.

### Run an Assessment

```bash
# Run full assessment
perimtr scan

# With verbose output
perimtr scan -v

# Using a specific config file
perimtr scan -c /path/to/config.yaml
```

### View Results

```bash
# Generate HTML report from latest assessment
perimtr report

# Save report to specific path
perimtr report -o my_report.html

# Show changes between last two assessments
perimtr diff

# List all saved assessments
perimtr history
```

### Schedule Recurring Assessments

```bash
# Start the scheduler (runs in foreground)
perimtr schedule
```

## Configuration

Perimtr uses a YAML configuration file (`perimtr.yaml`):

```yaml
project_name: my-company-perimeter

targets:
  networks:
    - 203.0.113.0/24
    - 198.51.100.0/28
  domains:
    - example.com
    - api.example.com

schedule:
  frequency: weekly    # daily, weekly, monthly
  enabled: false

scan_settings:
  port_scan_rate: 10   # max packets/sec (slow to avoid blocks)
  top_ports: 1000      # number of ports to scan
  dns_timeout: 10      # seconds
  http_timeout: 15     # seconds
  threads: 5           # concurrent module execution

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
  provider: openai     # openai, anthropic, openrouter, local
  api_key: sk-...
  model: gpt-4o-mini
  base_url: null       # for local LLMs (e.g., http://localhost:11434/v1)

data_dir: data
```

### LLM Providers

Perimtr supports multiple LLM providers for AI-powered analysis:

| Provider | Setup | Example Model |
|----------|-------|---------------|
| **OpenAI** | API key from platform.openai.com | `gpt-4o-mini`, `gpt-4o` |
| **Anthropic** | API key from console.anthropic.com | `claude-sonnet-4-20250514` |
| **OpenRouter** | API key from openrouter.ai | `anthropic/claude-3.5-sonnet` |
| **Local** | Ollama, vLLM, or any OpenAI-compatible server | `llama3`, `mistral` |

When no LLM is configured, Perimtr still generates useful reports with predefined recommendations based on findings.

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

Each assessment JSON contains the full results from all modules, with timestamps and metadata. The diff engine compares any two assessments to detect changes.

## Report Dashboard

Reports are self-contained HTML files with an interactive JavaScript dashboard featuring:

- **Overview** — summary statistics, severity breakdown, bar charts
- **Network** — host and port table with service details
- **DNS** — subdomain grid, DNS records, zone transfer results
- **Web Security** — header analysis per domain with present/missing/leaking
- **Certificates** — cert details, WHOIS data, expiry tracking
- **Domain Security** — SPF/DKIM/DMARC/DNSSEC/CAA status cards
- **Vulnerabilities** — filterable findings table with severity badges
- **Changes** — diff view showing new, resolved, and changed findings
- **AI Analysis** — risk score, executive summary, priority actions, recommendations
- **All Issues** — searchable, filterable master issue table

## How It Works

### Scan Flow

1. **Load config** — reads targets, settings, and module configuration
2. **Run modules** — executes enabled modules concurrently with rate limiting
3. **Save assessment** — stores results as timestamped JSON
4. **Diff** — compares with previous assessment to detect changes
5. **Analyze** — generates analysis (LLM-powered or predefined)
6. **Report** — produces interactive HTML dashboard

### Stealth Scanning

Port scans use slow, rate-limited techniques to avoid detection and blocking:

- Default rate: 10 packets/second
- SYN scan with `-T2` timing (nmap) or timed socket connections
- Only well-known ports (no full port range by default)
- Randomized order where possible
- Configurable via `scan_settings.port_scan_rate`

### Change Detection

The diff engine tracks changes across all module types:

| Change Type | Severity | Example |
|-------------|----------|---------|
| New open port | High | Port 8080 appeared on web server |
| Port closed | Info | Port 21 (FTP) no longer responding |
| New host | High | New host discovered at 10.0.0.5 |
| Host gone | Medium | Host 10.0.0.3 stopped responding |
| New subdomain | Medium | dev.example.com appeared |
| DNS record changed | Medium | A record for api.example.com changed |
| New vulnerability | Critical | MySQL exposed without authentication |
| Vulnerability fixed | Info | Anonymous FTP access removed |
| Certificate issuer changed | High | SSL cert issuer changed unexpectedly |
| New missing header | Medium | HSTS header removed from production |
| Domain security issue | Medium | SPF record changed to +all |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=perimtr --cov-report=term-missing

# Run specific test file
pytest tests/test_diff_engine.py -v
```

78 tests covering configuration, data storage, diff engine, all 6 recon modules, LLM engine, and HTML report generation.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Add your module following the plugin architecture
4. Write tests for your module
5. Submit a pull request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**Jesus A. Perez Duerto** — [Red Hound Information Security](https://redhound.us)
