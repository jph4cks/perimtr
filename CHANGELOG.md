# Changelog

All notable changes to Perimtr will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-04-16

### Added

- **Core Engine**
  - YAML-based configuration with interactive first-run setup
  - JSON-based local data store for assessment persistence
  - Concurrent module execution with configurable threading
  - Assessment scheduling (daily, weekly, monthly)

- **Recon Modules**
  - Port Scanner — slow SYN scan with nmap integration and socket fallback
  - DNS Enumeration — passive (crt.sh CT logs) and active (brute-force) subdomain discovery, full DNS record enumeration, zone transfer testing
  - HTTP Security Headers — HSTS, CSP, X-Frame-Options, cookie security, TLS info, information leakage detection
  - WHOIS & Certificate Intelligence — domain registration, SSL/TLS certificate analysis, key strength, expiry tracking
  - Vulnerability Checks — exposed databases, open RDP, anonymous FTP, default SNMP, weak SSH, SMTP open relay
  - Domain Security — SPF, DKIM, DMARC, DNSSEC, and CAA record validation with policy analysis

- **Change Detection Engine**
  - Automatic comparison with previous assessments
  - Detects new/removed ports, hosts, subdomains, vulnerabilities, headers, and certificates
  - Severity classification for all changes

- **LLM Analysis Layer**
  - Support for OpenAI, Anthropic, OpenRouter, and local LLMs
  - AI-powered executive summaries, risk scoring, and prioritized recommendations
  - Graceful fallback to predefined analysis when no LLM is configured

- **HTML Report Dashboard**
  - Interactive JavaScript-powered reports with tabbed navigation
  - Overview with severity distribution and service charts
  - Filterable and searchable issue tables
  - Change tracking visualization
  - AI analysis section with risk meter and priority actions

- **CLI Interface**
  - `perimtr scan` — run assessment
  - `perimtr setup` — interactive configuration
  - `perimtr report` — generate report from latest
  - `perimtr diff` — show changes between assessments
  - `perimtr history` — list all assessments
  - `perimtr schedule` — start recurring scheduler
  - `perimtr version` — show version

- **Testing**
  - 78 unit tests covering all components
  - Configuration, data store, diff engine, all modules, LLM engine, and report generation

- **Documentation**
  - Comprehensive README with architecture, installation, usage, and configuration
  - SECURITY.md with responsible use guidelines
  - ROADMAP.md with planned features
