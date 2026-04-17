# Changelog

All notable changes to Perimtr will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-04-17

### Added

- **New Modules**
  - Web Technology Fingerprinting — detects 33 technologies (CMS, frameworks, servers, CDNs, analytics) via headers, HTML, cookies, meta tags, and path probing with confidence scoring
  - SSL/TLS Deep Analysis — protocol version enumeration (SSLv3–TLS 1.3), cipher suite grading, PFS verification, OCSP stapling, certificate chain validation, HSTS preload check, and A+ through F letter grading

- **Error Handling & Input Validation**
  - `ConfigError` custom exception with structured validation errors
  - CIDR, domain, port, and port-range validators in `perimtr.core.validators`
  - `sanitize_targets()` — strips whitespace, lowercases domains, deduplicates, skips invalid entries with warnings
  - Graceful handling of corrupt JSON assessment files in data store
  - File locking on assessment writes to prevent concurrent corruption
  - Per-module retry logic with configurable `retry_count` and `retryable_exceptions`
  - Partial result preservation — modules can expose `_partial_results` on failure
  - Socket context managers throughout all modules to prevent resource leaks

- **Configuration Improvements**
  - Schema validation on load and after interactive setup
  - Environment variable overrides: `PERIMTR_LLM_API_KEY`, `PERIMTR_LLM_PROVIDER`, `PERIMTR_LLM_MODEL`
  - `mask_secrets()` for safe config display in logs
  - `_deep_merge()` fix — None values no longer overwrite valid defaults

- **CLI Enhancements**
  - `--dry-run` flag — previews what modules would run without scanning
  - `--modules` flag — comma-separated filter to run specific modules only
  - `--output-dir` flag — override report output directory
  - `--no-report` flag — skip HTML report generation
  - `--json` flag on `report` subparser — output JSON instead of HTML
  - Global exception handling: clean KeyboardInterrupt exit, formatted ConfigError, verbose hint for unexpected errors

- **Logging Overhaul**
  - Structured logging with `perimtr.core.logging_config`
  - Console output via Rich with severity colors
  - Rotating file logs (10 MB, 5 backups) always at DEBUG level
  - Per-module verbosity control via `module_levels` dict
  - Third-party logger suppression (urllib3, requests, asyncio)

- **Utilities**
  - `perimtr.core.exceptions` — full exception hierarchy (PerimtrError, ConfigError, ModuleError, DataStoreError, LLMError, ScanTimeoutError, NetworkError, TargetValidationError)
  - `perimtr.utils.network` — RateLimiter (thread-safe token bucket), cached DNS resolution, TCP connectivity test, safe banner grabbing
  - `DataStore.cleanup_old_assessments(keep=10)` — auto-cleanup of oldest files
  - `DataStore.export_assessment()` — JSON and CSV export by timestamp ID

- **Documentation**
  - `docs/ARCHITECTURE.md` — full system architecture with ASCII diagrams, component descriptions, data flow, module plugin guide, JSON schemas, directory tree, threading model, and error handling strategy
  - Complete docstrings with Args/Returns/Raises on every method across all modules
  - Type hints on all function parameters and return types
  - Inline comments on all complex logic sections

- **Testing**
  - 266 tests (up from 78), all passing
  - New test suites: validators (55 tests), exceptions (30 tests), network utils (31 tests), web tech (50 tests), SSL audit (40 tests)
  - Edge case coverage for Unicode domains, oversized labels, corrupt JSON, concurrent writes

---

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
