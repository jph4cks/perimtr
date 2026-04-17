# Perimtr Architecture

## System Overview

Perimtr is an automated perimeter security reconnaissance tool that discovers, analyses, and monitors the attack surface of target networks and domains.  It runs a configurable set of independent recon modules in parallel, persists results across runs, diffs the current assessment against the previous one to surface regressions, optionally enriches findings with LLM-generated analysis, and produces an interactive HTML report.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              perimtr run / schedule                          │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                    CLI                                       │
│  perimtr init  │  perimtr run  │  perimtr diff  │  perimtr report  │  sched  │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  Config                                      │
│  Loads perimtr.yaml  ──►  targets, scan_settings, modules, llm, schedule     │
└───────────────────────────────────────┬──────────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  Engine                                      │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │              ThreadPoolExecutor (scan_settings.threads)               │  │
│  │                                                                        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │port_scan │ │dns_enum  │ │http_hdrs │ │whois_cert│ │vuln_check│   │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                              │  │
│  │  │dom_secur │ │web_tech  │ │ssl_audit │   (+ any future modules)     │  │
│  │  └──────────┘ └──────────┘ └──────────┘                              │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                        │                                     │
│                        assessment dict (all module results)                  │
│                                        │                                     │
│                         ┌─────────────▼────────────┐                        │
│                         │        DataStore          │                        │
│                         │  saves JSON to data_dir   │                        │
│                         └─────────────┬────────────┘                        │
│                                        │                                     │
│                         ┌─────────────▼────────────┐                        │
│                         │        DiffEngine         │                        │
│                         │  compares with previous   │                        │
│                         └─────────────┬────────────┘                        │
│                                        │                                     │
│                         ┌─────────────▼────────────┐                        │
│                         │        LLMEngine          │                        │
│                         │  optional AI analysis     │                        │
│                         └─────────────┬────────────┘                        │
│                                        │                                     │
│                         ┌─────────────▼────────────┐                        │
│                         │   HTMLReportGenerator     │                        │
│                         │  Jinja2 → report.html     │                        │
│                         └──────────────────────────┘                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Descriptions

### CLI (`perimtr/cli.py`)

The command-line interface built with [Typer](https://typer.tiangolo.com/).  Provides subcommands:

| Command | Description |
|---------|-------------|
| `perimtr init` | First-run wizard: creates `perimtr.yaml` with targets, schedule, and LLM config |
| `perimtr run` | Execute a full assessment immediately |
| `perimtr diff` | Show changes between the two most-recent assessments |
| `perimtr report` | Regenerate the HTML report from saved assessment data |
| `perimtr schedule` | Start the background scheduler for recurring assessments |

CLI flags include `--config` (path override), `--modules` (comma-separated filter), `--output-dir`, `--dry-run`, `--no-report`, and `--no-llm`.

---

### Config (`perimtr/core/config.py`)

Loads and validates `perimtr.yaml`.  Exposes the parsed config as a plain dict (`Config.data`) for use throughout the system.

**Schema (YAML):**

```yaml
project_name: my-perimeter

targets:
  networks:
    - "192.168.1.0/24"
    - "10.0.0.0/16"
  domains:
    - "example.com"
    - "api.example.com"

schedule:
  frequency: weekly        # daily | weekly | monthly
  enabled: false

scan_settings:
  port_scan_rate: 10        # packets per second (10 = stealthy)
  top_ports: 1000           # well-known ports to scan
  dns_timeout: 10           # seconds
  http_timeout: 15          # seconds
  threads: 5                # concurrent module threads

modules:
  port_scanner:   { enabled: true }
  dns_enum:       { enabled: true }
  http_headers:   { enabled: true }
  whois_cert:     { enabled: true }
  vuln_check:     { enabled: true }
  domain_security: { enabled: true }
  web_tech:       { enabled: true }
  ssl_audit:      { enabled: true }

llm:
  provider: openrouter      # openai | anthropic | openrouter | local
  api_key: "sk-..."
  model: "openai/gpt-4o"
  base_url: null             # required for openrouter/local

data_dir: data
```

---

### Engine (`perimtr/engine.py`)

Orchestrates the full assessment workflow:

1. **Instantiate modules** — reads the `MODULES` registry from `perimtr/modules/__init__.py`, filters by config and optional CLI filter, instantiates each enabled module with the config dict.
2. **Execute in parallel** — submits each module's `safe_run(targets)` to a `ThreadPoolExecutor` with `scan_settings.threads` workers.  `safe_run()` is defined on `ReconModule` and guarantees no exceptions escape; errors are stored in `result["_meta"]`.
3. **Assemble assessment** — collects results from all futures into a single dict keyed by module name plus a `_assessment` metadata block.
4. **Persist** — passes the assessment to `DataStore.save_assessment()`.
5. **Diff** — if a previous assessment exists, runs `DiffEngine.diff(previous, current)`.
6. **LLM analysis** — if LLM is configured and not disabled, calls `LLMEngine.analyze(assessment, diff)`.
7. **Report** — calls `HTMLReportGenerator.generate(assessment, diff, llm_analysis)`.

---

### Modules (`perimtr/modules/`)

Each module is a self-contained Python class that inherits from `ReconModule`.

| Module | Category | Description |
|--------|----------|-------------|
| `PortScanner` | `network` | TCP port scan (nmap / socket fallback) |
| `DNSEnum` | `dns` | DNS record enumeration + subdomain discovery |
| `HTTPHeaders` | `web` | HTTP security header analysis |
| `WhoisCert` | `cert` | WHOIS + SSL/TLS certificate inspection |
| `VulnCheck` | `vuln` | Service-specific vulnerability checks |
| `DomainSecurity` | `domain` | SPF, DKIM, DMARC, DNSSEC, CAA, MX |
| `WebTechFingerprint` | `web` | CMS, framework, CDN, library detection |
| `SSLAudit` | `cert` | Deep TLS protocol/cipher/grade analysis |

---

### DataStore (`perimtr/core/datastore.py`)

Persists assessment results as JSON files under `data_dir/<project_name>/`.

```
data/
  my-perimeter/
    assessment_20240115_143022.json
    assessment_20240122_091500.json
    latest.json                   ← symlink or copy of most-recent
```

Provides:
- `save_assessment(assessment)` → path
- `load_latest()` → dict | None
- `load_previous()` → dict | None (second-most-recent)
- `list_assessments()` → list[str]

---

### DiffEngine (`perimtr/core/diff_engine.py`)

Compares two assessment dicts and returns a structured diff highlighting:
- **New findings** — issues/hosts/subdomains present in current but not previous
- **Resolved findings** — issues in previous but absent from current
- **Changed values** — fields whose values differ between runs
- `summary.has_changes` — bool indicating whether anything changed

**Diff JSON schema:**

```json
{
  "summary": {
    "has_changes": true,
    "new_findings": 3,
    "resolved_findings": 1,
    "changed_fields": 5
  },
  "new": {
    "hosts": ["10.0.0.5"],
    "subdomains": ["new.example.com"],
    "issues": [{"module": "...", "detail": "..."}]
  },
  "resolved": {
    "issues": [{"module": "...", "detail": "..."}]
  },
  "changed": {
    "port_scanner.hosts.10.0.0.1.ports": {
      "previous": [...],
      "current": [...]
    }
  }
}
```

---

### LLMEngine (`perimtr/core/llm_engine.py`)

Optional AI-powered analysis layer.  Supports OpenAI, Anthropic, OpenRouter, and local LLM endpoints.

Responsibilities:
- Summarize the assessment findings in plain English
- Prioritize remediation actions based on severity and business impact
- Highlight regression findings from the diff
- Generate an executive summary for non-technical stakeholders

The LLM engine is disabled by default and does not block report generation if unavailable.

---

### Reports (`perimtr/reports/html_report.py`)

Generates a self-contained HTML report using Jinja2 templates and Chart.js.

Sections included:
- Executive summary (severity distribution chart)
- Findings table (all issues, sortable by severity/module/host)
- Per-module detail panels (ports, DNS, headers, certs, vulns, domain security)
- Diff view (new/resolved findings highlighted)
- LLM analysis section (if available)

---

## Data Flow

```
perimtr.yaml
    │
    ▼
Config.load()
    │ targets: {networks, domains}
    │ scan_settings, modules, llm
    ▼
Engine.__init__()
    │ instantiates DataStore, DiffEngine, LLMEngine, HTMLReportGenerator
    ▼
Engine.run_assessment()
    │
    ├─ for each enabled module:
    │      module.safe_run(targets)
    │          └─ module.run(targets) → result dict
    │
    ├─ assessment = { "port_scanner": {...}, "dns_enum": {...}, ... }
    │
    ├─ DataStore.save_assessment(assessment)
    │
    ├─ previous = DataStore.load_previous()
    │  DiffEngine.diff(previous, assessment) → diff dict
    │
    ├─ LLMEngine.analyze(assessment, diff) → llm_analysis dict (optional)
    │
    └─ HTMLReportGenerator.generate(assessment, diff, llm_analysis)
           └─ report_<timestamp>.html
```

---

## Module Plugin Architecture

### How modules work

Every module is a Python class that:
1. Inherits from `perimtr.core.module_base.ReconModule`
2. Sets class-level attributes `name`, `description`, and `category`
3. Implements the `run(targets: dict) -> dict` abstract method

The `ReconModule` base class provides:
- `__init__(config)` — stores config and scan_settings, sets up logger
- `safe_run(targets)` — wraps `run()` with error handling and timing; always returns a dict with a `_meta` key
- `is_enabled(config)` — checks `config["modules"][self.name]["enabled"]`

### How to write a new module

```python
# perimtr/modules/my_module.py
"""
My Custom Module.

Brief description of what this module does.
"""
from perimtr.core.module_base import ReconModule


class MyModule(ReconModule):
    name = "my_module"
    description = "Brief human-readable description"
    category = "web"   # network | dns | web | cert | vuln | domain

    def run(self, targets: dict) -> dict:
        """
        Execute the module.

        Args:
            targets: {"networks": [...], "domains": [...]}

        Returns:
            Module-specific results dict.
        """
        results = {}
        domains = targets.get("domains", [])
        timeout = self.scan_settings.get("http_timeout", 15)

        for domain in domains:
            self.logger.info(f"Checking {domain}")
            results[domain] = self._check_domain(domain, timeout)

        return results

    def _check_domain(self, domain: str, timeout: int) -> dict:
        """Domain-specific logic."""
        ...
```

Then register it in `perimtr/modules/__init__.py`:

```python
from perimtr.modules.my_module import MyModule

MODULES = [
    ...,
    MyModule,
]

__all__ = [..., "MyModule"]
```

Add a default config entry in `perimtr/core/config.py`:

```python
DEFAULT_CONFIG["modules"]["my_module"] = {"enabled": True}
```

### Module output conventions

- Return a plain `dict` — no exceptions should propagate (handled by `safe_run`)
- Use `self.logger.info/warning/debug` for progress and errors
- Include an `"issues"` list for security findings when applicable
- Each issue should have: `issue`, `severity` (critical/high/medium/low/info), `detail`, `recommendation`
- Rate-limit outbound requests using `self.scan_settings["port_scan_rate"]`

---

## Assessment JSON Schema

```json
{
  "_assessment": {
    "timestamp": "2024-01-15T14:30:22.123456",
    "version": "1.0.0",
    "project_name": "my-perimeter",
    "targets": {
      "networks": ["192.168.1.0/24"],
      "domains": ["example.com"]
    },
    "duration_seconds": 42.7,
    "modules_run": ["port_scanner", "dns_enum", "http_headers", ...]
  },
  "port_scanner": {
    "hosts": {
      "93.184.216.34": {
        "ports": [
          {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
        ],
        "hostname": "example.com",
        "domain": "example.com"
      }
    },
    "total_hosts_scanned": 1,
    "total_open_ports": 2,
    "_meta": {"module": "port_scanner", "duration_seconds": 3.1, "status": "success"}
  },
  "dns_enum": {
    "subdomains": ["api.example.com", "www.example.com"],
    "records": {
      "example.com": {"A": ["93.184.216.34"], "MX": ["..."], "TXT": ["..."]}
    },
    "zone_transfer": {},
    "reverse_dns": {}
  },
  "http_headers": {
    "results": {
      "example.com": {
        "url": "https://example.com",
        "status_code": 200,
        "missing_headers": ["Content-Security-Policy"],
        "present_headers": [{"header": "Strict-Transport-Security", "value": "..."}],
        "info_leaks": [],
        "cookie_issues": [],
        "issues": [...]
      }
    },
    "total_issues": 3
  },
  "web_tech": {
    "results": {
      "example.com": {
        "technologies": [
          {"name": "Nginx", "version": "1.24.0", "category": "server",
           "confidence": "high", "evidence": "header server: nginx/1.24.0"}
        ],
        "tech_stack": {"server": ["Nginx"], "framework": [], "cdn": [], ...},
        "probed_paths": {"/wp-login.php": 404},
        "error": null
      }
    },
    "total_domains": 1,
    "technologies_found": 2
  },
  "ssl_audit": {
    "results": {
      "example.com": {
        "grade": "A",
        "protocol_support": {"SSLv3": false, "TLSv1.0": false, "TLSv1.1": false,
                              "TLSv1.2": true, "TLSv1.3": true},
        "cipher_suites": [
          {"name": "TLS_AES_256_GCM_SHA384", "strength": "strong", "bits": 256}
        ],
        "pfs_supported": true,
        "ocsp_stapling": null,
        "hsts_preload": false,
        "certificate_chain": {"valid": true, "length": 3, "issues": []},
        "vulnerabilities": [],
        "recommendations": ["Consider submitting to HSTS preload list"],
        "error": null
      }
    }
  }
}
```

---

## Directory Structure

```
perimtr/
├── perimtr/                    # Main Python package
│   ├── __init__.py             # Package version
│   ├── cli.py                  # Typer CLI entrypoint
│   ├── engine.py               # Assessment orchestrator
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py           # YAML config loading and validation
│   │   ├── module_base.py      # ReconModule abstract base class
│   │   ├── datastore.py        # JSON persistence layer
│   │   ├── diff_engine.py      # Assessment diff computation
│   │   ├── llm_engine.py       # LLM analysis integration
│   │   └── scheduler.py        # APScheduler-based recurring runs
│   ├── modules/
│   │   ├── __init__.py         # Module registry (MODULES list)
│   │   ├── port_scanner.py     # TCP port scanning (nmap / socket)
│   │   ├── dns_enum.py         # DNS enumeration + subdomain discovery
│   │   ├── http_headers.py     # HTTP security header analysis
│   │   ├── whois_cert.py       # WHOIS + SSL/TLS certificate analysis
│   │   ├── vuln_check.py       # Service vulnerability checks
│   │   ├── domain_security.py  # SPF/DKIM/DMARC/DNSSEC/CAA/MX
│   │   ├── web_tech.py         # Web technology fingerprinting
│   │   └── ssl_audit.py        # Deep TLS/SSL protocol analysis
│   ├── reports/
│   │   ├── __init__.py
│   │   └── html_report.py      # Jinja2 HTML report generator
│   └── templates/
│       └── report.html         # Main report Jinja2 template
├── tests/
│   ├── __init__.py
│   ├── test_config.py
│   ├── test_datastore.py
│   ├── test_diff_engine.py
│   ├── test_llm_engine.py
│   ├── test_modules.py         # Tests for core recon modules
│   ├── test_web_tech.py        # Tests for web_tech module
│   ├── test_ssl_audit.py       # Tests for ssl_audit module
│   └── test_report.py
├── docs/
│   ├── ARCHITECTURE.md         # This document
│   ├── index.html              # Documentation site
│   └── favicon.svg
├── data/                       # Runtime data directory (gitignored)
│   └── <project_name>/
│       ├── assessment_<timestamp>.json
│       └── latest.json
├── pyproject.toml              # Build config + dependencies
├── README.md
├── CHANGELOG.md
├── ROADMAP.md
└── SECURITY.md
```

---

## Threading Model

The engine uses Python's `concurrent.futures.ThreadPoolExecutor` to run modules in parallel:

```python
with ThreadPoolExecutor(max_workers=threads) as executor:
    futures = {
        executor.submit(module.safe_run, targets): module
        for module in enabled_modules
    }
    for future in as_completed(futures):
        module = futures[future]
        result = future.result()    # always returns (safe_run catches exceptions)
        assessment[module.name] = result
```

**Key properties:**
- Each module runs in its own thread; modules are fully independent and do not share mutable state.
- The `safe_run()` wrapper on `ReconModule` ensures no exception escapes to the thread pool — failures are stored in `result["_meta"]["status"] = "error"`.
- Rate limiting within each module (DNS, port scan, HTTP) is implemented with `time.sleep()` calls — these are per-module and do not coordinate across threads.
- The number of threads is controlled by `scan_settings.threads` (default: 5).

**Thread safety notes:**
- The `DataStore` writes are performed after all futures complete — no concurrent writes.
- `self.logger` is thread-safe (Python's `logging` module uses internal locks).
- Module instances are created fresh for each assessment run — no shared module-level mutable state between runs.

---

## Error Handling Strategy

Perimtr uses a layered error handling approach:

### Layer 1 — Module level (`safe_run`)
Every module call goes through `ReconModule.safe_run()`:
```python
def safe_run(self, targets):
    try:
        results = self.run(targets)
        results["_meta"] = {"status": "success", ...}
        return results
    except Exception as e:
        return {"_meta": {"status": "error", "error": str(e), ...}}
```
This guarantees the engine always receives a dict, never an exception.

### Layer 2 — Method level (internal try/except)
Within each module, individual check methods catch and handle their own exceptions:
- Network timeouts → return `None` or empty dict
- DNS resolution failures → logged at `WARNING` level, empty result returned
- SSL errors → captured in result dict with `"error"` key
- HTTP failures → try HTTP fallback, then log warning

### Layer 3 — Engine level
The engine's `ThreadPoolExecutor` loop calls `future.result()` which will re-raise exceptions — but since `safe_run` guarantees no exceptions, this is purely defensive.

### Severity levels (for findings/issues)
| Level | Description |
|-------|-------------|
| `critical` | Immediate risk; should be remediated within 24 hours (e.g. expired cert, SSLv3, open relay) |
| `high` | Significant risk; remediate within 1 week (e.g. expiring cert, missing HSTS, weak key) |
| `medium` | Moderate risk; remediate within 30 days (e.g. missing CSP, soft-fail SPF, TLS 1.1) |
| `low` | Informational/best-practice; remediate when convenient (e.g. missing CAA, HSTS no subdomains) |
| `info` | Purely informational; no action required |

---

## Adding a Schedule

Perimtr uses APScheduler for recurring scans:

```bash
perimtr schedule        # Start scheduler in foreground (reads perimtr.yaml)
```

Schedule configuration in `perimtr.yaml`:
```yaml
schedule:
  frequency: weekly     # daily | weekly | monthly
  enabled: true
```

The scheduler persists its job store to `data/<project_name>/scheduler.db` (SQLite) so jobs survive process restarts.
