# Perimtr Roadmap

## Current Release: v1.1.0

Core platform with 8 recon modules, change detection, LLM analysis, interactive HTML reports,
structured logging, input validation, and a custom exception hierarchy.

---

## v1.2.0 — Advanced Scanning

- [ ] **Nuclei integration** — Template-based vulnerability scanning for known CVEs
- [ ] **Custom port lists** — User-defined port ranges per target
- [ ] **UDP scanning** — SNMP, DNS, NTP, and other UDP service discovery
- [ ] **Service version detection** — Deep banner analysis with CPE matching
- [ ] **Cloud asset discovery** — AWS, Azure, GCP public resource enumeration
- [ ] **Wayback Machine integration** — Discover historical endpoints and removed pages
- [ ] **ASN and IP range discovery** — Automatic network range identification from organization name

## v1.3.0 — Reporting & Notifications

- [ ] **PDF report export** — Professional PDF reports for management
- [ ] **Email notifications** — Send alerts when critical changes are detected
- [ ] **Slack/Teams integration** — Post assessment summaries to channels
- [ ] **Trend analysis** — Historical charts showing attack surface changes over time
- [ ] **Compliance mapping** — Map findings to CIS, NIST, PCI DSS controls
- [ ] **Report comparison view** — Side-by-side visual diff between any two assessments

## v1.4.0 — Enterprise Features

- [ ] **Multi-project management** — Manage multiple perimeters from one instance
- [ ] **API server** — REST API for integration with other tools
- [ ] **Role-based access** — Team access controls for shared deployments
- [ ] **Custom module SDK** — Simplified module development with hot-reload
- [ ] **Database backend** — Optional SQLite/PostgreSQL for large-scale deployments
- [ ] **Plugin marketplace** — Community module registry

## v2.0.0 — Continuous Monitoring

- [ ] **Continuous scanning mode** — Real-time change detection with configurable intervals
- [ ] **Webhook triggers** — Fire webhooks when specific changes occur
- [ ] **Asset inventory UI** — Web-based dashboard for browsing inventory
- [ ] **Risk scoring model** — Machine learning-based risk prioritization
- [ ] **Supply chain monitoring** — Track third-party service dependencies

---

## Completed

### v1.1.0 (2026-04-17)
- [x] Web technology fingerprinting (33 technologies)
- [x] SSL/TLS deep analysis with letter grading
- [x] Input validation and config schema enforcement
- [x] Environment variable support for API keys
- [x] Structured logging with file rotation
- [x] Custom exception hierarchy
- [x] CLI enhancements (--dry-run, --modules, --json, --no-report)
- [x] Architecture documentation
- [x] 266 tests (up from 78)

### v1.0.0 (2026-04-16)
- [x] Core engine with 6 recon modules
- [x] Change detection engine
- [x] LLM analysis layer (OpenAI, Anthropic, OpenRouter, local)
- [x] Interactive HTML report dashboard
- [x] CLI with scan, setup, report, diff, history, schedule
- [x] Product website on GitHub Pages

---

## Contributing

We welcome contributions for any roadmap item. See the [README](README.md) for contribution guidelines.

Priority items are tagged with `good first issue` or `help wanted` in the GitHub issue tracker.
