"""
HTML Report Generator.

Generates interactive HTML reports with JavaScript dashboards.
Uses Jinja2 templates for rendering.

How it works:
  1. ``generate()`` accepts the full assessment results dict plus optional
     diff and LLM analysis dicts.
  2. ``_prepare_data()`` extracts and aggregates data from all module results
     into a flat context dict ready for Jinja2 template rendering.
  3. ``_collect_all_issues()`` flattens severity-rated findings from all
     modules into a single sorted list for the findings table.
  4. The Jinja2 template is rendered and written to ``output_path``.

Templates:
  The template lives at ``perimtr/templates/report.html`` and receives the
  full context dict.  It uses Chart.js for severity distribution and service
  frequency charts.

Data flow::

    assessment dict
        │
        ▼
    _prepare_data() → Jinja2 context
        │
        ▼
    template.render(**context) → HTML string
        │
        ▼
    write to output_path → str (path)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from perimtr.core.llm_engine import LLMEngine

logger = logging.getLogger("perimtr")


class HTMLReportGenerator:
    """
    Interactive HTML Security Report Generator.

    Renders a self-contained HTML report from assessment results, including
    severity charts, findings tables, per-module detail sections, and an
    optional LLM-generated executive summary.

    The generated report is a single HTML file with all CSS and JavaScript
    inlined (via CDN references) so it can be viewed offline.

    Attributes:
        config: Application configuration dict.
        env: Jinja2 ``Environment`` configured to load templates from the
            ``perimtr/templates/`` directory.

    Example usage::

        generator = HTMLReportGenerator(config)
        path = generator.generate(
            assessment=results,
            diff=diff_data,
            llm_analysis=analysis,
            output_path="report_20240101.html"
        )
    """

    def __init__(self, config: dict):
        """
        Initialize the report generator with application config.

        Sets up the Jinja2 templating environment with auto-escaping enabled
        for HTML files.

        Args:
            config: Full application configuration dict.  Used to extract
                ``project_name`` for the report title.
        """
        self.config = config
        template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html"]),
        )

    def generate(
        self,
        assessment: dict,
        diff: Optional[dict] = None,
        llm_analysis: Optional[dict] = None,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate an HTML report from assessment results.

        Prepares the template context from all module results, renders the
        Jinja2 template, and writes the output to a file.

        Args:
            assessment: Full assessment results dict as produced by the engine.
                Expected to contain module result dicts keyed by module name
                plus a ``_assessment`` metadata key.
            diff: Optional diff dict from ``DiffEngine.diff()``.  If provided
                and ``diff["summary"]["has_changes"]`` is truthy, a changes
                section is rendered.
            llm_analysis: Optional analysis dict from ``LLMEngine.analyze()``.
                If provided, an executive summary section is rendered.
            output_path: File system path for the output HTML file.  If not
                provided, a timestamped filename (``report_YYYYMMDD_HHMMSS.html``)
                is used in the current working directory.

        Returns:
            Absolute or relative path to the generated HTML file.

        Raises:
            jinja2.TemplateNotFound: If ``report.html`` is not found in the
                templates directory.
            OSError: If the output path is not writable.

        Example::

            path = generator.generate(assessment, output_path="/tmp/report.html")
            # Returns: "/tmp/report.html"
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"report_{timestamp}.html"

        # Build the Jinja2 template context
        data = self._prepare_data(assessment, diff, llm_analysis)

        # Render the HTML template
        template = self.env.get_template("report.html")
        html = template.render(**data)

        # Write report to disk
        with open(output_path, "w") as f:
            f.write(html)

        logger.info(f"Report generated: {output_path}")
        return output_path

    def _prepare_data(
        self,
        assessment: dict,
        diff: Optional[dict],
        llm_analysis: Optional[dict],
    ) -> dict:
        """
        Build the Jinja2 template context from assessment results.

        Extracts per-module data, aggregates severity counts across all
        modules, and prepares JSON-serialized versions of data structures
        for use by Chart.js in the template.

        Severity counting sources:
          - ``vuln_check.findings[].severity``
          - ``http_headers.results[*].issues[].severity``
          - ``domain_security.results[*].issues[].severity``
          - ``whois_cert.issues[].severity``

        Args:
            assessment: Full assessment results dict.
            diff: Optional diff results dict, or ``None``.
            llm_analysis: Optional LLM analysis dict, or ``None``.

        Returns:
            dict of template variables including module data, summary
            statistics, JSON-serialized chart data, and diff/LLM sections.
        """
        # Extract per-module result dicts
        port_data = assessment.get("port_scanner", {})
        dns_data = assessment.get("dns_enum", {})
        headers_data = assessment.get("http_headers", {})
        cert_data = assessment.get("whois_cert", {})
        vuln_data = assessment.get("vuln_check", {})
        domain_data = assessment.get("domain_security", {})
        meta = assessment.get("_assessment", {})

        # Aggregate severity counts across all modules
        severity_counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # Vulnerability findings from vuln_check
        for finding in vuln_data.get("findings", []):
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # HTTP header issues
        for domain, data in headers_data.get("results", {}).items():
            for issue in data.get("issues", []):
                sev = issue.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Domain security issues (SPF/DMARC/DKIM/DNSSEC/CAA/MX)
        for domain, data in domain_data.get("results", {}).items():
            for issue in data.get("issues", []):
                sev = issue.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Certificate issues from whois_cert
        for issue in cert_data.get("issues", []):
            sev = issue.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_issues = sum(severity_counts.values())

        # Build service frequency dict for the port distribution chart
        services: dict = {}
        for host, info in port_data.get("hosts", {}).items():
            for port_info in info.get("ports", []):
                if isinstance(port_info, dict):
                    svc = port_info.get("service", "unknown")
                    services[svc] = services.get(svc, 0) + 1

        return {
            "project_name": self.config.get("project_name", "Assessment"),
            "timestamp": meta.get("timestamp", datetime.now().isoformat()),
            "version": meta.get("version", "1.0.0"),

            # Summary statistics for the overview cards
            "total_hosts": len(port_data.get("hosts", {})),
            "total_open_ports": port_data.get("total_open_ports", 0),
            "total_subdomains": len(dns_data.get("subdomains", [])),
            "total_issues": total_issues,
            "severity_counts": severity_counts,

            # Per-module data dicts for detail sections
            "port_data": port_data,
            "dns_data": dns_data,
            "headers_data": headers_data,
            "cert_data": cert_data,
            "vuln_data": vuln_data,
            "domain_data": domain_data,

            # JSON-serialized chart data for Chart.js
            "services": services,
            "services_json": json.dumps(services),
            "severity_json": json.dumps(severity_counts),

            # Diff section (only rendered when has_changes=True)
            "has_diff": diff is not None and diff.get("summary", {}).get("has_changes", False),
            "diff": diff or {},
            "diff_json": json.dumps(diff or {}),

            # LLM analysis section (only rendered when analysis is present)
            "has_analysis": llm_analysis is not None,
            "analysis": llm_analysis or {},
            "analysis_json": json.dumps(llm_analysis or {}),

            # Flat issue list for the sortable findings table
            "all_issues": self._collect_all_issues(assessment),
            "all_issues_json": json.dumps(self._collect_all_issues(assessment)),
        }

    def _collect_all_issues(self, assessment: dict) -> list:
        """
        Collect and sort all security issues from every module into a flat list.

        Aggregates findings from:
          - ``vuln_check.findings``
          - ``http_headers.results[*].issues``
          - ``domain_security.results[*].issues``
          - ``whois_cert.issues``

        Each issue is normalized to a common schema with ``module``,
        ``severity``, ``host``, ``detail``, and ``recommendation`` keys,
        then sorted from most to least severe.

        Args:
            assessment: Full assessment results dict.

        Returns:
            List of normalized issue dicts, sorted by severity
            (critical → high → medium → low → info).

        Example::

            [
                {
                    "module": "Vulnerability",
                    "severity": "critical",
                    "host": "10.0.0.1",
                    "detail": "Redis accepts unauthenticated connections",
                    "recommendation": "Enable Redis AUTH"
                },
                ...
            ]
        """
        issues: list = []

        # Vulnerability findings from service checks
        for finding in assessment.get("vuln_check", {}).get("findings", []):
            issues.append({
                "module": "Vulnerability",
                "severity": finding.get("severity", "info"),
                "host": finding.get("host", ""),
                "detail": finding.get("detail", ""),
                "recommendation": finding.get("recommendation", ""),
            })

        # HTTP security header issues per domain
        for domain, data in assessment.get("http_headers", {}).get("results", {}).items():
            for issue in data.get("issues", []):
                issues.append({
                    "module": "HTTP Headers",
                    "severity": issue.get("severity", "info"),
                    "host": domain,
                    "detail": issue.get("detail", ""),
                    "recommendation": issue.get("recommendation", ""),
                })

        # Domain security issues (email/DNS configuration)
        for domain, data in assessment.get("domain_security", {}).get("results", {}).items():
            for issue in data.get("issues", []):
                issues.append({
                    "module": "Domain Security",
                    "severity": issue.get("severity", "info"),
                    "host": issue.get("domain", domain),
                    "detail": issue.get("detail", ""),
                    "recommendation": issue.get("recommendation", ""),
                })

        # Certificate and WHOIS issues
        for issue in assessment.get("whois_cert", {}).get("issues", []):
            issues.append({
                "module": "Certificates",
                "severity": issue.get("severity", "info"),
                "host": issue.get("domain", ""),
                "detail": issue.get("detail", ""),
                "recommendation": issue.get("recommendation", ""),
            })

        # Sort from most to least severe using a numeric key mapping
        severity_order: dict = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))

        return issues
