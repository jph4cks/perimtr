"""
HTML Report Generator.

Generates interactive HTML reports with JavaScript dashboards.
Uses Jinja2 templates for rendering.
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
    """Generates interactive HTML security reports."""

    def __init__(self, config: dict):
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

        Args:
            assessment: Full assessment results
            diff: Optional diff from previous assessment
            llm_analysis: Optional LLM-generated analysis
            output_path: Where to save the report

        Returns:
            Path to the generated report
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"report_{timestamp}.html"

        # Prepare template data
        data = self._prepare_data(assessment, diff, llm_analysis)

        # Render template
        template = self.env.get_template("report.html")
        html = template.render(**data)

        # Write output
        with open(output_path, "w") as f:
            f.write(html)

        logger.info(f"Report generated: {output_path}")
        return output_path

    def _prepare_data(self, assessment: dict, diff: Optional[dict], llm_analysis: Optional[dict]) -> dict:
        """Prepare data for template rendering."""
        # Extract module results
        port_data = assessment.get("port_scanner", {})
        dns_data = assessment.get("dns_enum", {})
        headers_data = assessment.get("http_headers", {})
        cert_data = assessment.get("whois_cert", {})
        vuln_data = assessment.get("vuln_check", {})
        domain_data = assessment.get("domain_security", {})
        meta = assessment.get("_assessment", {})

        # Count severity levels across all modules
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # From vuln_check
        for finding in vuln_data.get("findings", []):
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # From http_headers
        for domain, data in headers_data.get("results", {}).items():
            for issue in data.get("issues", []):
                sev = issue.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # From domain_security
        for domain, data in domain_data.get("results", {}).items():
            for issue in data.get("issues", []):
                sev = issue.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # From whois_cert
        for issue in cert_data.get("issues", []):
            sev = issue.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_issues = sum(severity_counts.values())

        # Port data for charts
        services = {}
        for host, info in port_data.get("hosts", {}).items():
            for port_info in info.get("ports", []):
                if isinstance(port_info, dict):
                    svc = port_info.get("service", "unknown")
                    services[svc] = services.get(svc, 0) + 1

        return {
            "project_name": self.config.get("project_name", "Assessment"),
            "timestamp": meta.get("timestamp", datetime.now().isoformat()),
            "version": meta.get("version", "1.0.0"),

            # Summary stats
            "total_hosts": len(port_data.get("hosts", {})),
            "total_open_ports": port_data.get("total_open_ports", 0),
            "total_subdomains": len(dns_data.get("subdomains", [])),
            "total_issues": total_issues,
            "severity_counts": severity_counts,

            # Module data
            "port_data": port_data,
            "dns_data": dns_data,
            "headers_data": headers_data,
            "cert_data": cert_data,
            "vuln_data": vuln_data,
            "domain_data": domain_data,

            # Services distribution
            "services": services,
            "services_json": json.dumps(services),
            "severity_json": json.dumps(severity_counts),

            # Diff data
            "has_diff": diff is not None and diff.get("summary", {}).get("has_changes", False),
            "diff": diff or {},
            "diff_json": json.dumps(diff or {}),

            # LLM analysis
            "has_analysis": llm_analysis is not None,
            "analysis": llm_analysis or {},
            "analysis_json": json.dumps(llm_analysis or {}),

            # All issues for the table
            "all_issues": self._collect_all_issues(assessment),
            "all_issues_json": json.dumps(self._collect_all_issues(assessment)),
        }

    def _collect_all_issues(self, assessment: dict) -> list:
        """Collect all issues from all modules into a flat list."""
        issues = []

        # Vulnerability findings
        for finding in assessment.get("vuln_check", {}).get("findings", []):
            issues.append({
                "module": "Vulnerability",
                "severity": finding.get("severity", "info"),
                "host": finding.get("host", ""),
                "detail": finding.get("detail", ""),
                "recommendation": finding.get("recommendation", ""),
            })

        # HTTP header issues
        for domain, data in assessment.get("http_headers", {}).get("results", {}).items():
            for issue in data.get("issues", []):
                issues.append({
                    "module": "HTTP Headers",
                    "severity": issue.get("severity", "info"),
                    "host": domain,
                    "detail": issue.get("detail", ""),
                    "recommendation": issue.get("recommendation", ""),
                })

        # Domain security issues
        for domain, data in assessment.get("domain_security", {}).get("results", {}).items():
            for issue in data.get("issues", []):
                issues.append({
                    "module": "Domain Security",
                    "severity": issue.get("severity", "info"),
                    "host": issue.get("domain", domain),
                    "detail": issue.get("detail", ""),
                    "recommendation": issue.get("recommendation", ""),
                })

        # Certificate issues
        for issue in assessment.get("whois_cert", {}).get("issues", []):
            issues.append({
                "module": "Certificates",
                "severity": issue.get("severity", "info"),
                "host": issue.get("domain", ""),
                "detail": issue.get("detail", ""),
                "recommendation": issue.get("recommendation", ""),
            })

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))

        return issues
