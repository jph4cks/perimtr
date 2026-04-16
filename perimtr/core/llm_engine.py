"""
LLM Analysis Engine.

Provides AI-powered analysis of assessment results when an LLM provider
is configured. Falls back to predefined recommendations when no LLM is available.

Supports:
  - OpenAI (ChatGPT)
  - Anthropic (Claude)
  - OpenRouter (any model)
  - Local LLMs (Ollama, vLLM, etc.)
"""

import json
import logging
from typing import Optional

import requests

logger = logging.getLogger("perimtr")


class LLMEngine:
    """Generates AI-powered security analysis and recommendations."""

    def __init__(self, config: dict):
        self.llm_config = config.get("llm", {})
        self.provider = self.llm_config.get("provider")
        self.api_key = self.llm_config.get("api_key")
        self.model = self.llm_config.get("model")
        self.base_url = self.llm_config.get("base_url")
        self.available = self.provider is not None

    def analyze(self, assessment: dict, diff: Optional[dict] = None) -> dict:
        """
        Analyze assessment results and generate recommendations.

        Args:
            assessment: Full assessment results
            diff: Optional diff from previous assessment

        Returns:
            Dict with executive_summary, findings_analysis, recommendations,
            risk_score, and priority_actions
        """
        if not self.available:
            return self._generate_basic_analysis(assessment, diff)

        try:
            return self._generate_llm_analysis(assessment, diff)
        except Exception as e:
            logger.warning(f"LLM analysis failed, falling back to basic: {e}")
            return self._generate_basic_analysis(assessment, diff)

    def _generate_llm_analysis(self, assessment: dict, diff: Optional[dict]) -> dict:
        """Generate analysis using configured LLM provider."""
        prompt = self._build_prompt(assessment, diff)

        if self.provider in ("openai", "local", "openrouter"):
            return self._call_openai_compatible(prompt)
        elif self.provider == "anthropic":
            return self._call_anthropic(prompt)
        else:
            return self._generate_basic_analysis(assessment, diff)

    def _build_prompt(self, assessment: dict, diff: Optional[dict]) -> str:
        """Build the analysis prompt from assessment data."""
        # Summarize findings to keep prompt manageable
        summary = self._summarize_assessment(assessment)

        prompt = f"""You are a senior cybersecurity analyst reviewing a perimeter security assessment.
Analyze the following findings and provide a structured security report.

## Assessment Summary
{json.dumps(summary, indent=2)}
"""
        if diff and diff.get("summary", {}).get("has_changes"):
            prompt += f"""
## Changes Since Last Assessment
{json.dumps(diff, indent=2)}
"""

        prompt += """
Provide your analysis in the following JSON structure:
{
  "executive_summary": "2-3 paragraph executive summary for leadership",
  "risk_score": <1-100 integer>,
  "risk_rating": "critical|high|medium|low",
  "top_risks": ["risk 1", "risk 2", ...],
  "priority_actions": [
    {"priority": 1, "action": "description", "effort": "low|medium|high", "impact": "description"},
    ...
  ],
  "findings_analysis": {
    "network": "analysis of network findings",
    "web_security": "analysis of web/HTTP findings",
    "email_security": "analysis of email/domain findings",
    "certificates": "analysis of certificate findings",
    "vulnerabilities": "analysis of vulnerability findings"
  },
  "recommendations": [
    {"category": "category", "recommendation": "detailed recommendation", "priority": "critical|high|medium|low"},
    ...
  ]
}

Be specific, actionable, and reference actual findings. Prioritize by risk.
Respond with ONLY the JSON object, no other text.
"""
        return prompt

    def _call_openai_compatible(self, prompt: str) -> dict:
        """Call OpenAI-compatible API (OpenAI, OpenRouter, local LLMs)."""
        if self.provider == "openai":
            base = "https://api.openai.com/v1"
        elif self.provider == "openrouter":
            base = self.base_url or "https://openrouter.ai/api/v1"
        else:  # local
            base = self.base_url or "http://localhost:11434/v1"

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert providing perimeter security analysis. Always respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 4000,
        }

        resp = requests.post(
            f"{base}/chat/completions",
            headers=headers,
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()

        content = data["choices"][0]["message"]["content"]
        # Strip markdown code blocks if present
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content[:-3]

        return json.loads(content)

    def _call_anthropic(self, prompt: str) -> dict:
        """Call Anthropic API."""
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": self.model or "claude-sonnet-4-20250514",
            "max_tokens": 4000,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "system": "You are a cybersecurity expert providing perimeter security analysis. Always respond with valid JSON.",
        }

        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()

        content = data["content"][0]["text"]
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content[:-3]

        return json.loads(content)

    def _summarize_assessment(self, assessment: dict) -> dict:
        """Create a concise summary of assessment for the LLM prompt."""
        summary = {}

        # Port scanner summary
        ps = assessment.get("port_scanner", {})
        if ps:
            hosts = ps.get("hosts", {})
            summary["network"] = {
                "hosts_found": len(hosts),
                "total_open_ports": ps.get("total_open_ports", 0),
                "services": {},
            }
            for host, info in hosts.items():
                for port_info in info.get("ports", []):
                    svc = port_info.get("service", "unknown") if isinstance(port_info, dict) else "unknown"
                    port = port_info.get("port", 0) if isinstance(port_info, dict) else port_info
                    summary["network"]["services"][f"{host}:{port}"] = svc

        # DNS summary
        dns_data = assessment.get("dns_enum", {})
        if dns_data:
            summary["dns"] = {
                "subdomains_found": len(dns_data.get("subdomains", [])),
                "subdomains": dns_data.get("subdomains", [])[:20],
                "zone_transfer_possible": any(
                    v.get("successful", False) for v in dns_data.get("zone_transfer", {}).values()
                ),
            }

        # HTTP headers summary
        headers_data = assessment.get("http_headers", {})
        if headers_data:
            summary["web_security"] = {
                "total_issues": headers_data.get("total_issues", 0),
                "domains_checked": list(headers_data.get("results", {}).keys()),
            }
            for domain, data in headers_data.get("results", {}).items():
                summary["web_security"][domain] = {
                    "missing_headers": data.get("missing_headers", []),
                    "info_leaks": [l.get("header") for l in data.get("info_leaks", [])],
                    "issues_count": len(data.get("issues", [])),
                }

        # Vulnerability summary
        vuln_data = assessment.get("vuln_check", {})
        if vuln_data:
            summary["vulnerabilities"] = {
                "total_findings": len(vuln_data.get("findings", [])),
                "severity_counts": vuln_data.get("summary", {}).get("severity_counts", {}),
                "findings": [
                    {
                        "id": f.get("id"),
                        "severity": f.get("severity"),
                        "detail": f.get("detail"),
                        "host": f.get("host"),
                    }
                    for f in vuln_data.get("findings", [])[:20]
                ],
            }

        # Domain security summary
        domain_data = assessment.get("domain_security", {})
        if domain_data:
            summary["domain_security"] = {}
            for domain, data in domain_data.get("results", {}).items():
                summary["domain_security"][domain] = {
                    "spf": data.get("spf", {}).get("exists", False),
                    "dmarc": data.get("dmarc", {}).get("exists", False),
                    "dmarc_policy": data.get("dmarc", {}).get("policy"),
                    "dkim_found": len(data.get("dkim", {}).get("found_selectors", [])),
                    "dnssec": data.get("dnssec", {}).get("enabled", False),
                    "caa": data.get("caa", {}).get("exists", False),
                    "issues_count": len(data.get("issues", [])),
                }

        # Certificate summary
        cert_data = assessment.get("whois_cert", {})
        if cert_data:
            summary["certificates"] = {}
            for domain, data in cert_data.get("certificates", {}).items():
                summary["certificates"][domain] = {
                    "days_until_expiry": data.get("days_until_expiry"),
                    "issuer": data.get("issuer", {}).get("organizationName") if isinstance(data.get("issuer"), dict) else None,
                    "protocol": data.get("protocol"),
                    "key_algorithm": data.get("key_info", {}).get("algorithm"),
                    "key_size": data.get("key_info", {}).get("key_size"),
                }

        return summary

    def _generate_basic_analysis(self, assessment: dict, diff: Optional[dict]) -> dict:
        """Generate basic predefined analysis when no LLM is available."""
        summary = self._summarize_assessment(assessment)

        # Calculate basic risk score
        risk_score = 20  # Base score
        issues = []
        recommendations = []

        # Check vulnerabilities
        vuln_summary = summary.get("vulnerabilities", {})
        severity_counts = vuln_summary.get("severity_counts", {})
        risk_score += severity_counts.get("critical", 0) * 20
        risk_score += severity_counts.get("high", 0) * 10
        risk_score += severity_counts.get("medium", 0) * 5
        risk_score += severity_counts.get("low", 0) * 2

        for finding in vuln_summary.get("findings", []):
            issues.append(f"{finding.get('severity', 'info').upper()}: {finding.get('detail', 'Unknown finding')}")

        # Check web security
        web = summary.get("web_security", {})
        if web.get("total_issues", 0) > 5:
            risk_score += 15
            recommendations.append({
                "category": "Web Security",
                "recommendation": "Multiple security headers are missing. Implement HSTS, CSP, X-Frame-Options, and other security headers.",
                "priority": "high",
            })

        # Check domain security
        for domain, ds in summary.get("domain_security", {}).items():
            if not ds.get("dmarc"):
                risk_score += 10
                recommendations.append({
                    "category": "Email Security",
                    "recommendation": f"Configure DMARC for {domain} to prevent email spoofing.",
                    "priority": "high",
                })
            if not ds.get("spf"):
                risk_score += 10
                recommendations.append({
                    "category": "Email Security",
                    "recommendation": f"Add SPF record for {domain}.",
                    "priority": "high",
                })
            if not ds.get("dnssec"):
                recommendations.append({
                    "category": "DNS Security",
                    "recommendation": f"Enable DNSSEC for {domain} to protect against DNS spoofing.",
                    "priority": "medium",
                })

        # Check certificates
        for domain, cert in summary.get("certificates", {}).items():
            days = cert.get("days_until_expiry")
            if days is not None and days < 30:
                risk_score += 15
                recommendations.append({
                    "category": "Certificates",
                    "recommendation": f"Certificate for {domain} expires in {days} days. Renew immediately.",
                    "priority": "critical",
                })

        # Check DNS
        dns_info = summary.get("dns", {})
        if dns_info.get("zone_transfer_possible"):
            risk_score += 25
            recommendations.append({
                "category": "DNS Security",
                "recommendation": "DNS zone transfer is allowed — restrict AXFR to authorized servers only.",
                "priority": "critical",
            })

        # Cap risk score
        risk_score = min(100, risk_score)

        # Determine rating
        if risk_score >= 80:
            risk_rating = "critical"
        elif risk_score >= 60:
            risk_rating = "high"
        elif risk_score >= 40:
            risk_rating = "medium"
        else:
            risk_rating = "low"

        # Build executive summary
        network = summary.get("network", {})
        exec_summary = (
            f"This assessment scanned {network.get('hosts_found', 0)} hosts and discovered "
            f"{network.get('total_open_ports', 0)} open ports. "
            f"{dns_info.get('subdomains_found', 0)} subdomains were enumerated. "
            f"The overall risk score is {risk_score}/100 ({risk_rating}).\n\n"
        )

        if severity_counts.get("critical", 0) > 0:
            exec_summary += (
                f"CRITICAL: {severity_counts['critical']} critical vulnerabilities were found "
                f"that require immediate attention. "
            )

        if web.get("total_issues", 0) > 0:
            exec_summary += (
                f"Web security analysis found {web['total_issues']} header-related issues "
                f"across the assessed domains. "
            )

        if diff and diff.get("summary", {}).get("has_changes"):
            ds = diff["summary"]
            exec_summary += (
                f"\n\nCompared to the previous assessment: {ds.get('total_new', 0)} new findings, "
                f"{ds.get('total_removed', 0)} resolved, {ds.get('total_changed', 0)} changed."
            )

        # Priority actions
        priority_actions = []
        prio = 1
        for rec in sorted(recommendations, key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["priority"], 4)):
            priority_actions.append({
                "priority": prio,
                "action": rec["recommendation"],
                "effort": "medium",
                "impact": f"Addresses {rec['priority']} severity finding",
            })
            prio += 1
            if prio > 10:
                break

        return {
            "executive_summary": exec_summary,
            "risk_score": risk_score,
            "risk_rating": risk_rating,
            "top_risks": issues[:10],
            "priority_actions": priority_actions,
            "findings_analysis": {
                "network": f"Found {network.get('hosts_found', 0)} hosts with {network.get('total_open_ports', 0)} open ports",
                "web_security": f"Found {web.get('total_issues', 0)} security header issues",
                "email_security": "See domain security section for SPF/DKIM/DMARC status",
                "certificates": f"Analyzed certificates for {len(summary.get('certificates', {}))} domains",
                "vulnerabilities": f"Discovered {vuln_summary.get('total_findings', 0)} vulnerability findings",
            },
            "recommendations": recommendations,
            "llm_generated": False,
        }
