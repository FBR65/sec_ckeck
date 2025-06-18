import json
import os
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Template
import aiofiles

from sec_ckeck.models.security_models import (
    SecurityReport,
    Vulnerability,
    SeverityLevel,
    RemediationStep,
)
from sec_ckeck.config import config


class ReportGenerator:
    def __init__(self):
        self.output_dir = config.report_output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    async def generate(self, report: SecurityReport) -> str:
        """Generate comprehensive security report."""
        # Calculate risk metrics
        report.risk_score = self._calculate_risk_score(report.vulnerabilities)
        report.end_time = datetime.now()

        # Generate executive summary
        report.executive_summary = self._generate_executive_summary(report)

        # Generate remediation steps
        report.remediation_steps = self._generate_remediation_steps(
            report.vulnerabilities
        )

        # Generate reports in multiple formats
        json_report = await self._generate_json_report(report)
        html_report = await self._generate_html_report(report)
        text_report = await self._generate_text_report(report)

        return f"Reports generated:\n- JSON: {json_report}\n- HTML: {html_report}\n- Text: {text_report}"

    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall risk score based on vulnerabilities."""
        if not vulnerabilities:
            return 0.0

        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0,
        }

        total_score = sum(
            severity_weights.get(vuln.severity, 1.0) for vuln in vulnerabilities
        )
        max_possible = len(vulnerabilities) * 10.0

        return min((total_score / max_possible) * 100, 100.0)

    def _generate_executive_summary(self, report: SecurityReport) -> str:
        """Generate executive summary."""
        vuln_counts = self._count_vulnerabilities_by_severity(report.vulnerabilities)

        summary = f"""
Security Assessment Summary for {report.target}

Assessment Period: {report.start_time.strftime("%Y-%m-%d %H:%M")} - {report.end_time.strftime("%Y-%m-%d %H:%M") if report.end_time else "In Progress"}

Risk Score: {report.risk_score:.1f}/100

Vulnerability Summary:
- Critical: {vuln_counts.get(SeverityLevel.CRITICAL, 0)}
- High: {vuln_counts.get(SeverityLevel.HIGH, 0)}
- Medium: {vuln_counts.get(SeverityLevel.MEDIUM, 0)}
- Low: {vuln_counts.get(SeverityLevel.LOW, 0)}
- Info: {vuln_counts.get(SeverityLevel.INFO, 0)}

Key Findings:
{self._generate_key_findings(report.vulnerabilities)}

Immediate Actions Required:
{self._generate_immediate_actions(report.vulnerabilities)}
        """.strip()

        return summary

    def _generate_key_findings(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate key findings from vulnerabilities."""
        findings = []

        critical_high = [
            v
            for v in vulnerabilities
            if v.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]

        if critical_high:
            findings.append(
                f"• {len(critical_high)} critical/high severity vulnerabilities require immediate attention"
            )

        services = set(v.service for v in vulnerabilities if v.service)
        if services:
            findings.append(f"• Affected services: {', '.join(services)}")

        cve_count = len([v for v in vulnerabilities if v.cve_info])
        if cve_count:
            findings.append(f"• {cve_count} vulnerabilities linked to known CVEs")

        return (
            "\n".join(findings)
            if findings
            else "• No significant security issues identified"
        )

    def _generate_immediate_actions(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate immediate action items."""
        actions = []

        critical = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        if critical:
            actions.append("• Apply critical security patches immediately")

        high = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        if high:
            actions.append("• Schedule high-priority patching within 48 hours")

        exposed_services = [
            v
            for v in vulnerabilities
            if "exposed" in v.title.lower() or "open" in v.title.lower()
        ]
        if exposed_services:
            actions.append("• Review and restrict network access to exposed services")

        return (
            "\n".join(actions)
            if actions
            else "• Continue monitoring and maintain current security posture"
        )

    def _generate_remediation_steps(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[RemediationStep]:
        """Generate prioritized remediation steps."""
        steps = []
        step_num = 1

        # Critical vulnerabilities first
        critical_vulns = [
            v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL
        ]
        for vuln in critical_vulns:
            steps.append(
                RemediationStep(
                    step_number=step_num,
                    description=f"Address critical vulnerability: {vuln.title}",
                    priority=SeverityLevel.CRITICAL,
                    estimated_effort="Immediate (0-4 hours)",
                )
            )
            step_num += 1

        # High severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        for vuln in high_vulns:
            steps.append(
                RemediationStep(
                    step_number=step_num,
                    description=f"Patch high-severity issue: {vuln.title}",
                    priority=SeverityLevel.HIGH,
                    estimated_effort="Urgent (4-24 hours)",
                )
            )
            step_num += 1

        # General security improvements
        if vulnerabilities:
            steps.append(
                RemediationStep(
                    step_number=step_num,
                    description="Implement security monitoring and alerting",
                    priority=SeverityLevel.MEDIUM,
                    estimated_effort="1-2 weeks",
                )
            )
            step_num += 1

            steps.append(
                RemediationStep(
                    step_number=step_num,
                    description="Schedule regular security assessments",
                    priority=SeverityLevel.LOW,
                    estimated_effort="Ongoing",
                )
            )

        return steps

    def _count_vulnerabilities_by_severity(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[SeverityLevel, int]:
        """Count vulnerabilities by severity level."""
        counts = {}
        for vuln in vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts

    async def _generate_json_report(self, report: SecurityReport) -> str:
        """Generate JSON format report."""
        filename = f"{self.output_dir}/{report.report_id}.json"

        # Convert to dict for JSON serialization
        report_dict = {
            "report_id": report.report_id,
            "target": report.target,
            "scan_type": report.scan_type,
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat() if report.end_time else None,
            "risk_score": report.risk_score,
            "executive_summary": report.executive_summary,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity.value,
                    "target_host": v.target_host,
                    "target_port": v.target_port,
                    "service": v.service,
                    "status": v.status.value,
                    "discovered_at": v.discovered_at.isoformat(),
                    "cve_info": {
                        "cve_id": v.cve_info.cve_id,
                        "description": v.cve_info.description,
                        "severity": v.cve_info.severity.value,
                        "cvss_score": v.cve_info.cvss_score,
                    }
                    if v.cve_info
                    else None,
                }
                for v in report.vulnerabilities
            ],
            "remediation_steps": [
                {
                    "step_number": step.step_number,
                    "description": step.description,
                    "priority": step.priority.value,
                    "estimated_effort": step.estimated_effort,
                }
                for step in report.remediation_steps
            ],
        }

        async with aiofiles.open(filename, "w") as f:
            await f.write(json.dumps(report_dict, indent=2))

        return filename

    async def _generate_html_report(self, report: SecurityReport) -> str:
        """Generate HTML format report."""
        filename = f"{self.output_dir}/{report.report_id}.html"

        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {{ report.target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; font-weight: bold; }
        .severity-low { color: #388e3c; font-weight: bold; }
        .severity-info { color: #1976d2; font-weight: bold; }
        .vulnerability { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }
        .risk-score { font-size: 24px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {{ report.target }}</p>
        <p><strong>Report ID:</strong> {{ report.report_id }}</p>
        <p><strong>Generated:</strong> {{ report.end_time.strftime('%Y-%m-%d %H:%M:%S') if report.end_time else 'In Progress' }}</p>
        <p><strong>Risk Score:</strong> <span class="risk-score">{{ "%.1f"|format(report.risk_score) }}/100</span></p>
    </div>
    
    <h2>Executive Summary</h2>
    <pre>{{ report.executive_summary }}</pre>
    
    <h2>Vulnerabilities ({{ report.vulnerabilities|length }})</h2>
    {% for vuln in report.vulnerabilities %}
    <div class="vulnerability">
        <h3 class="severity-{{ vuln.severity.value }}">{{ vuln.title }} ({{ vuln.severity.value.upper() }})</h3>
        <p><strong>Host:</strong> {{ vuln.target_host }}{% if vuln.target_port %}:{{ vuln.target_port }}{% endif %}</p>
        <p><strong>Service:</strong> {{ vuln.service or 'Unknown' }}</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if vuln.cve_info %}
        <p><strong>CVE:</strong> {{ vuln.cve_info.cve_id }} (CVSS: {{ vuln.cve_info.cvss_score or 'N/A' }})</p>
        {% endif %}
    </div>
    {% endfor %}
    
    <h2>Remediation Steps</h2>
    <ol>
    {% for step in report.remediation_steps %}
        <li class="severity-{{ step.priority.value }}">
            <strong>{{ step.description }}</strong><br>
            Priority: {{ step.priority.value.upper() }} | Estimated Effort: {{ step.estimated_effort }}
        </li>
    {% endfor %}
    </ol>
</body>
</html>
        """

        template = Template(html_template)
        html_content = template.render(report=report)

        async with aiofiles.open(filename, "w") as f:
            await f.write(html_content)

        return filename

    async def _generate_text_report(self, report: SecurityReport) -> str:
        """Generate plain text format report."""
        filename = f"{self.output_dir}/{report.report_id}.txt"

        content = f"""
SECURITY ASSESSMENT REPORT
==========================

Target: {report.target}
Report ID: {report.report_id}
Generated: {report.end_time.strftime("%Y-%m-%d %H:%M:%S") if report.end_time else "In Progress"}
Risk Score: {report.risk_score:.1f}/100

EXECUTIVE SUMMARY
================
{report.executive_summary}

VULNERABILITIES ({len(report.vulnerabilities)})
==============
"""
        for i, vuln in enumerate(report.vulnerabilities, 1):
            content += f"""
{i}. {vuln.title} [{vuln.severity.value.upper()}]
   Host: {vuln.target_host}{":" + str(vuln.target_port) if vuln.target_port else ""}
   Service: {vuln.service or "Unknown"}
   Description: {vuln.description}
   {f"CVE: {vuln.cve_info.cve_id} (CVSS: {vuln.cve_info.cvss_score or 'N/A'})" if vuln.cve_info else ""}
"""

        content += """
REMEDIATION STEPS
================
"""
        for step in report.remediation_steps:
            content += f"""
{step.step_number}. {step.description}
   Priority: {step.priority.value.upper()}
   Estimated Effort: {step.estimated_effort}
"""

        async with aiofiles.open(filename, "w") as f:
            await f.write(content)

        return filename
