from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIModel
from typing import List, Dict, Any, Optional
import asyncio
import json
from datetime import datetime

from ..models.security_models import Vulnerability, SecurityReport, SeverityLevel
from ..config import config
from ..tools.vulnerability_scanner import VulnerabilityScanner
from ..tools.exploit_engine import ExploitEngine
from ..tools.cve_database import CVEDatabase
from ..tools.report_generator import ReportGenerator


class SecurityAgentDeps:
    def __init__(self):
        self.vuln_scanner = VulnerabilityScanner()
        self.exploit_engine = ExploitEngine()
        self.cve_database = CVEDatabase()
        self.report_generator = ReportGenerator()


# Configure Ollama as OpenAI-compatible model
model = OpenAIModel(
    "llama3.1",
    base_url=config.ollama_base_url,
    api_key="ollama",  # Ollama doesn't need real API key
)

security_agent = Agent(
    model,
    deps_type=SecurityAgentDeps,
    system_prompt="""You are an advanced IT security testing agent specializing in:
    1. Vulnerability assessment and CVE analysis
    2. Ethical penetration testing and exploitation
    3. Security reporting and remediation guidance
    
    You must:
    - Conduct thorough security assessments
    - Prioritize findings by risk level
    - Provide actionable remediation steps
    - Maintain ethical hacking principles
    - Generate comprehensive security reports
    
    Always verify findings and provide evidence-based recommendations.""",
)


@security_agent.tool
async def scan_vulnerabilities(
    ctx: RunContext[SecurityAgentDeps], target: str, scan_type: str = "comprehensive"
) -> List[Vulnerability]:
    """Scan target for vulnerabilities using various techniques."""
    return await ctx.deps.vuln_scanner.scan(target, scan_type)


@security_agent.tool
async def lookup_cve(ctx: RunContext[SecurityAgentDeps], cve_id: str) -> Dict[str, Any]:
    """Look up CVE information from database."""
    return await ctx.deps.cve_database.get_cve_info(cve_id)


@security_agent.tool
async def search_cves_by_product(
    ctx: RunContext[SecurityAgentDeps], product: str, version: str = None
) -> List[Dict[str, Any]]:
    """Search CVEs affecting specific product/version."""
    return await ctx.deps.cve_database.search_by_product(product, version)


@security_agent.tool
async def attempt_exploitation(
    ctx: RunContext[SecurityAgentDeps], vulnerability: Vulnerability
) -> Dict[str, Any]:
    """Attempt ethical exploitation of identified vulnerability."""
    if not config.ethical_hacking_mode:
        return {"error": "Ethical hacking mode disabled"}
    return await ctx.deps.exploit_engine.exploit(vulnerability)


@security_agent.tool
async def generate_security_report(
    ctx: RunContext[SecurityAgentDeps],
    vulnerabilities: List[Vulnerability],
    target: str,
) -> str:
    """Generate comprehensive security report."""
    report = SecurityReport(
        report_id=f"SEC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        target=target,
        scan_type="Automated Security Assessment",
        start_time=datetime.now(),
        vulnerabilities=vulnerabilities,
        executive_summary="",
        risk_score=0.0,
    )
    return await ctx.deps.report_generator.generate(report)


async def run_security_assessment(
    target: str, enable_exploitation: bool = False
) -> str:
    """Run complete security assessment on target."""

    prompt = f"""
    Conduct a comprehensive security assessment of target: {target}
    
    Steps to follow:
    1. Perform vulnerability scanning
    2. Analyze findings against CVE database
    3. {"Attempt ethical exploitation if vulnerabilities found" if enable_exploitation else "Skip exploitation phase"}
    4. Generate detailed security report with remediation guidance
    
    Provide detailed analysis and actionable recommendations.
    """

    result = await security_agent.run(prompt)
    return result.data
