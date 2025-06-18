from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"


class CVEInfo(BaseModel):
    cve_id: str = Field(..., description="CVE identifier")
    description: str = Field(..., description="Vulnerability description")
    severity: SeverityLevel = Field(..., description="CVSS severity level")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    published_date: Optional[datetime] = Field(None, description="CVE publication date")
    affected_products: List[str] = Field(
        default=[], description="List of affected products/services"
    )


class Vulnerability(BaseModel):
    id: str = Field(..., description="Unique vulnerability identifier")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    severity: SeverityLevel = Field(..., description="Vulnerability severity")
    cve_info: Optional[CVEInfo] = Field(None, description="Related CVE information")
    target_host: str = Field(..., description="Target host/IP")
    target_port: Optional[int] = Field(None, description="Target port")
    service: Optional[str] = Field(None, description="Affected service")
    status: VulnerabilityStatus = Field(default=VulnerabilityStatus.OPEN)
    discovered_at: datetime = Field(default_factory=datetime.now)
    proof_of_concept: Optional[str] = Field(
        None, description="PoC or exploitation details"
    )


class ExploitResult(BaseModel):
    vulnerability_id: str = Field(..., description="Related vulnerability ID")
    success: bool = Field(..., description="Exploitation success status")
    technique: str = Field(..., description="Exploitation technique used")
    evidence: List[str] = Field(
        default=[], description="Evidence of successful exploitation"
    )
    impact_assessment: str = Field(..., description="Assessment of potential impact")
    executed_at: datetime = Field(default_factory=datetime.now)


class RemediationStep(BaseModel):
    step_number: int = Field(..., description="Remediation step number")
    description: str = Field(..., description="Step description")
    priority: SeverityLevel = Field(..., description="Step priority")
    estimated_effort: str = Field(..., description="Estimated effort/time")


class SecurityReport(BaseModel):
    report_id: str = Field(..., description="Unique report identifier")
    target: str = Field(..., description="Scan target")
    scan_type: str = Field(..., description="Type of security scan")
    start_time: datetime = Field(..., description="Scan start time")
    end_time: Optional[datetime] = Field(None, description="Scan end time")
    vulnerabilities: List[Vulnerability] = Field(
        default=[], description="Found vulnerabilities"
    )
    exploit_results: List[ExploitResult] = Field(
        default=[], description="Exploitation results"
    )
    remediation_steps: List[RemediationStep] = Field(
        default=[], description="Remediation guidance"
    )
    executive_summary: str = Field(..., description="Executive summary")
    risk_score: float = Field(..., description="Overall risk score")
