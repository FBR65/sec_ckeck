from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class SecurityConfig(BaseSettings):
    # LLM Configuration
    llm_endpoint: str = Field(
        default="http://localhost:11434/v1", description="LLM API endpoint"
    )
    llm_api_key: str = Field(default="ollama", description="LLM API key")
    llm_model_name: str = Field(
        default="qwen2.5-coder:latest", description="LLM model name"
    )

    # CVE Database Configuration
    cve_api_url: str = Field(
        default="https://cve.circl.lu/api",
        description="CVE database API URL (fallback)",
    )
    cve_org_api: str = Field(
        default="https://cveawg.mitre.org/api", description="CVE.org API endpoint"
    )
    nvd_api_key: Optional[str] = Field(
        default=None, description="NVD API key for enhanced access"
    )

    # Security Testing Configuration
    max_concurrent_scans: int = Field(
        default=5, description="Maximum concurrent vulnerability scans"
    )
    scan_timeout: int = Field(default=300, description="Scan timeout in seconds")
    ethical_hacking_mode: bool = Field(
        default=False, description="Enable ethical hacking features"
    )

    # Reporting Configuration
    report_output_dir: str = Field(
        default="./reports", description="Directory for security reports"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


config = SecurityConfig()
