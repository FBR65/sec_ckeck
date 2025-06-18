from pydantic import BaseSettings, Field
from typing import Optional


class SecurityConfig(BaseSettings):
    # Ollama Configuration
    ollama_base_url: str = Field(
        default="http://localhost:11434", description="Ollama API base URL"
    )
    ollama_model: str = Field(default="llama3.1", description="Ollama model to use")

    # CVE Database Configuration
    cve_api_url: str = Field(
        default="https://cve.circl.lu/api", description="CVE database API URL"
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
