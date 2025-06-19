# Automated IT Security Testing Agent

An advanced security testing tool built with PydanticAI Agents and MCP (Model Context Protocol) for automated vulnerability assessment, ethical hacking, and security reporting.

## Features

- **Vulnerability Scanning**: Comprehensive port scanning and service detection
- **CVE Database Integration**: Multi-source CVE intelligence from CVE.org, NVD, and fallback APIs
- **Ethical Exploitation**: Safe exploitation testing with detailed reporting
- **AI-Powered Analysis**: Ollama-powered security analysis and recommendations
- **Comprehensive Reporting**: JSON, HTML, and text report generation
- **MCP Integration**: Extensible tool architecture using Model Context Protocol

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment:
```bash
# Copy and edit the .env file
cp .env .env.backup
# Edit .env with your settings
```

3. Start Ollama (if not already running):
```bash
ollama serve
ollama pull qwen2.5-coder:latest
```

## Usage

### Using Direct Runner (Recommended)
```bash
cd c:\Users\frank\Documents\py_projects\dev\sec_ckeck

# Basic vulnerability scan
python run_direct.py scan 192.168.1.100

# CVE lookup
python run_direct.py cve-lookup CVE-2021-44228

# Search CVEs by product
python run_direct.py search-cves "Apache Traffic Server" --debug

# Search by keyword
python run_direct.py search-keyword "traffic server"
```

### Using Package Installation
```bash
pip install -e .
sec-check scan 192.168.1.100 --exploit
```

### Command Examples

#### Basic Vulnerability Scan
```bash
python run_direct.py scan 192.168.1.100
```

#### Scan with Ethical Exploitation (requires ETHICAL_HACKING_MODE=true)
```bash
python run_direct.py scan 192.168.1.100 --exploit
```

#### CVE Lookup
```bash
python run_direct.py cve-lookup CVE-2025-31698
```

#### Search CVEs by Product with Debug
```bash
python run_direct.py search-cves "Apache HTTP Server" --version "2.4" --debug
```

#### Search CVEs by Keyword
```bash
python run_direct.py search-keyword "apache traffic server"
```

#### View Configuration
```bash
python run_direct.py config-show
```

#### Test CVE.org Integration
```bash
python run_direct.py test-cve-org
```

#### Debug CVE APIs
```bash
python run_direct.py debug-cve-api
```

## Architecture

### Core Components

1. **Security Agent** (`agents/security_agent.py`): Main PydanticAI agent coordinating security operations
2. **Vulnerability Scanner** (`tools/vulnerability_scanner.py`): Network and service vulnerability scanning
3. **CVE Database** (`tools/cve_database.py`): Multi-source CVE intelligence gathering and analysis
4. **Exploit Engine** (`tools/exploit_engine.py`): Ethical exploitation and penetration testing
5. **Report Generator** (`tools/report_generator.py`): Multi-format security report generation

### CVE Data Sources

The tool integrates with multiple CVE data sources:
1. **CVE.org** (Primary): Official CVE records and search
2. **NVD** (Secondary): NIST National Vulnerability Database
3. **CVE.circl.lu** (Fallback): Alternative CVE database

### Security Models

The tool uses Pydantic models for type-safe security data handling:
- `Vulnerability`: Individual security findings
- `CVEInfo`: CVE database information
- `ExploitResult`: Exploitation attempt results
- `SecurityReport`: Comprehensive assessment reports

## Configuration

### Environment Variables (.env file)

```bash
# LLM Configuration (Ollama)
LLM_ENDPOINT=http://localhost:11434/v1
LLM_API_KEY=ollama
LLM_MODEL_NAME=qwen2.5-coder:latest

# CVE Database Configuration
CVE_API_URL=https://cve.circl.lu/api
CVE_ORG_API=https://cveawg.mitre.org/api
NVD_API_KEY=

# Security Testing Configuration
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300
ETHICAL_HACKING_MODE=false

# Reporting Configuration
REPORT_OUTPUT_DIR=./reports
```

### LLM Configuration

The tool uses PydanticAI with OpenAI-compatible providers:
- **LLM_ENDPOINT**: Ollama API endpoint (default: http://localhost:11434/v1)
- **LLM_API_KEY**: API key for authentication (default: "ollama")
- **LLM_MODEL_NAME**: Model to use (default: qwen2.5-coder:latest)

### CVE API Configuration

- **CVE_API_URL**: Fallback CVE API endpoint
- **CVE_ORG_API**: CVE.org MITRE API endpoint
- **NVD_API_KEY**: Optional NVD API key for enhanced access and rate limits

### Ethical Hacking Mode

Set `ETHICAL_HACKING_MODE=true` to enable exploitation features. This should only be used:
- On systems you own or have explicit permission to test
- In isolated lab environments
- For educational and security research purposes

## Report Formats

The tool generates reports in multiple formats:

1. **JSON**: Machine-readable format for integration
2. **HTML**: Web-friendly format with styling
3. **TXT**: Plain text format for terminal viewing

## Prerequisites

### Ollama Setup
1. Install Ollama from https://ollama.ai
2. Start Ollama service: `ollama serve`
3. Pull required model: `ollama pull qwen2.5-coder:latest`
4. Verify endpoint is accessible at http://localhost:11434

### Python Dependencies
- Python 3.8+
- PydanticAI with OpenAI provider support
- Rich for CLI formatting
- Typer for command-line interface
- python-nmap for network scanning
- BeautifulSoup4 for web scraping
- httpx for async HTTP requests

### Optional: NVD API Key
Get a free API key from https://nvd.nist.gov/developers/request-an-api-key for:
- Higher rate limits
- More reliable CVE data access
- Enhanced search capabilities

## Safety and Legal Considerations

⚠️ **IMPORTANT**: This tool is designed for ethical security testing only.

- Only use on systems you own or have explicit written permission to test
- Respect applicable laws and regulations
- Follow responsible disclosure practices
- Use in isolated environments when possible
- Keep exploitation modules disabled unless specifically needed

## Troubleshooting

### Common Issues

1. **Module Import Errors**: Use `run_direct.py` instead of package imports
2. **Ollama Connection**: Ensure Ollama is running on http://localhost:11434
3. **Model Not Found**: Pull the required model with `ollama pull llama3.1`
4. **Permission Errors**: Run scans only on authorized systems
5. **CVE Search Issues**: Use debug mode to see which APIs are being tried
6. **Rate Limiting**: Consider getting an NVD API key for better access

### Debug Commands

```bash
# Test Ollama connection
curl http://localhost:11434/v1/models

# Check configuration
python run_direct.py config-show

# Test CVE lookup with specific CVE
python run_direct.py cve-lookup CVE-2021-44228

# Debug CVE API connectivity
python run_direct.py debug-cve-api

# Test CVE.org integration
python run_direct.py test-cve-org

# Search with debug output
python run_direct.py search-cves "Apache" --debug
```

### CVE Search Tips

- Use specific product names: "Apache HTTP Server" vs "Apache"
- Try different variations if no results found
- Use keyword search for broader results
- Enable debug mode to see which APIs are responding
- Some CVEs may not be immediately available in all databases

## Integration with Other Tools

The tool can be integrated with:
- CI/CD pipelines for automated security testing
- SIEM systems for vulnerability management
- Ticketing systems for remediation tracking
- Custom dashboards via JSON API output
- Security orchestration platforms


## License

This project is licensed under the AGPLv3 License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before testing any systems.
