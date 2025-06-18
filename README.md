# Automated IT Security Testing Agent

An advanced security testing tool built with PydanticAI Agents and MCP (Model Context Protocol) for automated vulnerability assessment, ethical hacking, and security reporting.

## Features

- **Vulnerability Scanning**: Comprehensive port scanning and service detection
- **CVE Database Integration**: Real-time vulnerability intelligence from CVE databases
- **Ethical Exploitation**: Safe exploitation testing with detailed reporting
- **AI-Powered Analysis**: Ollama-powered security analysis and recommendations
- **Comprehensive Reporting**: JSON, HTML, and text report generation
- **MCP Integration**: Extensible tool architecture using Model Context Protocol

## Installation

1. Install dependencies:
```bash
uv pip install -r requirements.txt
```

2. Configure environment:
```bash
cp .env .env.example
# Edit .env with your settings
```

3. Start Ollama (if not already running):
```bash
ollama serve
ollama pull llama3.1
```

## Usage

### Using Direct Runner (Recommended)
```bash
cd c:\Users\frank\Documents\py_projects\dev\sec_ckeck
python run_direct.py scan 192.168.1.100
python run_direct.py cve-lookup CVE-2021-44228
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

#### Scan with Ethical Exploitation
```bash
python run_direct.py scan 192.168.1.100 --exploit
```

#### CVE Lookup
```bash
python run_direct.py cve-lookup CVE-2021-44228
```

#### Search CVEs by Product
```bash
python run_direct.py search-cves "Apache HTTP Server" --version "2.4"
```

#### View Configuration
```bash
python run_direct.py config-show
```

## Architecture

### Core Components

1. **Security Agent** (`agents/security_agent.py`): Main PydanticAI agent coordinating security operations
2. **Vulnerability Scanner** (`tools/vulnerability_scanner.py`): Network and service vulnerability scanning
3. **CVE Database** (`tools/cve_database.py`): CVE intelligence gathering and analysis
4. **Exploit Engine** (`tools/exploit_engine.py`): Ethical exploitation and penetration testing
5. **Report Generator** (`tools/report_generator.py`): Multi-format security report generation

### Security Models

The tool uses Pydantic models for type-safe security data handling:
- `Vulnerability`: Individual security findings
- `CVEInfo`: CVE database information
- `ExploitResult`: Exploitation attempt results
- `SecurityReport`: Comprehensive assessment reports

## Configuration

### Environment Variables (.env file)

```bash
# LLM Configuration
LLM_ENDPOINT=http://localhost:11434/v1
LLM_API_KEY=ollama
LLM_MODEL_NAME=qwen2.5-coder:latest

# CVE Database Configuration
CVE_API_URL=https://cve.circl.lu/api
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
- **LLM_MODEL_NAME**: Model to use (default: llama3.1)

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
3. Pull required model: `ollama pull llama3.1`
4. Verify endpoint is accessible at http://localhost:11434

### Python Dependencies
- Python 3.8+
- PydanticAI with OpenAI provider support
- Rich for CLI formatting
- Typer for command-line interface
- nmap for network scanning

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

### Debug Commands

```bash
# Test Ollama connection
curl http://localhost:11434/v1/models

# Check configuration
python run_direct.py config-show

# Test CVE lookup
python run_direct.py cve-lookup CVE-2021-44228
```

## Integration with Other Tools

The tool can be integrated with:
- CI/CD pipelines for automated security testing
- SIEM systems for vulnerability management
- Ticketing systems for remediation tracking
- Custom dashboards via JSON API output


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before testing any systems.
