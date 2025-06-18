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
cp .env.example .env
# Edit .env with your settings
```

3. Start Ollama (if not already running):
```bash
ollama serve
ollama pull qwen2.5-coder:latest
```

## Usage

### Basic Vulnerability Scan
```bash
python -m sec_check scan 192.168.1.100
```

### Scan with Ethical Exploitation
```bash
python -m sec_check scan 192.168.1.100 --exploit
```

### CVE Lookup
```bash
python -m sec_check cve-lookup CVE-2021-44228
```

### Search CVEs by Product
```bash
python -m sec_check search-cves "Apache HTTP Server" --version "2.4"
```

### View Configuration
```bash
python -m sec_check config-show
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

### Environment Variables

- `OLLAMA_BASE_URL`: Ollama API endpoint (default: http://localhost:11434)
- `OLLAMA_MODEL`: LLM model to use (default: qwen2.5-coder)
- `ETHICAL_HACKING_MODE`: Enable/disable exploitation features (default: false)
- `NVD_API_KEY`: Optional NVD API key for enhanced CVE data
- `REPORT_OUTPUT_DIR`: Directory for generated reports (default: ./reports)

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

## Safety and Legal Considerations

⚠️ **IMPORTANT**: This tool is designed for ethical security testing only.

- Only use on systems you own or have explicit written permission to test
- Respect applicable laws and regulations
- Follow responsible disclosure practices
- Use in isolated environments when possible
- Keep exploitation modules disabled unless specifically needed

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
