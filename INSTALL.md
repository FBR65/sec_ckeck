# Installation Guide

## Prerequisites

### Python Environment
- Python 3.8 or higher
- pip package manager

### Optional: Nmap (for advanced scanning)

#### Windows
1. Download from: https://nmap.org/download.html
2. Install the Windows installer
3. Add nmap to your PATH
4. Install Python wrapper: `pip install python-nmap`

#### Linux
```bash
# Ubuntu/Debian
sudo apt-get install nmap
pip install python-nmap

# CentOS/RHEL
sudo yum install nmap
pip install python-nmap
```

#### macOS
```bash
# Using Homebrew
brew install nmap
pip install python-nmap

# Using MacPorts
sudo port install nmap
pip install python-nmap
```

## Installation Steps

1. Clone or download the project
2. Create virtual environment:
```bash
python -m venv .venv
```

3. Activate virtual environment:
```bash
# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate
```

4. Install Python dependencies:
```bash
pip install -r requirements.txt
```

5. (Optional) Install nmap for advanced scanning:
```bash
pip install python-nmap
```

6. Configure environment:
```bash
cp .env .env.example
# Edit .env with your settings
```

## Verification

Test the installation:
```bash
python run_direct.py config-show
```

Test basic scanning (without nmap):
```bash
python run_direct.py scan 127.0.0.1
```

## Troubleshooting

### Nmap Issues
- **"nmap program was not found"**: Install nmap binary and add to PATH
- **Permission denied**: Run as administrator/sudo or scan non-privileged ports only
- **Firewall blocking**: Configure firewall to allow nmap traffic

### Network Issues
- **Connection refused**: Target host may be down or firewalled
- **Timeout errors**: Increase scan timeout in configuration
- **Rate limiting**: Reduce concurrent scans in configuration
