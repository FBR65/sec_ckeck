# Security Testing Environment

This directory contains a comprehensive testing environment for the security testing agent using Docker containers with intentionally vulnerable services.

## Test Environment Setup

### 1. Start Test Environment
```bash
cd test
docker-compose up -d
```

### 2. Verify Services
```bash
docker-compose ps
```

### 3. Run Security Tests
```bash
python test_scenarios.py
```

## Available Test Targets

| Service | Port | Description | Vulnerabilities |
|---------|------|-------------|----------------|
| DVWA | 8080 | Damn Vulnerable Web App | SQL Injection, XSS, CSRF |
| WebGoat | 8081 | OWASP WebGoat | Multiple OWASP Top 10 |
| Apache | 8082 | Vulnerable Apache/PHP | File Inclusion, Info Disclosure |
| Nginx | 8083 | Older Nginx version | Configuration issues |
| SSH | 2222 | Weak SSH config | Weak passwords, old protocols |
| FTP | 21 | Anonymous FTP | Weak authentication |
| MySQL | 3306 | Default credentials | Weak passwords, no encryption |
| Redis | 6379 | No authentication | No auth, command injection |
| MongoDB | 27017 | No authentication | No auth, injection |

## Manual Testing Commands

### Basic Vulnerability Scan
```bash
python ../run_direct.py scan 127.0.0.1 --debug
```

### Test Web Applications
```bash
# Test DVWA
python ../run_direct.py scan 127.0.0.1:8080

# Test WebGoat  
python ../run_direct.py scan 127.0.0.1:8081
```

### Test Database Services
```bash
# Test MySQL
python ../run_direct.py scan 127.0.0.1:3306

# Test Redis
python ../run_direct.py scan 127.0.0.1:6379
```

## Automated Test Suite

The `test_scenarios.py` script provides:
- Comprehensive port scanning
- Vulnerability identification
- CVE database testing
- Web application security testing
- Database security assessment
- Automated reporting

## Safety Notes

⚠️ **WARNING**: These containers contain intentionally vulnerable services!

- Only run in isolated test environments
- Never expose these services to public networks
- Shut down containers after testing
- Use only for authorized security testing

## Cleanup

```bash
# Stop all containers
docker-compose down

# Remove containers and volumes
docker-compose down -v

# Remove images (optional)
docker-compose down --rmi all
```
