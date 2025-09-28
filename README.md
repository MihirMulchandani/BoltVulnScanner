# ⚡ BoltVulnScanner

**Automated Web Vulnerability Scanner for Ethical Hackers and Security Researchers**

BoltVulnScanner is a comprehensive, single-user automated web vulnerability scanner designed for educational and authorized security testing. It combines a powerful CLI with an intuitive Streamlit web UI to detect common web vulnerabilities including XSS, SQLi, directory traversal, and more.

## 🌟 Key Features

- **Dual Interface**: Command-line interface (CLI) and Streamlit web UI
- **Modular Design**: 12+ security modules for comprehensive scanning
- **Safe-by-Default**: Active scanning requires explicit consent
- **Multiple Report Formats**: JSON, Markdown, PDF, and ZIP exports
- **Educational Focus**: Bug bounty-style reports with CVSS approximations
- **No Login/Database**: Single-user design with no authentication system
- **Docker Ready**: Containerized deployment for easy setup

## 🛠️ Scanner Modules

1. **Crawler** - Domain-limited crawler respecting robots.txt
2. **Ports** - TCP port scanner with configurable ranges
3. **XSS** - Reflected & stored XSS detection with Playwright validation
4. **SQLi** - Error-based, boolean-based, and time-based SQL injection
5. **TLS Check** - Certificate validation and weak protocol detection
6. **Headers** - Security header analysis (CSP, HSTS, etc.)
7. **Directory Enumeration** - File/folder discovery with wordlists
8. **Open Redirect** - Detection of open redirect vulnerabilities
9. **CSRF Check** - Missing CSRF token detection
10. **Traversal** - Directory traversal heuristics
11. **Subdomain** - Passive subdomain enumeration
12. **Command Injection** - Detection of command injection flaws

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/BoltVulnScanner.git
cd BoltVulnScanner

# Install dependencies
pip install -r requirements.txt

# For optional features (PDF reports, headless browser)
pip install -r requirements-optional.txt
```

### Using Poetry (Recommended)

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# For optional features
poetry install --extras "pdf headless tls"
```

## 🖥️ Usage

### Command Line Interface

```bash
# Run a basic scan
boltvulnscan scan --target http://example.com --checks xss,sqli

# Run a full active scan (requires consent)
boltvulnscan scan --target http://example.com --enable-active --confirm-legal "I CONSENT TO ACTIVE TESTS"

# Generate reports from previous scan
boltvulnscan report --input reports/scan_20231201_120000/report.json --format md,pdf

# Launch the web UI
boltvulnscan ui
```

### Web Interface

```bash
# Launch the Streamlit web UI
boltvulnscan ui
# or directly
streamlit run src/boltvuln/streamlit_app.py
```

## 📊 Sample Report

### Executive Summary

This scan identified **7** potential security issues, with **3** confirmed findings.

#### Severity Breakdown
- **CRITICAL**: 1
- **HIGH**: 2
- **MEDIUM**: 3
- **LOW**: 1
- **INFO**: 0

### Sample Finding

#### Missing Content-Security-Policy Header
- **ID**: HEADER-MISSING-CONTENTSECURITYPOLICY
- **Module**: headers
- **URL**: https://example.com/
- **Parameter**: content-security-policy
- **Severity**: HIGH
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N

##### Proof of Concept
```
Header 'content-security-policy' is missing from the response
```

##### Reproduction Steps
1. Send a request to https://example.com/
2. Check the response headers
3. Observe that the 'content-security-policy' header is missing

##### Impact
The Content-Security-Policy header helps prevent XSS and other injection attacks.

##### Recommended Fix
Implement a Content Security Policy that restricts sources for scripts, styles, and other content. Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

##### Suggested Bounty
$500-$2000

## ⚠️ Legal and Ethical Usage

### Important Disclaimers

1. **Authorized Testing Only**: This tool is for authorized security testing only. Unauthorized scanning is illegal.
2. **Educational Purpose**: Scores and CVSS vectors are approximations for educational purposes.
3. **Demo Limitations**: Demo scans use safe payloads and are non-destructive.
4. **Production Scoring**: Pentest-grade scoring requires professional tools and expertise.

### Consent Requirements

Active scanning requires explicit consent:
```bash
--confirm-legal "I CONSENT TO ACTIVE TESTS"
```

## 🐳 Docker Deployment

### Building the Image

```bash
docker build -t boltvulnscanner .
```

### Running with Docker

```bash
# Run a scan
docker run --rm -v $(pwd)/reports:/app/reports boltvulnscanner scan --target http://example.com

# Run with active consent
docker run --rm -v $(pwd)/reports:/app/reports boltvulnscanner scan --target http://example.com --enable-active --confirm-legal "I CONSENT TO ACTIVE TESTS"

# Launch the web UI
docker run --rm -p 8501:8501 boltvulnscanner ui
```

### Docker Compose

```bash
# Start with docker-compose
docker-compose up

# Run a scan
docker-compose run --rm scanner scan --target http://example.com
```

## 🧪 Testing

### Unit Tests

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=src tests/
```

### Integration Tests

```bash
# Run integration tests (requires CI_ALLOW_INTEGRATION=true)
CI_ALLOW_INTEGRATION=true pytest tests/integration/
```

## 📁 Project Structure

```
BoltVulnScanner/
├─ pyproject.toml
├─ requirements.txt
├─ requirements-optional.txt
├─ Dockerfile
├─ docker-compose.yml
├─ .github/workflows/ci.yml
├─ README.md
├─ LICENSE
├─ CONTRIBUTING.md
├─ .gitignore
├─ config.yaml
├─ creds.example.yaml
├─ push_to_github.sh
├─ src/boltvuln/
│  ├─ __init__.py
│  ├─ cli.py
│  ├─ streamlit_app.py
│  ├─ orchestrator.py
│  ├─ utils.py
│  ├─ crawler.py
│  ├─ ports.py
│  ├─ xss.py
│  ├─ sqli.py
│  ├─ tls_check.py
│  ├─ dir_enum.py
│  ├─ open_redirect.py
│  ├─ headers_check.py
│  ├─ csrf_check.py
│  ├─ traversal.py
│  ├─ subdomain_enum.py
│  ├─ cmd_injection.py
│  ├─ reporter.py
└─ demo/
   ├─ sample_target.html
   ├─ fixtures/
   ├─ sample_scan_output.json
   └─ sample_bug_report.md
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- Code style guidelines
- Testing requirements
- Pull request process
- Reporting issues

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security testing guidelines
- The Python security community for inspiration
- All contributors who help improve this tool

---

*Note: BoltVulnScanner is designed for educational and authorized security testing purposes. The vulnerability detection capabilities and scoring mechanisms are approximations. For production security assessments, always use professional tools and engage qualified security professionals.*