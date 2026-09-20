# VAPT Platform

Automated Vulnerability Assessment & Reconnaissance Platform

A cybersecurity assessment tool for authorized security testing and professional portfolio demonstration.

## Overview

VAPT Platform is a complete, locally-run security assessment platform. It handles reconnaissance, network scanning, service enumeration, vulnerability correlation, findings management, severity classification, and report generation.

Built for cybersecurity professionals targeting VAPT, vulnerability assessment, application security, and security engineering roles.

## Features

- **Project & Target Management**: Create assessment projects, define authorized targets with IP/domain/hostname, configure allowed port ranges and exclusions
- **Host Discovery**: Identify reachable hosts, hostname resolution, MAC address and vendor detection, OS fingerprinting
- **Port Scanning**: Nmap TCP connect/SYN scanning with configurable port ranges, service detection, and version detection
- **Service Fingerprinting**: Identify service names, versions, and CPE identifiers
- **Vulnerability Correlation**: Map discovered services and versions against a curated local CVE database
- **Nmap NSE Integration**: Safe, curated set of non-exploitation NSE scripts (http-enum, http-title, http-methods, ssl-cert, smb-protocols, ssh2-enum-algos)
- **Security Findings Engine**: Normalized findings with title, host, port, service, category, severity, evidence, remediation, confidence, and status
- **False-Positive Handling**: Detection source tracking; confirmed, needs validation, false positive, and remediated states
- **Professional Dashboard**: Total hosts, open ports, services discovered, total findings, severity distribution, scan history
- **Report Generation**: HTML and PDF reports with executive summary, methodology, target inventory, findings, severity distribution, evidence, and remediation recommendations
- **REST API**: Clean endpoints for all resources (projects, targets, scans, hosts, findings, reports, dashboard)
- **Database**: SQLite persistence with parameterized operations
- **Structured Logging**: JSON format with audit logging for scan events and report generation
- **Security by Design**: Input validation, safe subprocess handling, no shell injection, environment variables for secrets, authorization/scope mechanism

## Architecture

```
vapt-platform/
├── backend/          # FastAPI application with API endpoints
├── database/         # SQLAlchemy/SQLModel models and persistence
├── scanner/          # Nmap integration with safety controls
├── vulnerability_engine/  # CVE correlation and findings engine
├── reports/          # PDF/HTML report generation
├── frontend/         # Dashboard (HTML/CSS/JS)
├── tests/            # Test suite
└── Dockerfile
```

## Technology Stack

- **Language**: Python 3.12+
- **Framework**: FastAPI
- **ORM**: SQLAlchemy 2.0 + SQLModel
- **Validation**: Pydantic 2.x
- **Scanner**: python-nmap with safety controls
- **Reporting**: WeasyPrint for PDF, Jinja2 for HTML
- **Testing**: pytest with async support
- **Logging**: structlog with JSON formatting
- **Container**: Docker

## Installation

### Local Installation

```bash
git clone https://github.com/om-panjwani/vapt-platform.git
cd vapt-platform

python3 -m venv .venv
source .venv/bin/activate

pip install -e .

cp .env.example .env

uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Docker Installation

```bash
docker build -t vapt-platform .
docker run -p 8000:8000 vapt-platform
```

## Configuration

Edit the `.env` file:

```
APP_NAME="VAPT Platform"
APP_VERSION="1.0.0"
DEBUG=false
SECRET_KEY="vapt-platform-secret-key-min-32-chars-for-development-only"

DATABASE_URL="sqlite+aiosqlite:///./data/vapt.db"
DATABASE_ECHO=false

NMAP_PATH="/usr/bin/nmap"
DEFAULT_SCAN_TIMEOUT=300
MAX_CONCURRENT_SCANS=3
ALLOWED_NSE_SCRIPTS="http-enum,http-title,http-methods,ssl-cert,smb-protocols,ssh2-enum-algos"

ALLOWED_HOSTS="localhost,127.0.0.1"
CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:8000"
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

REPORT_OUTPUT_DIR="./reports/output"
REPORT_TEMPLATE_DIR="./reports/templates"

LOG_LEVEL="INFO"
LOG_FORMAT="json"
LOG_FILE="./logs/vapt.log"
```

## API Endpoints

Base URL: `http://localhost:8000/api/v1/`

| Endpoint | Description |
|---|---|
| `GET /api/health` | Health check |
| `POST /api/v1/projects` | Create project |
| `GET /api/v1/projects` | List projects |
| `GET /api/v1/projects/{id}` | Get project details |
| `PATCH /api/v1/projects/{id}` | Update project |
| `DELETE /api/v1/projects/{id}` | Delete project |
| `POST /api/v1/projects/{id}/targets` | Create target |
| `GET /api/v1/projects/{id}/targets` | List targets |
| `POST /api/v1/projects/{id}/scans` | Create scan |
| `POST /api/v1/scans/{id}/start` | Start scan |
| `GET /api/v1/projects/{id}/findings` | List findings |
| `POST /api/v1/projects/{id}/reports` | Generate report |
| `GET /api/v1/reports/{id}/download` | Download report |

## Testing

```bash
pytest tests/test_core.py -v
pytest tests/test_api.py -v
pytest tests/test_scanner.py -v
pytest tests/test_vulnerability.py -v
```

```
28 of 31 core tests pass
3 tests fail due to nmap not being installed in test environment (expected)
```

## Limitations

1. Requires nmap installed on the system for network scanning
2. CVE database is local and not exhaustive; manual validation always required
3. PDF generation requires WeasyPrint dependencies (works best in Docker)
4. Only authorized targets within defined scope should be assessed
5. Automated detection may produce false positives
6. No exploitation or privilege escalation activities performed

## Security Disclaimer

This tool is designed for authorized security testing only. Only scan targets you have explicit permission to assess. Always define and respect the assessment scope. The developers are not responsible for misuse of this tool.

## License

MIT