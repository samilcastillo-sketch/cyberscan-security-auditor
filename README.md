# CyberScan - Security Headers & Web Posture Audit Engine

High-performance web security auditing service and interactive dashboard. Evaluates HTTP security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, etc.), detects missing defenses against XSS, Clickjacking, and MITM attacks, and calculates a security posture score (A+ to F) with remediation guidance.

## Key Features

- **Automated Header Auditing:** Evaluates critical HTTP response headers with weighted scoring.
- **Security Grading Matrix:** Computes compliance scores (0-100) and assigns grades from A+ to F.
- **Actionable Remediation:** Provides exact header configuration directives for missing security headers.
- **RESTful API:** Audit endpoints via `GET /api/v1/scan?url=<target>`.
- **Interactive Web Dashboard:** Clean UI to inspect target posture in real-time.
- **Zero Third-Party Dependencies:** Built on pure Python standard library and lightweight HTML5/CSS3.

## Quickstart

```bash
# Run locally
python3 -m src.server
```

Open `http://localhost:5005` in your browser.

## Running Tests

```bash
python3 -m unittest discover tests -v
```

## Docker Deployment

```bash
docker-compose up --build -d
```
