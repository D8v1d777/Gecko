# 🦎 Gecko Apocalypse Engine v10.0

**Gecko Apocalypse** is a professional, high-performance Vulnerability Assessment and Penetration Testing Framework. Designed to provide industrial-grade offensive security capabilities, it leverages asynchronous architecture to perform rapid, comprehensive scanning across modern web applications, cloud infrastructure, and APIs.

## 🚀 Features

*   **Massive Modular Arsenal**: Includes over 20 specialized attack modules targeting everything from classic SQLi/XSS to modern cloud vulnerabilities and business logic flaws.
    *   **Modern Web**: GraphQL fuzzing, JWT manipulation, CORS misconfiguration, WebSocket hijacking.
    *   **Cloud Native**: AWS/GCP/Azure metadata probing, S3/Blob public exposure checks, Kubernetes and Docker registry enumeration.
    *   **Business Logic**: Race condition detection, price manipulation, privilege escalation, and workflow bypass testing.
    *   **Advanced Recon**: Subdomain enumeration, DNS analysis, GitHub leak detection, and Wayback Machine correlation.
*   **Real-Time Web Dashboard**: Monitor live scan progress, view statistics, and review findings in real-time through the built-in FastAPI/WebSockets dashboard.
*   **Comprehensive Reporting**: Generate detailed executive and technical reports in multiple formats (HTML, PDF, JSON, Markdown). Findings are automatically mapped to **CVSS v3.1**, **CWE**, and the **OWASP Top 10**.
*   **Extensible Plugin System**: Easily create and load custom modules via the dynamic plugin loader without modifying the core orchestrator.
*   **Session Resumption**: Built-in SQLite persistence allows you to pause and resume long-running scans with checkpointing.
*   **Alerts & Notifications**: Automatic integration with Slack and Discord webhooks to alert teams immediately upon discovering Critical vulnerabilities.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/D8v1d777/Gecko.git
cd Gecko

# Install requirements
pip install -r requirements.txt
```

## 💻 Usage

Gecko Apocalypse provides a highly configurable Command Line Interface (CLI).

```bash
# Basic scan against a target
python gecko_apocalypse.py https://example.com

# Run a scan and output reports in HTML and JSON
python gecko_apocalypse.py https://example.com -o html json

# Run only specific modules (e.g., API fuzzing and Cloud hunting)
python gecko_apocalypse.py https://example.com --modules api_fuzzing cloud_hunter

# Route traffic through a local proxy (e.g., Burp Suite) and use 50 threads
python gecko_apocalypse.py https://example.com --proxy http://127.0.0.1:8080 -t 50
```

### Display available modules:
```bash
python gecko_apocalypse.py --list-modules
```

## ⚙️ Configuration

The framework is highly customizable via `config/config.yaml`. You can enable/disable modules, set target scopes, specify authentication tokens for APIs (Shodan, GitHub, HaveIBeenPwned), and configure proxy routing. 

## ⚖️ Legal Disclaimer

**For Authorized Security Testing Only.**

This tool is designed exclusively for security professionals, penetration testers, and researchers to assess the security of systems they have explicit, written permission to test. Unauthorized access to computer systems or networks is illegal. The authors and contributors are not responsible for any misuse, damage, or legal consequences resulting from the use of this software.