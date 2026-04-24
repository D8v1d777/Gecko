# 🦎 Gecko Apocalypse Engine v10.0

**Gecko Apocalypse** is a professional, high-performance Vulnerability Assessment and Penetration Testing Framework. Designed to provide industrial-grade offensive security capabilities, it leverages asynchronous architecture to perform rapid, comprehensive scanning across modern web applications, cloud infrastructure, and APIs.

## 🚀 Features

*   **Massive Modular Arsenal**: Includes over 25 specialized attack modules targeting everything from classic SQLi/XSS to modern cloud vulnerabilities and business logic flaws.
    *   **Advanced Bug Bounty Modules**: Context-aware reflected XSS, Time/Error based SQLi, Advanced BOLA/IDOR detection, Open Redirects, and JWT alg:none testing.
    *   **Network & Web Correlation**: Enterprise-grade cross-layer security analysis using `bs4` and `scapy`. Detects missing CSRF, insecure external resources, DNS security issues, cleartext credentials, and performs raw packet crafting.
    *   **Modern Web**: GraphQL fuzzing, JWT manipulation, CORS misconfiguration, WebSocket hijacking.
    *   **Cloud Native**: AWS/GCP/Azure metadata probing, S3/Blob public exposure checks, Kubernetes and Docker registry enumeration.
    *   **Business Logic**: Race condition detection, price manipulation, privilege escalation, and workflow bypass testing.
    *   **Advanced Recon**: Subdomain enumeration, DNS analysis, GitHub leak detection, and Wayback Machine correlation.
*   **SPA-Aware Crawler**: Comprehensive crawler that extracts embedded JS bundle routes, discovers hidden API endpoints (`/api`, `/rest`), and parses HTML forms dynamically.
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

### Enterprise integration example
```python
from gecko.enterprise import EnterpriseOrchestrator, HTTPSmuggler

# Load config with vault integration
config = load_config_with_vault("config/enterprise.yaml")

# Initialize orchestrator
orchestrator = EnterpriseOrchestrator(config, db, auth_vault=vault_client)

# Initialize HTTPSmuggler with orchestrator
smuggler = HTTPSmuggler(
    session=aiohttp_session,
    config=config["http_smuggling"],
    db=db,
    orchestrator=orchestrator
)

# Run correlated scan
findings = await smuggler.scan_with_correlation(
    url="https://target.example.com/admin",
    content=html_content,
    headers=response_headers,
    response=response_obj
)

# Export high-confidence findings to Burp + Nuclei
high_conf = [f for f in findings if f.confidence > 0.9]
export_results = await smuggler.export_to_integrations(high_conf)

# Trigger coordinated scan across all tools
scan_results = await orchestrator.trigger_cross_tool_scan(
    target="https://target.example.com",
    config={
        "burp": {"scan_config": {"audit_mode": "full"}},
        "nuclei": {"severity_filter": ["high", "critical"]},
        "enterprise:checkmarx": {"scan_preset": "owasp_top_10"}
    }
)

# Poll for completion and correlate results
# (Implementation depends on async task queue like Celery/RQ)

# After detecting a novel smuggling pattern
finding = CrossToolFinding(...)  # High-confidence Gecko detection

# Export to Nuclei registry
nuclei_integration = orchestrator.integrations["nuclei"]
result = await nuclei_integration.export_findings([finding])

# Result: Template saved to ./gecko_nuclei_templates/gecko-abc123.yaml
# Can now be used in CI/CD pipelines or shared with team

# Usage example with cross-tool correlation
from gecko.enterprise import EnterpriseOrchestrator, AuthBypass

# Initialize orchestrator with Burp/Nuclei integrations
orchestrator = EnterpriseOrchestrator(config, db, auth_vault)

# Initialize AuthBypass with orchestrator
auth_scanner = AuthBypass(
    session=aiohttp_session,
    config=config["auth_bypass"],
    db=db,
    orchestrator=orchestrator
)

# Run scan with correlation
findings = await auth_scanner.scan(
    url="https://target.example.com/login",
    content=html_content,
    headers=response_headers,
    response=response_obj
)

# Export high-confidence findings to Burp for analyst review
high_conf = [f for f in findings if f.confidence > 0.9]
export_results = await orchestrator.export_findings(high_conf, ["burp", "nuclei"])

# Trigger workflow actions for critical findings
await orchestrator.execute_workflow_actions(
    [f for f in findings if f.severity == "CRITICAL"],
    actions={"jira": True, "slack": True}
)

# Usage example with cross-tool correlation
from gecko.enterprise import EnterpriseOrchestrator, VulnerabilityScanner

# Initialize orchestrator with Burp/Nuclei integrations
orchestrator = EnterpriseOrchestrator(config, db, auth_vault)

# Initialize VulnerabilityScanner with orchestrator
scanner = VulnerabilityScanner(
    session=aiohttp_session,
    config=config["vuln_scanner"],
    db=db,
    orchestrator=orchestrator
)

# Run scan with correlation
findings = await scanner.scan(
    url="https://target.example.com",
    content=html_content,
    headers=response_headers,
    response=response_obj
)

# Export high-confidence findings to Burp for analyst review
high_conf = [f for f in findings if f.confidence > 0.9]
export_results = await orchestrator.export_findings(high_conf, ["burp", "nuclei"])

# Generate Nuclei templates from findings for CI/CD integration
nuclei_integration = orchestrator.integrations.get("nuclei")
if nuclei_integration:
    template_results = await nuclei_integration.export_findings(high_conf)
    logger.info(f"Generated {len(template_results.get('template_paths', []))} Nuclei templates")

# Trigger workflow actions for critical findings
await orchestrator.execute_workflow_actions(
    [f for f in findings if f.severity == "CRITICAL"],
    actions={"jira": True, "slack": True, "auto_pr": False}  # Auto-PR disabled for file exposure
)

# Usage example with cross-tool correlation
from gecko.enterprise import EnterpriseOrchestrator, NoSQLInjector

# Initialize orchestrator with Burp/Nuclei integrations
orchestrator = EnterpriseOrchestrator(config, db, auth_vault)

# Initialize NoSQLInjector with orchestrator
injector = NoSQLInjector(
    session=aiohttp_session,
    config=config["nosql_injector"],
    db=db,
    orchestrator=orchestrator
)

# Run scan with correlation
findings = await injector.scan(
    url="https://target.example.com/api/login",
    content=request_body,
    headers=request_headers,
    response=response_obj
)

# Export high-confidence findings to Burp for analyst review
high_conf = [f for f in findings if f.confidence > 0.9]
export_results = await orchestrator.export_findings(high_conf, ["burp", "nuclei"])

# Generate Nuclei templates from findings
nuclei_integration = orchestrator.integrations.get("nuclei")
if nuclei_integration:
    template_results = await nuclei_integration.export_findings(high_conf)
    logger.info(f"Generated {len(template_results.get('template_paths', []))} NoSQL Nuclei templates")

# Trigger workflow actions for critical findings
await orchestrator.execute_workflow_actions(
    [f for f in findings if f.severity == "CRITICAL"],
    actions={"jira": True, "slack": True}
)

# Usage example with cross-tool correlation
from gecko.enterprise import EnterpriseOrchestrator, JWTModule

# Initialize orchestrator with Burp/Nuclei integrations
orchestrator = EnterpriseOrchestrator(config, db, auth_vault)

# Initialize JWTModule with orchestrator
jwt_scanner = JWTModule(
    session=aiohttp_session,
    config=config["jwt_module"],
    db=db,
    orchestrator=orchestrator
)

# Run scan with correlation
context = {
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_location": "header",
    "original_headers": {"Accept": "application/json"}
}

findings = await jwt_scanner.run(
    target="https://target.example.com/api/user",
    session=aiohttp_session,
    context=context
)

# Export high-confidence findings to Burp for analyst review
high_conf = [f for f in findings if f.confidence > 0.9]
export_results = await orchestrator.export_findings(high_conf, ["burp", "nuclei"])

# Generate Nuclei templates from findings
nuclei_integration = orchestrator.integrations.get("nuclei")
if nuclei_integration:
    template_results = await nuclei_integration.export_findings(high_conf)
    logger.info(f"Generated {len(template_results.get('template_paths', []))} JWT Nuclei templates")

# Trigger workflow actions for critical findings
await orchestrator.execute_workflow_actions(
    [f for f in findings if f.severity == "CRITICAL"],
    actions={"jira": True, "slack": True}
)
```

## ⚙️ Configuration

The framework is highly customizable via `config/config.yaml`. You can enable/disable modules, set target scopes, specify authentication tokens for APIs (Shodan, GitHub, HaveIBeenPwned), and configure proxy routing. 

## ⚖️ Legal Disclaimer

**For Authorized Security Testing Only.**

This tool is designed exclusively for security professionals, penetration testers, and researchers to assess the security of systems they have explicit, written permission to test. Unauthorized access to computer systems or networks is illegal. The authors and contributors are not responsible for any misuse, damage, or legal consequences resulting from the use of this software.