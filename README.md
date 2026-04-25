# 🦎 Gecko Apocalypse Engine v10.0

**Gecko Apocalypse** is a sophisticated, high-performance Vulnerability Assessment and Penetration Testing Framework. Engineered to deliver enterprise-grade offensive security capabilities, it employs an asynchronous architecture for rapid, exhaustive scanning across modern web applications, cloud infrastructure, and APIs.

## ✨ What's New in v10.0

*   **Enterprise PDF Reporting Engine:** Generates pristine, boardroom-ready PDF reports featuring automated CVSS scoring, precise OWASP mapping, and actionable remediation SLAs.
*   **Intelligent Finding Deduplication:** Smartly aggregates vulnerabilities by type and consolidates affected assets, drastically reducing report bloat while maintaining comprehensive forensic detail.
*   **Seamless Execution:** Eliminated legacy authorization constraints (`--authorized` flag), streamlining the workflow for authorized security assessments.
*   **Enhanced Output Formatting:** Refined XML parsing for the flawless rendering of custom styles, severity gauges, and vulnerability badges within generated documents.

## 🚀 Key Features

*   **Comprehensive Attack Modules**: Features over 25 specialized attack vectors targeting classic vulnerabilities, modern cloud misconfigurations, and intricate business logic flaws.
    *   **Advanced Bug Bounty Modules**: Context-aware Reflected XSS, Time/Error-based SQLi, sophisticated BOLA/IDOR detection, Open Redirects, and JWT manipulation.
    *   **Network & Web Correlation**: Enterprise-grade cross-layer analysis utilizing `bs4` and `scapy` to detect CSRF omissions, insecure external resources, and cleartext credential transmission.
    *   **Modern Web Architecture**: GraphQL fuzzing, CORS misconfigurations, and WebSocket hijacking validation.
    *   **Cloud Native Profiling**: AWS/GCP/Azure metadata probing, S3/Blob public exposure checks, and Kubernetes registry enumeration.
    *   **Business Logic Scrutiny**: Race condition detection, privilege escalation probing, and workflow bypass testing.
*   **SPA-Aware Crawler**: An intelligent crawler capable of extracting embedded JS bundle routes, discovering hidden API endpoints, and dynamically parsing complex HTML forms.
*   **Extensible Plugin Architecture**: Seamlessly integrate custom modules via the dynamic plugin loader without modifying the core orchestrator.
*   **Session Persistence**: SQLite-backed checkpointing enables the pausing and resuming of prolonged scanning sessions.

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/D8v1d777/Gecko.git
cd Gecko

# Install requirements
pip install -r requirements.txt
```

## 💻 Usage

Gecko Apocalypse offers a highly configurable and intuitive Command Line Interface (CLI).

```bash
# Basic reconnaissance scan
python cli/main.py https://example.com

# Comprehensive deep scan generating an enterprise PDF report
python cli/main.py https://example.com --deep --output pdf

# Targeted execution of specific modules
python cli/main.py https://example.com --modules xss,sqli

# Customizing the request with bespoke headers and multi-threading
python cli/main.py https://example.com --header "X-Custom: secret" --threads 5
```

### Enterprise Integration Example

Gecko facilitates seamless integration into enterprise workflows, allowing orchestration across external tools like Burp Suite and Nuclei.

```python
from gecko.enterprise import EnterpriseOrchestrator, VulnerabilityScanner

# Initialize the orchestrator with vault-backed configurations
config = load_config_with_vault("config/enterprise.yaml")
orchestrator = EnterpriseOrchestrator(config, db, auth_vault=vault_client)

# Instantiate a specialized scanner module
scanner = VulnerabilityScanner(
    session=aiohttp_session,
    config=config["vuln_scanner"],
    db=db,
    orchestrator=orchestrator
)

# Execute an advanced correlated scan
findings = await scanner.scan(
    url="https://target.example.com",
    content=html_content,
    headers=response_headers,
    response=response_obj
)

# Filter high-confidence findings for analyst review
high_conf = [f for f in findings if f.confidence > 0.9]

# Export findings seamlessly to Burp Suite and Nuclei
export_results = await orchestrator.export_findings(high_conf, ["burp", "nuclei"])

# Automate workflow actions for critical vulnerabilities
await orchestrator.execute_workflow_actions(
    [f for f in findings if f.severity == "CRITICAL"],
    actions={"jira": True, "slack": True}
)
```

## ⚙️ Configuration

The framework is deeply customizable via `config/config.yaml`. Administrators can toggle modules, define target scopes, provision authentication tokens for third-party APIs (e.g., Shodan, GitHub), and configure custom proxy routing topologies.

## ⚖️ Legal Disclaimer

**For Authorized Security Testing Only.**

This suite is strictly intended for security professionals, penetration testers, and researchers conducting assessments on systems where explicit, written authorization has been granted. Unauthorized access or exploitation of systems is strictly prohibited. The authors and contributors disclaim any liability for misuse, damages, or legal repercussions stemming from the utilization of this software.