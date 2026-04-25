import asyncio
import os
import sys

import typer
from rich import print
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, track
from rich.table import Table

# Add parent directory to path to import core and modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gecko_apocalypse import MODULES, run_scan
from core.finding import Severity
from modules.reporting.pdf_generator import ProfessionalPDFGenerator, VulnerabilityDetails
from core.config import Config
from datetime import datetime

app = typer.Typer(help="Gecko - Intelligent Security Scanner")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    modules: str = typer.Option(None, help="Comma-separated modules"),
    output: str = typer.Option("console", help="Output format: console/html/json"),
    threads: int = typer.Option(20, help="Concurrency level"),
    header: list[str] = typer.Option(None, help="Custom headers (e.g. 'Authorization: Bearer token')"),
    crawl_depth: int = typer.Option(2, help="Depth for the web crawler"),
    deep: bool = typer.Option(False, "--deep", help="Use the Deep Security Crawler"),
):
    """
    Run a high-fidelity security scan against a target
    """
    # Banner
    print(
        Panel.fit(
            "[bold magenta]Gecko Scanner v1.0[/]",
            subtitle="Advanced Security Orchestrator",
        )
    )


    print(f"[bold green]Starting scan on:[/] {target}")

    selected_module_names = modules.split(",") if modules else None

    headers_dict = {}
    if header:
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers_dict[k.strip()] = v.strip()

    # Logic to show progress while running async modules
    # In a real tool, we might want to update the progress as each module finishes
    # For now, we'll use a Spinner
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(
            description="Gecko is hunting for vulnerabilities...", total=None
        )

        findings = asyncio.run(
            run_scan(target, selected_modules=selected_module_names, threads=threads, headers=headers_dict, crawl_depth=crawl_depth, deep_crawl=deep)
        )

    display_results(findings)

    if output != "console":
        print("[bold yellow]Generating professional reports...[/]")
        
        scan_start = datetime.now() # Approximate or pass from run_scan
        metadata = {
            "target": target,
            "scan_id": f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "scan_date": datetime.now().strftime('%Y-%m-%d'),
            "classification": "CONFIDENTIAL"
        }
        
        # Determine formats to generate
        requested_formats = [output] if output in ["pdf", "html", "json", "markdown"] else ["html"]
        
        config = {"theme": "professional"}
        reporter = ProfessionalPDFGenerator(config)
        
        import os
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        report_base_name = f"gecko_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Convert Finding objects to VulnerabilityDetails
        vuln_details = []
        for f in findings:
            vuln = VulnerabilityDetails(
                title=f.title or f.type,
                severity=f.severity.value.upper(),
                cvss_score=f.cvss_score or 0.0,
                cvss_vector=f.cvss_vector or "N/A",
                cwe_id=f.cwe_id or "CWE-Unknown",
                cwe_name="Unknown Weakness",
                owasp_category=f.owasp_category or "A00:Unknown",
                url=f.url,
                location="N/A",
                parameter=None,
                method="GET", # Approximation, would need request info
                description=f.description or "No description provided",
                technical_details=f.description or "No technical details",
                root_cause="Improper validation or misconfiguration",
                business_impact=f.impact or "Could lead to compromise of application confidentiality, integrity, or availability.",
                affected_assets=[f.url],
                evidence=[{"request": f.raw_request, "response": f.raw_response}] if f.raw_request or f.raw_response else [],
                proof_of_concept=f.evidence or "",
                remediation_steps=[f.remediation] if f.remediation else ["Follow security best practices."],
                remediation_code=None,
                references=f.references or [],
                compliance_impact=[],
                likelihood="Medium",
                exploitability="Medium",
                time_to_exploit="Unknown",
                detected_at=f.timestamp,
                false_positive_probability=0.1
            )
            vuln_details.append(vuln)
        
        if "pdf" in requested_formats:
            output_path = os.path.join(report_dir, report_base_name + ".pdf")
            results = {"pdf": asyncio.run(reporter.generate(
                findings=vuln_details,
                output_path=output_path,
                metadata=metadata
            ))}
        else:
            print("[bold red]Only PDF output is currently supported by the Professional Generator.[/]")
            results = {}

        for fmt, path in results.items():
            print(f"[bold cyan]{fmt.upper()} report saved to:[/] {path}")


def display_results(findings):
    if not findings:
        print("[bold yellow][!] No vulnerabilities identified in this scan cycle.[/]")
        return

    table = Table(title="Scan Results", border_style="blue")

    table.add_column("Type", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Endpoint", style="green")
    table.add_column("Confidence", style="yellow")

    color_map = {
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "CRITICAL": "bold red",
    }

    for f in findings:
        severity = f.severity.value.upper()
        sev_color = color_map.get(severity, "white")

        table.add_row(
            str(f.type),
            f"[{sev_color}]{severity}[/]",
            str(f.url),
            "HIGH", # Confidence not in Finding yet
        )

    print(table)


if __name__ == "__main__":
    app()
