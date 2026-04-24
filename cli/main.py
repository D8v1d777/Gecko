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

app = typer.Typer(help="Gecko - Intelligent Security Scanner")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    modules: str = typer.Option(None, help="Comma-separated modules"),
    output: str = typer.Option("console", help="Output format: console/html/json"),
    threads: int = typer.Option(20, help="Concurrency level"),
    authorized: bool = typer.Option(
        False, "--authorized", help="Confirm authorization"
    ),
    header: list[str] = typer.Option(None, help="Custom headers (e.g. 'Authorization: Bearer token')"),
    crawl_depth: int = typer.Option(2, help="Depth for the web crawler"),
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

    if not authorized:
        print(
            "[bold red][-] Error:[/bold red] You must confirm authorization with --authorized"
        )
        raise typer.Exit(code=1)

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
            run_scan(target, selected_modules=selected_module_names, threads=threads, headers=headers_dict, crawl_depth=crawl_depth)
        )

    display_results(findings)

    if output != "console":
        from reports.deduplicator import Deduplicator
        from reports.generator import ReportGenerator, render_html

        print("[bold yellow]Generating report...[/]")
        deduped = Deduplicator(findings).deduplicate()
        report = ReportGenerator(target, deduped).build(output_format="dict")
        path = render_html(report)

        print(f"[bold cyan]Report saved to:[/] {path}")


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
        severity = str(f.get("severity", "MEDIUM")).upper()
        sev_color = color_map.get(severity, "white")

        table.add_row(
            str(f.get("type", "Unknown")),
            f"[{sev_color}]{severity}[/]",
            str(f.get("endpoint", "/")),
            str(f.get("confidence", "LOW")),
        )

    print(table)


if __name__ == "__main__":
    app()
