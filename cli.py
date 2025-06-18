import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

from sec_ckeck.agents.security_agent import run_security_assessment
from sec_ckeck.config import config
from sec_ckeck.tools.cve_database import CVEDatabase

app = typer.Typer(help="Automated IT Security Testing Agent")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host/IP to scan"),
    exploit: bool = typer.Option(
        False, "--exploit", "-e", help="Enable ethical exploitation"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output directory for reports"
    ),
):
    """Run comprehensive security assessment on target."""

    if output:
        config.report_output_dir = output

    console.print(f"[bold blue]Starting security assessment of: {target}[/bold blue]")

    if exploit and not config.ethical_hacking_mode:
        console.print(
            "[yellow]Warning: Ethical hacking mode disabled in config[/yellow]"
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running security assessment...", total=None)

        async def run_assessment():
            try:
                result = await run_security_assessment(target, exploit)
                return result
            except Exception as e:
                return f"Assessment failed: {str(e)}"

        result = asyncio.run(run_assessment())
        progress.remove_task(task)

    console.print("\n[bold green]Assessment Complete![/bold green]")
    console.print(result)


@app.command()
def cve_lookup(
    cve_id: str = typer.Argument(..., help="CVE ID to lookup (e.g., CVE-2021-44228)"),
):
    """Look up CVE information."""

    async def lookup():
        cve_db = CVEDatabase()
        try:
            info = await cve_db.get_cve_info(cve_id)
            return info
        finally:
            await cve_db.close()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Looking up {cve_id}...", total=None)
        info = asyncio.run(lookup())
        progress.remove_task(task)

    if "error" in info:
        console.print(f"[red]Error: {info['error']}[/red]")
    else:
        table = Table(title=f"CVE Information: {cve_id}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        for key, value in info.items():
            if value:
                table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)


@app.command()
def search_cves(
    product: str = typer.Argument(..., help="Product name to search"),
    version: Optional[str] = typer.Option(
        None, "--version", "-v", help="Product version"
    ),
):
    """Search CVEs by product/version."""

    async def search():
        cve_db = CVEDatabase()
        try:
            results = await cve_db.search_by_product(product, version)
            return results
        finally:
            await cve_db.close()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Searching CVEs for {product}...", total=None)
        results = asyncio.run(search())
        progress.remove_task(task)

    if not results:
        console.print(f"[yellow]No CVEs found for {product}[/yellow]")
        return

    table = Table(title=f"CVEs for {product}")
    table.add_column("CVE ID", style="red")
    table.add_column("Severity", style="yellow")
    table.add_column("CVSS", style="cyan")
    table.add_column("Description", style="white", max_width=50)

    for cve in results[:10]:  # Limit to first 10 results
        table.add_row(
            cve.get("cve_id", ""),
            cve.get("severity", "").upper(),
            str(cve.get("cvss_score", "N/A")),
            cve.get("description", "")[:100] + "..."
            if len(cve.get("description", "")) > 100
            else cve.get("description", ""),
        )

    console.print(table)

    if len(results) > 10:
        console.print(f"[blue]Showing 10 of {len(results)} results[/blue]")


@app.command()
def config_show():
    """Show current configuration."""

    table = Table(title="Security Agent Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("LLM Endpoint", config.llm_endpoint)
    table.add_row("LLM Model", config.llm_model_name)
    table.add_row("CVE API URL", config.cve_api_url)
    table.add_row("Ethical Hacking Mode", str(config.ethical_hacking_mode))
    table.add_row("Max Concurrent Scans", str(config.max_concurrent_scans))
    table.add_row("Report Output Dir", config.report_output_dir)

    console.print(table)


def main():
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
