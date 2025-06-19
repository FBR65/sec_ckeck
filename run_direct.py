#!/usr/bin/env python3
"""
Direct runner for the security check tool without package imports.
Usage: python run_direct.py [command] [arguments]
"""

import sys
import os
import asyncio
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Direct imports
from agents.security_agent import run_security_assessment
from config import config
from tools.cve_database import CVEDatabase

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
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output"),
):
    """Search CVEs by product/version."""

    async def search():
        cve_db = CVEDatabase()
        try:
            if debug:
                console.print(f"[yellow]Debug mode enabled[/yellow]")
                console.print(
                    f"[blue]Searching for product: '{product}'{f' version: {version}' if version else ''}[/blue]"
                )

            results = await cve_db.search_by_product(product, version)

            # If no results, try keyword search
            if not results and debug:
                console.print(
                    f"[yellow]No results from product search, trying keyword search...[/yellow]"
                )
                results = await cve_db.search_by_keyword(product)

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
def search_keyword(
    keyword: str = typer.Argument(..., help="Keyword to search in CVE data"),
):
    """Search CVEs by keyword."""

    async def search():
        cve_db = CVEDatabase()
        try:
            results = await cve_db.search_by_keyword(keyword)
            return results
        finally:
            await cve_db.close()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"Searching CVEs for keyword '{keyword}'...", total=None
        )
        results = asyncio.run(search())
        progress.remove_task(task)

    if not results:
        console.print(f"[yellow]No CVEs found for keyword '{keyword}'[/yellow]")
        return

    table = Table(title=f"CVEs for keyword: {keyword}")
    table.add_column("CVE ID", style="red")
    table.add_column("Severity", style="yellow")
    table.add_column("CVSS", style="cyan")
    table.add_column("Description", style="white", max_width=50)

    for cve in results[:10]:
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
def debug_cve_api():
    """Debug CVE API connectivity and responses."""

    async def debug():
        cve_db = CVEDatabase()
        try:
            console.print("[blue]Testing CVE API connectivity...[/blue]")

            # Test basic connectivity
            response = await cve_db.client.get(f"{cve_db.api_url}")
            console.print(f"API base URL response: {response.status_code}")

            # Test specific CVE lookup
            test_cve = "CVE-2021-44228"  # Log4j vulnerability
            console.print(f"Testing CVE lookup for {test_cve}...")
            cve_info = await cve_db.get_cve_info(test_cve)
            console.print(f"CVE info keys: {list(cve_info.keys())}")

            # Test recent CVEs
            console.print("Testing recent CVEs...")
            recent = await cve_db.get_recent_cves(7)
            console.print(f"Recent CVEs count: {len(recent)}")

            return "Debug complete"

        except Exception as e:
            return f"Debug failed: {str(e)}"
        finally:
            await cve_db.close()

    result = asyncio.run(debug())
    console.print(result)


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


@app.command()
def test_cve_org():
    """Test CVE.org integration with known CVEs."""

    async def test():
        cve_db = CVEDatabase()
        try:
            console.print("[blue]Testing CVE.org integration...[/blue]")

            # Test the specific CVE mentioned
            test_cves = ["CVE-2025-31698", "CVE-2021-44228"]

            for cve_id in test_cves:
                console.print(f"Testing {cve_id}...")
                cve_info = await cve_db.get_cve_info(cve_id)

                if "error" not in cve_info:
                    console.print(
                        f"✓ Found {cve_id}: {cve_info.get('description', 'No description')[:100]}..."
                    )
                else:
                    console.print(f"✗ Failed to get {cve_id}: {cve_info.get('error')}")

            # Test search
            console.print("\nTesting search for 'Apache Traffic Server'...")
            search_results = await cve_db.search_by_product("Apache Traffic Server")
            console.print(f"Found {len(search_results)} results")

            for result in search_results[:3]:
                console.print(
                    f"- {result.get('cve_id', 'Unknown')}: {result.get('description', 'No description')[:80]}..."
                )

            return "Test complete"

        finally:
            await cve_db.close()

    result = asyncio.run(test())
    console.print(result)


@app.command()
def exploit_cve(
    cve_id: str = typer.Argument(..., help="CVE ID to exploit"),
    target: str = typer.Argument(..., help="Target host/IP"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Target port"),
):
    """⚠️  ETHICAL TESTING ONLY: Attempt CVE-based exploitation."""

    if not config.ethical_hacking_mode:
        console.print("[red]❌ Ethical hacking mode is disabled![/red]")
        console.print("Enable with ETHICAL_HACKING_MODE=true in .env")
        console.print(
            "[yellow]⚠️  Only use on systems you own or have explicit permission to test![/yellow]"
        )
        return

    console.print("[yellow]⚠️  ETHICAL HACKING MODE ACTIVE ⚠️[/yellow]")
    console.print("Ensure you have authorization to test this system!")

    async def exploit():
        from tools.exploit_engine import ExploitEngine

        engine = ExploitEngine()
        return await engine.exploit_by_cve(cve_id, target, port)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Testing {cve_id} on {target}...", total=None)
        result = asyncio.run(exploit())
        progress.remove_task(task)

    if "error" in result:
        console.print(f"[red]Error: {result['error']}[/red]")
    else:
        table = Table(title=f"CVE Exploitation Test: {cve_id}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        for key, value in result.items():
            if key != "educational_info":
                table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)

        if "educational_info" in result:
            console.print("\n[bold blue]Educational Information:[/bold blue]")
            for key, value in result["educational_info"].items():
                console.print(f"• {key.replace('_', ' ').title()}: {value}")


# ...existing code for other commands...

if __name__ == "__main__":
    app()
