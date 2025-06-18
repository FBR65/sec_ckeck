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


# ...existing code for other commands...

if __name__ == "__main__":
    app()
