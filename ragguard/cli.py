import os

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ragguard.config import load_config
from ragguard.engine import run_scan
from ragguard.report.html import write_html_report
from ragguard.report.markdown import write_markdown_report
from ragguard.report.sarif import write_sarif_report
from ragguard.scanners import ALL_SCANNERS

console = Console(force_terminal=True)


@click.group()
@click.version_option()
def main():
    """RAGGuard -- static security scanner for RAG pipelines."""


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path (auto-detects format from extension).")
@click.option(
    "--format", "fmt", type=click.Choice(["markdown", "html", "sarif", "terminal"]), default="terminal",
)
@click.option(
    "--severity", type=click.Choice(["high", "medium", "low"], case_sensitive=False), help="Filter by severity."
)
@click.option("--category", help="Filter by category (e.g. filter-injection, nosql-injection).")
def scan(target: str, output: str | None, fmt: str, severity: str | None, category: str | None):
    """Scan a codebase for RAG security vulnerabilities."""
    target = os.path.abspath(target)
    console.print(f"\n[bold blue]RAGGuard[/] scanning [cyan]{target}[/]\n")

    config = load_config(target)
    scanners = [cls() for cls in ALL_SCANNERS]
    findings = run_scan(target, scanners, severity_filter=severity, category_filter=category, config=config)

    if output and not fmt:
        if output.endswith(".html"):
            fmt = "html"
        elif output.endswith(".md"):
            fmt = "markdown"

    if fmt == "terminal" and not output:
        _print_terminal(findings, target)
    elif fmt == "sarif" or (output and output.endswith(".sarif")):
        path = output or "ragguard-report.sarif"
        write_sarif_report(findings, target, path)
        console.print(f"\n[green]SARIF report written to {path}[/]")
    elif fmt == "html" or (output and output.endswith(".html")):
        path = output or "ragguard-report.html"
        write_html_report(findings, target, path)
        console.print(f"\n[green]HTML report written to {path}[/]")
    elif fmt == "markdown" or (output and output.endswith(".md")):
        path = output or "ragguard-report.md"
        write_markdown_report(findings, target, path)
        console.print(f"\n[green]Markdown report written to {path}[/]")
    else:
        _print_terminal(findings, target)

    _print_summary(findings)


def _print_terminal(findings: list, target: str):
    if not findings:
        console.print("[green]No findings.[/]")
        return

    for f in findings:
        sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(f.severity, "white")
        console.print(f"\n[bold {sev_color}]{f.id} [{f.severity}][/] {f.title}")
        console.print(f"  [dim]{f.file_path}:{f.line_number}[/]")
        console.print(f"  {escape(f.description)}")
        if f.code_snippet:
            console.print(f"  [dim]> {escape(f.code_snippet.strip()[:120])}[/]")


def _print_summary(findings: list):
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    console.print()
    table = Table(title="Summary", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[red]HIGH[/]", str(high))
    table.add_row("[yellow]MEDIUM[/]", str(med))
    table.add_row("[blue]LOW[/]", str(low))
    table.add_row("[bold]Total[/]", f"[bold]{len(findings)}[/]")
    console.print(table)
