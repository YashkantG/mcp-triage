from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_triage import __version__
from mcp_triage.audit_local import AuditResult, audit_local
from mcp_triage.baseline import BaselineError, new_findings, write_baseline
from mcp_triage.config import ConfigError
from mcp_triage.models import Severity
from mcp_triage.report import (
    render_badge,
    render_json,
    render_markdown,
    render_sarif,
    render_table,
)
from mcp_triage.scanner import scan as run_scan

app = typer.Typer(
    name="mcp-triage",
    help="Security scanner for MCP (Model Context Protocol) servers and tool manifests.",
    add_completion=False,
)
console = Console()


def _parse_fail_on(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError as exc:
        choices = ", ".join(severity.value.lower() for severity in Severity)
        raise typer.BadParameter(
            f"choose from {choices}",
            param_hint="--fail-on",
        ) from exc


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("`", "\\`").replace("\n", " ")


def _render_local_audit(result: AuditResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps({
            "config_files": result.config_files,
            "servers": [
                {"name": server.name, "config_file": server.config_file}
                for server in result.servers
            ],
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "file": finding.file,
                    "message": finding.message,
                }
                for finding in result.findings
            ],
            "errors": result.errors,
        }, indent=2))
        return

    if fmt == "markdown":
        print("# Local MCP configuration audit\n")
        print(f"**Configuration files checked:** {len(result.config_files)}\n")
        for path in result.config_files:
            print(f"- `{path}`")
        if not result.config_files:
            print("- No supported MCP configuration files were found.")
        print("\n## Configured servers\n")
        if result.servers:
            print("| Server | Configuration |")
            print("|---|---|")
            for server in result.servers:
                print(
                    f"| {_markdown_cell(server.name)} "
                    f"| `{_markdown_cell(server.config_file)}` |"
                )
        else:
            print("No configured MCP servers were found.")
        print("\n| Severity | Rule | Configuration | Finding |")
        print("|---|---|---|---|")
        for finding in sorted(
            result.findings,
            key=lambda item: (-item.severity.weight, item.file, item.rule_id),
        ):
            message = _markdown_cell(finding.message)
            location = _markdown_cell(finding.file)
            print(f"| {finding.severity.value} | {finding.rule_id} | `{location}` | {message} |")
        if not result.findings:
            print("| - | - | - | No risky settings found. |")
        for error in result.errors:
            print(f"\n> Error: {error}")
        return

    console.print(f"[bold]MCP configuration files checked: {len(result.config_files)}[/bold]")
    for path in result.config_files:
        console.print(Text(f"  {path}"))
    if not result.config_files:
        console.print("[yellow]No supported MCP configuration files were found.[/yellow]")
    if result.servers:
        server_table = Table(title="Configured MCP servers")
        server_table.add_column("Server")
        server_table.add_column("Configuration")
        for server in result.servers:
            server_table.add_row(Text(server.name), Text(server.config_file))
        console.print(server_table)
    else:
        console.print("[yellow]No configured MCP servers were found.[/yellow]")
    if result.findings:
        table = Table(title="Local MCP audit findings")
        table.add_column("Severity")
        table.add_column("Rule")
        table.add_column("Configuration")
        table.add_column("Finding")
        for finding in sorted(
            result.findings,
            key=lambda item: (-item.severity.weight, item.file, item.rule_id),
        ):
            table.add_row(
                finding.severity.value,
                finding.rule_id,
                Text(finding.file),
                Text(finding.message),
            )
        console.print(table)
    else:
        console.print("[bold green]No risky settings found.[/bold green]")
    for error in result.errors:
        console.print("[bold red]Error:[/bold red]", Text(error))


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcp-triage {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    pass


@app.command(name="scan")
def scan_command(
    target: Path = typer.Argument(
        ..., exists=True, help="Path to an MCP server project, a single source file, or a captured tools/manifest JSON file."
    ),
    fmt: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, json, sarif, markdown, or badge.",
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on",
        help="Exit non-zero for findings at or above this severity: high, medium, or low (case-insensitive).",
    ),
    ignore_rule: List[str] = typer.Option(
        [], "--ignore-rule", help="Rule ID to suppress (repeatable), e.g. --ignore-rule MCP004.",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", exists=True,
        help="Path to a .mcptriage.toml (or its containing directory). Defaults to looking next to TARGET.",
    ),
    include_tests: bool = typer.Option(
        False, "--include-tests",
        help="Also scan test/benchmark/example directories, which are skipped by default.",
    ),
    baseline: Optional[Path] = typer.Option(
        None, "--baseline",
        help="Only report findings not already recorded in this baseline JSON file.",
    ),
    write_baseline_path: Optional[Path] = typer.Option(
        None, "--write-baseline",
        help="Write the current findings to a baseline JSON file and exit successfully.",
    ),
) -> None:
    """Scan TARGET for MCP security issues."""
    if fmt not in {"table", "json", "sarif", "markdown", "badge"}:
        raise typer.BadParameter(
            "choose from table, json, sarif, markdown, or badge",
            param_hint="--format",
        )
    if baseline is not None and write_baseline_path is not None:
        raise typer.BadParameter(
            "--baseline and --write-baseline cannot be used together",
            param_hint="--baseline",
        )
    fail_threshold = _parse_fail_on(fail_on)
    root = target.resolve() if target.is_dir() else target.resolve().parent
    baseline_comparison = baseline is not None
    try:
        findings = run_scan(
            target,
            extra_ignored_rules=set(ignore_rule),
            config_path=config,
            include_tests=include_tests,
        )
        if write_baseline_path is not None:
            write_baseline(findings, write_baseline_path, root)
            typer.echo(f"Baseline written to {write_baseline_path}", err=True)
        elif baseline is not None:
            findings = new_findings(findings, baseline, root)
    except (ConfigError, BaselineError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if fmt == "json":
        print(render_json(findings))
    elif fmt == "sarif":
        print(render_sarif(findings, root))
    elif fmt == "markdown":
        print(render_markdown(findings, root, baseline_comparison))
    elif fmt == "badge":
        print(render_badge(findings))
    else:
        if baseline_comparison and not findings:
            console.print("[bold green]No new findings compared with the baseline.[/bold green]")
        else:
            if baseline_comparison:
                console.print("[dim]New findings compared with baseline:[/dim]")
            render_table(findings, console)

    if write_baseline_path is None and any(
        f.severity.weight >= fail_threshold.weight for f in findings
    ):
        raise typer.Exit(code=1)


@app.command(name="audit-local")
def audit_local_command(
    fmt: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, json, or markdown.",
    ),
    path: Optional[List[Path]] = typer.Option(
        None, "--path",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Audit this MCP config file instead of discovering known client configs (repeatable).",
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on",
        help="Exit non-zero for findings at or above this severity: high, medium, or low (case-insensitive).",
    ),
) -> None:
    """Audit MCP servers configured in local AI clients (read-only)."""
    if fmt not in {"table", "json", "markdown"}:
        raise typer.BadParameter(
            "choose from table, json, or markdown",
            param_hint="--format",
        )
    fail_threshold = _parse_fail_on(fail_on)
    result = audit_local(paths=path)
    _render_local_audit(result, fmt)
    if result.errors:
        raise typer.Exit(code=2)
    if any(f.severity.weight >= fail_threshold.weight for f in result.findings):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
