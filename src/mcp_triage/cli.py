from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from mcp_triage import __version__
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
    fail_on: Severity = typer.Option(
        Severity.HIGH, "--fail-on", help="Exit with a non-zero code if a finding at or above this severity is found."
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
        f.severity.weight >= fail_on.weight for f in findings
    ):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
