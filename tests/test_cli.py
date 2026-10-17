import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_triage.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_scan_exits_nonzero_on_high_severity():
    result = runner.invoke(app, ["scan", str(FIXTURES / "vulnerable_server"), "--include-tests", "--format", "json"])
    assert result.exit_code == 1


def test_scan_exits_zero_on_clean_target():
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean_server"), "--include-tests"])
    assert result.exit_code == 0


def test_ignore_rule_flag_removes_findings_and_can_flip_exit_code():
    all_high_rules = [
        "MCP001", "MCP101", "MCP102", "MCP103", "MCP104", "MCP201", "MCP302"
    ]
    args = ["scan", str(FIXTURES / "vulnerable_server"), "--include-tests", "--format", "json"]
    for rule in all_high_rules:
        args += ["--ignore-rule", rule]
    result = runner.invoke(app, args)
    findings = json.loads(result.stdout)
    assert all(f["severity"] != "HIGH" for f in findings)
    assert result.exit_code == 0


def test_sarif_format_produces_valid_json():
    result = runner.invoke(app, ["scan", str(FIXTURES / "vulnerable_server"), "--include-tests", "--format", "sarif"])
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "mcp-triage" in result.stdout


def test_invalid_format_is_rejected():
    result = runner.invoke(app, ["scan", str(FIXTURES / "clean_server"), "--format", "yaml"])
    assert result.exit_code == 2
    assert "choose from table" in result.output
    assert "markdown, or" in result.output
    assert "badge" in result.output


def test_invalid_config_fails_with_actionable_error(tmp_path):
    config = tmp_path / ".mcptriage.toml"
    config.write_text('[severity]\nMCP102 = "urgent"\n', encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "clean_server"), "--config", str(config)],
    )
    assert result.exit_code == 2
    assert "HIGH, MEDIUM, or LOW" in result.output
    assert "Traceback" not in result.output


def test_baseline_generation_and_comparison(tmp_path):
    baseline = tmp_path / "baseline.json"
    target = FIXTURES / "vulnerable_server"
    write_result = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--include-tests",
            "--format",
            "json",
            "--write-baseline",
            str(baseline),
        ],
    )
    assert write_result.exit_code == 0
    assert baseline.is_file()

    compare_result = runner.invoke(
        app,
        ["scan", str(target), "--include-tests", "--baseline", str(baseline)],
    )
    assert compare_result.exit_code == 0
    assert "No new findings compared with the baseline" in compare_result.output


def test_baseline_options_are_mutually_exclusive(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"schema_version": 1, "findings": []}', encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "clean_server"),
            "--baseline",
            str(baseline),
            "--write-baseline",
            str(tmp_path / "new.json"),
        ],
    )
    assert result.exit_code == 2
    assert "cannot be used" in result.output
    assert "together" in result.output


def test_markdown_format_produces_report():
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "vulnerable_server"), "--format", "markdown"],
    )
    assert "# mcp-triage scan report" in result.output
    assert "| Severity | Rule | Location | Finding |" in result.output


def test_malformed_baseline_fails_with_actionable_error(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{not json", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", str(FIXTURES / "clean_server"), "--baseline", str(baseline)],
    )
    assert result.exit_code == 2
    assert "Cannot read baseline" in result.output
    assert "Traceback" not in result.output
