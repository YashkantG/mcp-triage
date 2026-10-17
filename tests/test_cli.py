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
    all_high_rules = ["MCP001", "MCP101", "MCP102", "MCP103", "MCP201", "MCP302"]
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
    assert "choose from table, json, sarif, or badge" in result.output


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
