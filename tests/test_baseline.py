from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_triage.baseline import BaselineError, new_findings, write_baseline
from mcp_triage.models import Finding, Severity


def _finding(file: Path, line: int, message: str, snippet: str | None = None) -> Finding:
    return Finding(
        rule_id="MCP102",
        severity=Severity.HIGH,
        file=str(file),
        line=line,
        message=message,
        snippet=snippet,
    )


def test_baseline_matches_across_line_shifts_without_storing_snippets(tmp_path):
    source = tmp_path / "server.py"
    root = tmp_path
    first = _finding(source, 2, "Shell command call", "token=secret-value")
    baseline = tmp_path / ".mcp-triage-baseline.json"
    write_baseline([first], baseline, root)

    saved = json.loads(baseline.read_text(encoding="utf-8"))
    assert saved["schema_version"] == 1
    assert "secret-value" not in baseline.read_text(encoding="utf-8")

    shifted = _finding(source, 20, "Shell command call", "token=other-secret")
    new = _finding(source, 22, "Different shell command call")
    assert new_findings([shifted, new], baseline, root) == [new]


def test_duplicate_findings_preserve_baseline_multiplicity(tmp_path):
    source = tmp_path / "server.py"
    finding = _finding(source, 1, "Repeated call")
    baseline = tmp_path / "baseline.json"
    write_baseline([finding], baseline, tmp_path)

    assert new_findings([finding, finding], baseline, tmp_path) == [finding]


def test_malformed_baseline_fails_explicitly(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"schema_version": 99, "findings": []}', encoding="utf-8")

    with pytest.raises(BaselineError, match="unsupported baseline format"):
        new_findings([], baseline, tmp_path)


def test_unwritable_baseline_fails_explicitly(tmp_path):
    baseline = tmp_path / "missing" / "baseline.json"

    with pytest.raises(BaselineError, match="Cannot write baseline"):
        write_baseline([], baseline, tmp_path)
