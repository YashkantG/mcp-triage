from mcp_triage.models import Finding, Severity
from mcp_triage.report import render_markdown


def test_markdown_report_escapes_table_delimiters_and_uses_relative_paths(tmp_path):
    finding = Finding(
        rule_id="CUSTOM001",
        severity=Severity.MEDIUM,
        file=str(tmp_path / "src" / "server.py"),
        line=7,
        message="<script>alert(1)</script> | value\non next line",
    )

    report = render_markdown([finding], tmp_path)

    assert (
        "| MEDIUM | CUSTOM001 (unknown rule) | src/server.py:7 | "
        "&lt;script&gt;alert(1)&lt;/script&gt; \\| value on next line |"
    ) in report
    assert report.count("\n| MEDIUM |") == 1


def test_markdown_report_handles_no_findings(tmp_path):
    report = render_markdown([], tmp_path)

    assert "**Findings:** 0" in report
    assert "| - | - | - | No issues found. |" in report


def test_markdown_baseline_report_explains_empty_diff(tmp_path):
    report = render_markdown([], tmp_path, baseline_comparison=True)

    assert "**Comparison:** New findings not present in the supplied baseline." in report
    assert "No new findings compared with the baseline." in report
