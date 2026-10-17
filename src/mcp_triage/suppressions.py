"""Inline suppression comments, e.g.:

    subprocess.run(cmd, shell=True)  # mcp-triage: ignore[MCP102]
    subprocess.run(cmd, shell=True)  # mcp-triage: ignore

The bracketed form suppresses only the listed rule IDs on that line; the
bare form suppresses everything mcp-triage would otherwise flag there.
Findings with no line number (most JSON-manifest and config findings)
aren't eligible — there's no line to attach a comment to.
"""
from __future__ import annotations

import re
from pathlib import Path

_SUPPRESS_RE = re.compile(r"mcp-triage:\s*ignore(?:\[([A-Za-z0-9,\s]+)\])?", re.IGNORECASE)


def _read_lines(path: str) -> tuple:
    try:
        return tuple(Path(path).read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return ()


def is_suppressed(file: str, line: int, rule_id: str) -> bool:
    return _matches(_read_lines(file), line, rule_id)


def _matches(lines: tuple, line: int, rule_id: str) -> bool:
    if not lines or not (1 <= line <= len(lines)):
        return False
    match = _SUPPRESS_RE.search(lines[line - 1])
    if not match:
        return False
    rule_list = match.group(1)
    if rule_list is None:
        return True
    ids = {r.strip().upper() for r in rule_list.split(",")}
    return rule_id in ids


def filter_suppressed(findings: list) -> list:
    lines_by_file = {}
    kept = []
    for finding in findings:
        if finding.line is None:
            kept.append(finding)
            continue
        if finding.file not in lines_by_file:
            lines_by_file[finding.file] = _read_lines(finding.file)
        if not _matches(lines_by_file[finding.file], finding.line, finding.rule_id):
            kept.append(finding)
    return kept
