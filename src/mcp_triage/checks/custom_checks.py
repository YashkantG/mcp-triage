"""Runs user-defined custom rules (from .mcptriage.toml `[[custom_rules]]`)
against source files. This is the escape hatch for internal, company-specific
checks — a banned internal API, a legacy secret prefix, a deprecated helper —
without anyone needing to fork the tool.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_triage.config import CustomRule
from mcp_triage.models import Finding


def scan_with_custom_rules(path: Path, custom_rules: list) -> list:
    if not custom_rules or path.suffix not in {r for cr in custom_rules for r in cr.suffixes}:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    findings = []
    compiled = [(cr, re.compile(cr.pattern)) for cr in custom_rules if path.suffix in cr.suffixes]
    for lineno, line in enumerate(lines, start=1):
        for cr, pattern in compiled:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=cr.id,
                    severity=cr.severity,
                    file=str(path),
                    line=lineno,
                    message=cr.message,
                    snippet=line.strip()[:160],
                ))
    return findings
