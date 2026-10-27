"""Regex-based detection of obviously hardcoded secrets/credentials."""
from __future__ import annotations

import re
from pathlib import Path

from mcp_triage.models import Finding, Severity

_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "Hardcoded credential assignment",
        # The optional prefix/suffix lets env-var style names through
        # (`ANTHROPIC_API_KEY`, `STRIPE_SECRET_KEY`, `GITHUB_PERSONAL_ACCESS_TOKEN`) —
        # exactly how MCP client configs pass credentials in their `env` blocks.
        # The trailing lookahead still rejects `max_tokens`, `token_count`, etc.
        re.compile(
            r"""(?i)(?<![a-z0-9])(?:[a-z0-9_-]{0,64}[_-])?(api[_-]?key|secret|password|token|access[_-]?key)"""
            r"""(?:[_-]access)?(?:[_-]key)?(?![a-z0-9_])["']?\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{12,}["']"""
        ),
    ),
]

# Provider-issued key formats (MCP202). Their prefixes are distinctive enough
# that a match is a key whatever it's assigned to — including the bare values in
# `args`, headers, and URLs that the assignment pattern above can't see.
_PROVIDER_KEY_PATTERNS = [
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,}")),
    (
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}")),
    ("GitLab access token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
]

# A line containing any of these is treated as a non-secret. Derived from a
# survey of 143 public MCP server repositories, where the overwhelming majority
# of MCP201 hits were fake credentials in tests, mock fixtures, and docs —
# things like `api_key: "local-mock-only-key"` or a dummy `ghp_...` token in a
# test asserting that redaction works.
#
# This deliberately trades recall for precision. A scanner that cries wolf on
# every mock credential gets switched off, and a switched-off scanner has a
# detection rate of zero.
#
# "<" used to be here too, but it skipped every line containing a TypeScript
# generic or a comparison (`Record<string, string>`); no pattern above can
# match a `<your-key>` style value anyway.
_PLACEHOLDER_HINTS = (
    "example", "xxxx", "changeme", "your_", "your-", "${",
    "process.env", "os.environ", "getenv", "mock", "fake", "dummy",
    "placeholder", "sample", "redacted", "not-a-real", "notreal",
    "test-", "-test", "test_", "_test", "local-", "localhost",
    "insert", "replace-me", "todo", "xxx",
)

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".lock"}


def scan_file_for_secrets(path: Path) -> list[Finding]:
    if path.suffix in SKIP_SUFFIXES:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        lowered = line.lower()
        if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
            continue
        # MCP201 is checked first so lines it already reported keep their
        # rule ID (and therefore their baseline fingerprint). One finding per line.
        for rule_id, patterns in (("MCP201", _SECRET_PATTERNS), ("MCP202", _PROVIDER_KEY_PATTERNS)):
            label = next((label for label, pattern in patterns if pattern.search(line)), None)
            if label is not None:
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=Severity.HIGH,
                    file=str(path),
                    line=lineno,
                    message=f"Possible hardcoded secret: {label}",
                    snippet=line.strip()[:160],
                ))
                break
    return findings
