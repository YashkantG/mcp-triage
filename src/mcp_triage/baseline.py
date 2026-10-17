"""Stable, local finding baselines for incremental CI scans."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path

from mcp_triage import __version__
from mcp_triage.models import Finding

_SCHEMA_VERSION = 1
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class BaselineError(ValueError):
    """Raised when a finding baseline cannot be read or written safely."""


def _relative_file(file: str, root: Path) -> str:
    path = Path(file).resolve()
    try:
        return path.relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _fingerprint(finding: Finding, root: Path) -> str:
    identity = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "file": _relative_file(finding.file, root),
        "message": finding.message,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _counts(findings: list[Finding], root: Path) -> Counter:
    return Counter(_fingerprint(finding, root) for finding in findings)


def new_findings(
    findings: list[Finding],
    baseline_path: Path,
    root: Path,
) -> list[Finding]:
    """Return findings not present in a validated baseline.

    Line numbers and snippets are intentionally excluded from fingerprints:
    moving an unchanged issue within a file should not make it new, and snippets
    may contain credentials that should never be copied into a baseline file.
    Duplicate findings retain their multiplicity.
    """
    baseline = _load_counts(baseline_path)
    remaining = baseline.copy()
    new = []
    for finding in findings:
        fingerprint = _fingerprint(finding, root)
        if remaining[fingerprint]:
            remaining[fingerprint] -= 1
        else:
            new.append(finding)
    return new


def write_baseline(findings: list[Finding], path: Path, root: Path) -> None:
    """Atomically write a versioned baseline without storing code snippets."""
    fingerprints = _counts(findings, root)
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "tool_version": __version__,
        "findings": [
            {"fingerprint": fingerprint, "count": count}
            for fingerprint, count in sorted(fingerprints.items())
        ],
    }
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(payload, output, indent=2)
            output.write("\n")
        os.replace(temporary_path, path)
    except OSError as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise BaselineError(f"Cannot write baseline {path}: {exc}") from exc


def _load_counts(path: Path) -> Counter:
    try:
        with path.open(encoding="utf-8") as source:
            payload = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Cannot read baseline {path}: {exc}") from exc

    schema_version = payload.get("schema_version") if isinstance(payload, dict) else None
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != _SCHEMA_VERSION
    ):
        raise BaselineError(
            f"{path}: unsupported baseline format; expected schema_version "
            f"{_SCHEMA_VERSION}"
        )
    entries = payload.get("findings")
    if not isinstance(entries, list):
        raise BaselineError(f"{path}: 'findings' must be an array")

    counts = Counter()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise BaselineError(f"{path}: findings[{index}] must be an object")
        fingerprint = entry.get("fingerprint")
        count = entry.get("count")
        if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
            raise BaselineError(f"{path}: findings[{index}].fingerprint is invalid")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise BaselineError(f"{path}: findings[{index}].count must be a positive integer")
        counts[fingerprint] += count
    return counts
