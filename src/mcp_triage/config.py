"""Project-level configuration: .mcptriage.toml.

Lets a team check in what "accepted risk" looks like for their repo instead
of relying purely on CLI flags or editing the source they're scanning.

    [ignore]
    rules = ["MCP003", "MCP004"]
    paths = ["tests/fixtures/**", "vendor/**"]

    [severity]
    MCP004 = "LOW"
"""
from __future__ import annotations

import fnmatch
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from mcp_triage.models import Finding, Severity

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_FILENAME = ".mcptriage.toml"


class ConfigError(ValueError):
    """Raised when a project configuration cannot be used safely."""


@dataclass
class CustomRule:
    id: str
    pattern: str
    message: str
    severity: Severity = Severity.MEDIUM
    suffixes: tuple[str, ...] = (".py", ".js", ".ts", ".mjs", ".cjs")


@dataclass
class Config:
    ignored_rules: set[str] = field(default_factory=set)
    ignored_paths: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    custom_rules: list[CustomRule] = field(default_factory=list)
    root: Path | None = None

    def path_is_ignored(self, file: str) -> bool:
        normalized = file.replace("\\", "/")
        candidates = [normalized]
        if self.root is not None:
            try:
                relative = Path(file).resolve().relative_to(self.root.resolve())
            except ValueError:
                pass
            else:
                candidates.append(relative.as_posix())
        return any(
            fnmatch.fnmatch(candidate, pattern)
            for candidate in candidates
            for pattern in self.ignored_paths
        )

    def apply(self, findings: list[Finding]) -> list[Finding]:
        kept = []
        for finding in findings:
            if finding.rule_id in self.ignored_rules:
                continue
            if self.path_is_ignored(finding.file):
                continue
            override = self.severity_overrides.get(finding.rule_id)
            if override is not None:
                finding = _with_severity(finding, override)
            kept.append(finding)
        return kept


def _with_severity(finding: Finding, severity: Severity) -> Finding:
    from dataclasses import replace
    return replace(finding, severity=severity)


def _string_list(value, key: str, config_path: Path) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{config_path}: '{key}' must be an array of strings")
    return value


def _severity(value, key: str, config_path: Path) -> Severity:
    if not isinstance(value, str):
        raise ConfigError(f"{config_path}: '{key}' must be HIGH, MEDIUM, or LOW")
    try:
        return Severity(value.upper())
    except ValueError as exc:
        raise ConfigError(
            f"{config_path}: '{key}' must be HIGH, MEDIUM, or LOW (got {value!r})"
        ) from exc


def load_config(root: Path, config_path: Path | None = None) -> Config:
    """Load configuration for a scan rooted at `root`.

    An explicit config path may point to the TOML file or its containing
    directory. Relative ignore globs are always resolved against the scan root.
    """
    scan_root = root if root.is_dir() else root.parent
    scan_root = scan_root.resolve()
    if config_path is None:
        selected_config = scan_root / CONFIG_FILENAME
    elif config_path.is_dir():
        selected_config = config_path / CONFIG_FILENAME
    else:
        selected_config = config_path

    if not selected_config.is_file():
        return Config(root=scan_root)

    try:
        with open(selected_config, "rb") as f:
            data = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise ConfigError(f"Cannot read configuration {selected_config}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{selected_config}: configuration must be a TOML table")

    ignore = data.get("ignore", {})
    severity_data = data.get("severity", {})
    if not isinstance(ignore, dict):
        raise ConfigError(f"{selected_config}: [ignore] must be a TOML table")
    if not isinstance(severity_data, dict):
        raise ConfigError(f"{selected_config}: [severity] must be a TOML table")

    ignored_rules = {
        rule.upper()
        for rule in _string_list(
            ignore.get("rules", []), "ignore.rules", selected_config
        )
    }
    ignored_paths = _string_list(
        ignore.get("paths", []), "ignore.paths", selected_config
    )
    severity_overrides = {
        rule: _severity(value, f"severity.{rule}", selected_config)
        for rule, value in severity_data.items()
    }

    raw_custom_rules = data.get("custom_rules", [])
    if not isinstance(raw_custom_rules, list):
        raise ConfigError(f"{selected_config}: [[custom_rules]] must be an array of tables")
    custom_rules = []
    for index, rule in enumerate(raw_custom_rules, start=1):
        key = f"custom_rules[{index}]"
        if not isinstance(rule, dict):
            raise ConfigError(f"{selected_config}: {key} must be a TOML table")
        for required in ("id", "pattern", "message"):
            if not isinstance(rule.get(required), str) or not rule[required]:
                raise ConfigError(
                    f"{selected_config}: {key}.{required} must be a non-empty string"
                )
        rule_severity = _severity(
            rule.get("severity", "MEDIUM"), f"{key}.severity", selected_config
        )
        suffixes = _string_list(
            rule.get("suffixes", [".py", ".js", ".ts", ".mjs", ".cjs"]),
            f"{key}.suffixes",
            selected_config,
        )
        try:
            re.compile(rule["pattern"])
        except re.error as exc:
            raise ConfigError(
                f"{selected_config}: invalid regex in {key}.pattern: {exc}"
            ) from exc
        custom_rules.append(
            CustomRule(
                id=rule["id"],
                pattern=rule["pattern"],
                message=rule["message"],
                severity=rule_severity,
                suffixes=tuple(suffixes),
            )
        )

    return Config(
        root=scan_root,
        ignored_rules=ignored_rules,
        ignored_paths=ignored_paths,
        severity_overrides=severity_overrides,
        custom_rules=custom_rules,
    )
