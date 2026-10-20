"""Read-only audit of locally configured MCP servers."""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from mcp_triage.models import Finding, Severity

_SERVER_MAP_KEYS = {"mcpservers", "servers"}
_SECRET_KEY = re.compile(
    r"(?:api|access|auth|client|private|secret|token|password|credential|key)",
    re.IGNORECASE,
)
_PLACEHOLDERS = (
    "${", "$env:", "process.env", "os.environ", "getenv", "example",
    "placeholder", "changeme", "your_", "your-", "mock", "dummy",
    "fake", "sample", "redacted", "notreal", "not-a-real",
)
_HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOWNLOAD_PIPE = re.compile(
    r"(?:\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"
    r"|\b(?:sh|bash|zsh)\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b)",
    re.IGNORECASE,
)
_EXACT_NPM_VERSION = re.compile(r"@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")
_EXACT_PYTHON_VERSION = re.compile(r"==\s*\d+(?:\.\d+){1,3}(?:[A-Za-z0-9.+-]*)$")


@dataclass(frozen=True)
class ConfiguredServer:
    name: str
    config_file: str


@dataclass(frozen=True)
class AuditResult:
    config_files: list[str]
    servers: list[ConfiguredServer]
    findings: list[Finding]
    errors: list[str]


def default_config_paths(
    home: Path | None = None,
    platform_name: str | None = None,
    cwd: Path | None = None,
    environ: dict[str, str] | None = None,
) -> list[Path]:
    """Return known MCP config paths for common desktop clients."""
    home = (home or Path.home()).expanduser()
    platform_name = platform_name or sys.platform
    cwd = (cwd or Path.cwd()).expanduser()
    environ = environ or os.environ
    paths = []

    if platform_name == "darwin":
        app_support = home / "Library" / "Application Support"
        paths.extend([
            app_support / "Claude" / "claude_desktop_config.json",
            app_support / "Code" / "User" / "mcp.json",
            app_support / "Code - Insiders" / "User" / "mcp.json",
        ])
    elif platform_name.startswith("win"):
        app_data = Path(environ.get("APPDATA", home / "AppData" / "Roaming"))
        paths.extend([
            app_data / "Claude" / "claude_desktop_config.json",
            app_data / "Code" / "User" / "mcp.json",
            app_data / "Code - Insiders" / "User" / "mcp.json",
        ])
    else:
        config_home = Path(environ.get("XDG_CONFIG_HOME", home / ".config"))
        paths.extend([
            config_home / "Claude" / "claude_desktop_config.json",
            config_home / "Code" / "User" / "mcp.json",
            config_home / "Code - Insiders" / "User" / "mcp.json",
        ])

    paths.extend([
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / ".gemini" / "settings.json",
        cwd / ".mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
    ])
    unique = []
    seen = set()
    for path in paths:
        normalized = path.expanduser()
        key = str(normalized)
        if key not in seen:
            seen.add(key)
            unique.append(normalized)
    return unique


def _server_entries(value):
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if key.casefold() in _SERVER_MAP_KEYS and isinstance(child, dict):
            for name, server in child.items():
                if isinstance(server, dict):
                    yield str(name), server
        yield from _server_entries(child)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _is_placeholder(value: str) -> bool:
    lowered = value.casefold()
    return any(hint in lowered for hint in _PLACEHOLDERS)


def _credential_findings(server_name: str, server: dict, config_file: str) -> list[Finding]:
    findings = []
    for key, value in _key_values(server):
        if _SECRET_KEY.search(str(key)) and isinstance(value, str) and value.strip() and not _is_placeholder(value):
            findings.append(Finding(
                rule_id="MCP201",
                severity=Severity.HIGH,
                file=config_file,
                message=(
                    f"Server '{server_name}' has a credential-like value in its "
                    "configuration (value redacted)"
                ),
            ))
    return findings


def _key_values(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _key_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _key_values(child)


def _command_tokens(server: dict) -> list[str]:
    command = server.get("command")
    args = server.get("args", [])
    if isinstance(command, str):
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
    elif isinstance(command, list):
        tokens = [str(token) for token in command]
    else:
        tokens = []
    if isinstance(args, list):
        tokens.extend(str(token) for token in args)
    elif isinstance(args, str):
        try:
            tokens.extend(shlex.split(args))
        except ValueError:
            tokens.extend(args.split())
    return tokens


def _package_is_pinned(tokens: list[str], executable: str) -> bool:
    if executable == "npx":
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token in {"--package", "-p"}:
                return (
                    index + 1 < len(tokens)
                    and bool(_EXACT_NPM_VERSION.search(tokens[index + 1]))
                )
            if token.startswith("--package="):
                return bool(_EXACT_NPM_VERSION.search(token.split("=", 1)[1]))
            if token.startswith("-"):
                index += 1
                continue
            return bool(_EXACT_NPM_VERSION.search(token))
        return False

    for index, token in enumerate(tokens[1:], start=1):
        if token in {"--from", "-f"} and index + 1 < len(tokens):
            if _EXACT_PYTHON_VERSION.search(tokens[index + 1]):
                return True
        elif token.startswith("--from="):
            if _EXACT_PYTHON_VERSION.search(token.split("=", 1)[1]):
                return True
        elif not token.startswith("-") and _EXACT_PYTHON_VERSION.search(token):
            return True
    return False


def _is_local_host(host: str | None) -> bool:
    if not host:
        return True
    host = host.strip("[]").casefold()
    if host == "localhost" or host.endswith(".localhost") or host == "::1":
        return True
    if host.startswith("127."):
        return True
    return False


def _is_whole_home_mount(value: str, home: Path) -> bool:
    home_path = str(home.resolve())
    normalized = value.replace("\\", "/")
    for segment in re.split(r"[:,\s,]", normalized):
        cleaned = segment.strip("\"'")
        if "=" in cleaned:
            key, candidate = cleaned.split("=", 1)
            if key.casefold() in {"source", "src"}:
                cleaned = candidate
        if cleaned in {"/", "~", home_path}:
            return True
    if normalized.startswith(f"{home_path}:") or f"source={home_path}," in normalized:
        return True
    return False


def _audit_server(
    name: str,
    server: dict,
    config_file: str,
    home: Path,
) -> list[Finding]:
    findings = _credential_findings(name, server, config_file)
    tokens = _command_tokens(server)
    command_name = Path(tokens[0]).name.casefold() if tokens else ""
    executable = command_name
    for suffix in (".cmd", ".exe", ".bat", ".ps1"):
        if executable.endswith(suffix):
            executable = executable[:-len(suffix)]
            break

    if executable in {"npx", "uvx"} and not _package_is_pinned(tokens, executable):
        findings.append(Finding(
            rule_id="MCP303",
            severity=Severity.MEDIUM,
            file=config_file,
            message=f"Server '{name}' uses {command_name} without an exact package version pin",
        ))

    command_text = " ".join(tokens)
    if _DOWNLOAD_PIPE.search(command_text):
        findings.append(Finding(
            rule_id="MCP304",
            severity=Severity.HIGH,
            file=config_file,
            message=f"Server '{name}' downloads a script and pipes it to a shell",
        ))

    urls = list(_strings(server))
    for value in urls:
        for match in _HTTP_URL.finditer(value):
            parsed = urlparse(match.group(0).rstrip(".,);"))
            if parsed.scheme.casefold() == "http" and not _is_local_host(parsed.hostname):
                findings.append(Finding(
                    rule_id="MCP305",
                    severity=Severity.MEDIUM,
                    file=config_file,
                    message=f"Server '{name}' connects to a non-local endpoint over plain HTTP",
                ))
                break
        else:
            continue
        break

    elevated = command_name == "sudo" or any(
        Path(token).name.casefold() == "sudo" for token in tokens[:3]
    )
    broad_access = any(_is_whole_home_mount(value, home) for value in _strings(server))
    if elevated or broad_access:
        reason = "runs with elevated privileges" if elevated else "is granted access to the root or home directory"
        findings.append(Finding(
            rule_id="MCP306",
            severity=Severity.HIGH,
            file=config_file,
            message=f"Server '{name}' {reason}",
        ))
    return findings


def audit_local(
    paths: list[Path] | None = None,
    home: Path | None = None,
    platform_name: str | None = None,
    cwd: Path | None = None,
    environ: dict[str, str] | None = None,
) -> AuditResult:
    """Read known MCP config files or explicit paths without printing values."""
    home = (home or Path.home()).expanduser()
    candidates = paths if paths is not None else default_config_paths(
        home=home,
        platform_name=platform_name,
        cwd=cwd,
        environ=environ,
    )
    config_files = []
    servers = []
    findings = []
    errors = []
    for path in candidates:
        if not path.is_file():
            if paths is not None:
                errors.append(f"Configuration file not found: {path}")
            continue
        path = path.resolve()
        display_path = str(path)
        config_files.append(display_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"Cannot read configuration {path}: {exc}")
            continue
        entries = list(_server_entries(data))
        for name, server in entries:
            servers.append(ConfiguredServer(name=name, config_file=display_path))
            findings.extend(_audit_server(name, server, display_path, home))
    return AuditResult(
        config_files=config_files,
        servers=servers,
        findings=findings,
        errors=errors,
    )
