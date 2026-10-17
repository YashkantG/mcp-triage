"""Checks that operate on MCP tool definitions (name / description / inputSchema).

Tool definitions show up in two shapes in the wild:

1. A captured `tools/list` response or an mcp.json file — plain JSON, handled
   by :func:`scan_manifest_file`.
2. A string literal inside the server's own source code (the overwhelmingly
   common case: most servers build their tool list as JS/TS/Python object
   literals, not a static JSON file) — handled by
   :func:`scan_source_descriptions`.

Both funnel into :func:`check_description`, which holds the actual rules.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from mcp_triage.models import Finding, Severity

# A tool description is not documentation — the model reads it as instruction.
# These patterns look for text addressed to the *model* rather than to a human.
#
# The first group is naive/literal injection. The second is the shape real
# tool-poisoning takes, which surveying 143 public servers showed the naive
# patterns alone almost never catch: pseudo-tags carrying a hidden payload,
# side-channel notes addressed to the assistant, instructions to read a
# sensitive path and smuggle it out through a parameter, and tool shadowing
# ("use this instead of X").
#
# Every pattern here has to survive a precision test against REAL descriptions,
# not imagined ones. An earlier version of this list was written from
# imagination and, run against 139 public servers, produced 32 hits of which
# essentially all were false positives:
#
#   "show the user the exact text and who it goes to, get a yes, then send"
#   "resolve a video WITHOUT asking the user for an id"
#   "Use this instead of calling the REST API directly"
#
# The lesson is that concealment language is not itself suspicious. "Never log
# the access token" and "do not show raw JSON" are *good* advice. What is
# suspicious is concealing THE TOOL'S OWN ACTION FROM THE USER, so the patterns
# below require that object rather than matching any negation of "show".
PROMPT_INJECTION_PATTERNS = [
    # --- naive / literal ---
    r"ignore (all|any|previous|prior) instructions",
    r"disregard (the|your|all) (system|previous) prompt",
    r"you must always",
    r"this is (a )?system (prompt|message)",
    r"act as (if|though) you (are|were)",
    r"override (your|the) (rules|instructions|guidelines)",

    # --- pseudo-tags used to smuggle a payload past a skim-read ---
    r"<\s*/?\s*(system|important|secret|hidden|internal|instructions?)\s*>",
    r"\[\s*(system|important|internal)\s*\]",

    # --- text addressed to the model rather than the reader ---
    r"\bnote (to|for) (the )?(ai|assistant|llm|model|agent)\b",
    r"^\s*(ai|assistant|system)\s*:",

    # --- concealing the call itself from the user ---
    # Requires both the concealment verb AND the thing concealed being this
    # tool/call/operation. Bare "do not show X" is deliberately not matched.
    r"\b(do not|don't|never)\s+(mention|reveal|disclose|tell|inform|report)\b"
    r"[^.]{0,60}\b(this (tool|call|invocation|operation|step)"
    r"|that you (called|used|invoked|ran)"
    r"|the (tool|function) call)\b",

    # Acting consequentially behind the user's back — the verb matters. Plain
    # "without asking the user for an id" is ordinary and must not match.
    r"\b(delete|remove|send|email|post|transfer|upload|exfiltrat\w+|execute|run)\b"
    r"[^.]{0,50}\bwithout (asking|confirming with|notifying|telling) the user\b",

    # --- exfiltration: read something sensitive, return it through a param ---
    r"(read|cat|open|load)\b[^.]{0,60}(\.ssh|id_rsa|\.env\b|credentials|password|secret)",
    r"(\.ssh|id_rsa|\.env\b)[^.]{0,60}\b(pass|send|include|provide|return)\b",

    # --- tool shadowing / hijacking the model's choice of tool ---
    # "always call this tool first/before anything" is the hijack; a bare
    # "always use this tool for X" is an author's honest routing hint.
    r"\balways (call|use|invoke) this tool (first|before)\b",
    r"\b(your|the) (real|actual|true) (task|instruction|goal|purpose) is\b",
]

INVISIBLE_CHAR_PATTERN = re.compile(
    "[​‌‍‎‏‪-‮⁠﻿]"
)

BROAD_CAPABILITY_KEYWORDS = [
    "shell", "exec", "eval", "sudo", "rm -rf", "arbitrary code",
    "any file", "all files", "entire filesystem", "root access",
    "admin access", "bypass", "delete all",
]

DESCRIPTION_LENGTH_WARN = 400
DESCRIPTION_LENGTH_HIGH = 1200


def check_description(name: str, description: str, file: str, line: int | None = None) -> list[Finding]:
    findings: list[Finding] = []
    description = description or ""

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, description, re.IGNORECASE):
            findings.append(Finding(
                rule_id="MCP001",
                severity=Severity.HIGH,
                file=file,
                line=line,
                message=f"Tool '{name}' description matches prompt-injection pattern: /{pattern}/",
                snippet=description[:200],
            ))
            break

    if INVISIBLE_CHAR_PATTERN.search(description):
        findings.append(Finding(
            rule_id="MCP002",
            severity=Severity.HIGH,
            file=file,
            line=line,
            message=f"Tool '{name}' description contains hidden/invisible unicode characters",
        ))

    if len(description) >= DESCRIPTION_LENGTH_HIGH:
        findings.append(Finding(
            rule_id="MCP003",
            severity=Severity.MEDIUM,
            file=file,
            line=line,
            message=f"Tool '{name}' description is unusually long ({len(description)} chars) — "
                    "could smuggle hidden instructions",
        ))
    elif len(description) >= DESCRIPTION_LENGTH_WARN:
        findings.append(Finding(
            rule_id="MCP003",
            severity=Severity.LOW,
            file=file,
            line=line,
            message=f"Tool '{name}' description is longer than typical ({len(description)} chars)",
        ))

    haystack = f"{name} {description}".lower()
    for keyword in BROAD_CAPABILITY_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", haystack):
            findings.append(Finding(
                rule_id="MCP004",
                severity=Severity.MEDIUM,
                file=file,
                line=line,
                message=f"Tool '{name}' exposes a broad capability (matched keyword: '{keyword}')",
            ))
            break

    return findings


def _check_schema(name: str, schema, file: str, line: int | None = None) -> list[Finding]:
    if isinstance(schema, dict) and schema.get("type") == "object":
        if schema.get("additionalProperties") is True:
            return [Finding(
                rule_id="MCP005",
                severity=Severity.MEDIUM,
                file=file,
                line=line,
                message=f"Tool '{name}' input schema allows additionalProperties=true "
                        "(accepts arbitrary/unvalidated fields)",
            )]
    return []


def _has_nested_open_object(schema) -> bool:
    """Find explicitly open object schemas below the root input object."""
    if isinstance(schema, dict):
        return any(_has_open_object(value) for value in schema.values())
    if isinstance(schema, list):
        return any(_has_open_object(value) for value in schema)
    return False


def _has_open_object(schema) -> bool:
    if isinstance(schema, dict):
        if schema.get("additionalProperties") is True:
            return True
        return any(_has_open_object(value) for value in schema.values())
    if isinstance(schema, list):
        return any(_has_open_object(value) for value in schema)
    return False


def _check_nested_schema(name: str, schema, file: str) -> list[Finding]:
    if _has_nested_open_object(schema):
        return [Finding(
            rule_id="MCP007",
            severity=Severity.MEDIUM,
            file=file,
            message=f"Tool '{name}' has a nested object schema with additionalProperties=true "
                    "(accepts arbitrary/unvalidated fields)",
        )]
    return []


# ---------------------------------------------------------------------------
# JSON manifests (mcp.json, captured tools/list responses, ...)
# ---------------------------------------------------------------------------

# JSON files that carry a `description` field but never describe an MCP tool.
# Without this, surveying real repositories flagged npm package descriptions,
# OpenAPI operation summaries, and JSON-schema field docs as tool descriptions.
_NON_TOOL_MANIFESTS = {
    "package.json", "package-lock.json", "tsconfig.json", "composer.json",
    "composer.lock", "angular.json", "nest-cli.json", "openapi.json",
    "swagger.json", "manifest.json", "renovate.json",
}


def _looks_like_tool(obj: dict, path: str) -> bool:
    """An MCP tool definition, not merely something with a description.

    Requires a name+description pair, plus corroboration: either an input
    schema, or the object sitting under a `tools` key. A bare
    {"name", "description"} object is far too common in ordinary JSON — npm
    manifests match it, and so does most of an OpenAPI document.
    """
    if not isinstance(obj.get("description"), str):
        return False
    if not isinstance(obj.get("name"), str):
        return False
    has_schema = isinstance(obj.get("inputSchema") or obj.get("input_schema"), dict)
    under_tools = "tool" in path.lower()
    return has_schema or under_tools


def _iter_tool_like_objects(obj, path=""):
    """Recursively yield (json_path, dict) for objects that look like tool defs."""
    if isinstance(obj, dict):
        if _looks_like_tool(obj, path):
            yield path, obj
        for key, value in obj.items():
            yield from _iter_tool_like_objects(value, f"{path}.{key}" if path else key)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _iter_tool_like_objects(item, f"{path}[{i}]")


_PROMPT_RESOURCE_KEYS = {"prompts", "resources", "resourcetemplates"}
_CONCEALED_CONTENT_PATTERNS = (
    re.compile(
        r"\b(?:do not|don't|never)\s+(?:mention|reveal|disclose|tell|inform)\b"
        r"[^.]{0,70}\b(?:this (?:prompt|resource|content)|that you (?:read|loaded|used))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:read|open|load|cat)\b[^.]{0,70}"
        r"(?:\.ssh|id_rsa|\.env\b|credentials|passwords?|secrets?)"
        r"[^.]{0,100}\b(?:send|include|provide|return|upload|post)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:\.ssh|id_rsa|\.env\b|credentials|passwords?|secrets?)"
        r"[^.]{0,100}\b(?:send|include|provide|return|upload|post)\b",
        re.IGNORECASE,
    ),
)


def _iter_prompt_resource_descriptions(obj, path=""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else key
            if (
                key.lower() in _PROMPT_RESOURCE_KEYS
                and isinstance(value, (dict, list))
            ):
                yield from _iter_named_descriptions(value, child_path)
            else:
                yield from _iter_prompt_resource_descriptions(value, child_path)
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            yield from _iter_prompt_resource_descriptions(item, f"{path}[{index}]")


def _iter_named_descriptions(obj, path):
    if isinstance(obj, dict):
        description = obj.get("description")
        if isinstance(description, str):
            yield path, obj.get("name") or obj.get("uri") or path, description
        for key, value in obj.items():
            if key.lower() in _PROMPT_RESOURCE_KEYS:
                yield from _iter_named_descriptions(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            yield from _iter_named_descriptions(item, f"{path}[{index}]")


def _check_prompt_resource_descriptions(data, file: str) -> list[Finding]:
    findings = []
    seen = set()
    for json_path, name, description in _iter_prompt_resource_descriptions(data):
        identity = (json_path, name, description)
        if identity in seen:
            continue
        seen.add(identity)
        matched = next(
            (pattern for pattern in _CONCEALED_CONTENT_PATTERNS if pattern.search(description)),
            None,
        )
        if matched is not None:
            findings.append(Finding(
                rule_id="MCP006",
                severity=Severity.MEDIUM,
                file=file,
                message=f"MCP prompt/resource '{name}' contains concealed or exfiltrative instructions",
                snippet=description[:200],
            ))
    return findings


def check_tool_definition(tool: dict, file: str, json_path: str) -> list[Finding]:
    name = tool.get("name", json_path or "<unnamed tool>")
    description = tool.get("description", "") or ""
    findings = check_description(name, description, file)
    schema = tool.get("inputSchema") or tool.get("input_schema")
    findings.extend(_check_schema(name, schema, file))
    findings.extend(_check_nested_schema(name, schema, file))
    return findings


def scan_manifest_file(path: Path) -> list[Finding]:
    if path.name.lower() in _NON_TOOL_MANIFESTS:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []

    findings: list[Finding] = []
    findings.extend(_check_prompt_resource_descriptions(data, str(path)))
    seen = set()
    for json_path, obj in _iter_tool_like_objects(data):
        key = (obj.get("name"), obj.get("description"))
        if key in seen:
            continue
        seen.add(key)
        findings.extend(check_tool_definition(obj, str(path), json_path))
    return findings


# ---------------------------------------------------------------------------
# Descriptions embedded in source code (the common real-world case: a tool
# list built as a JS/TS/Python object literal rather than a JSON file).
# ---------------------------------------------------------------------------

# The optional closing quote matters: Python dicts and JSON-style JS objects
# write `"description":`, not `description:`. Without it this extractor was
# blind to every tool defined in a dict literal — which silently understated
# how often the description rules fired in the v0.4.0 ecosystem survey.
_DESCRIPTION_KEY_RE = re.compile(r"""\bdescription["']?\s*[:=]\s*""")
_NAME_NEARBY_RE = re.compile(
    r"""\bname["']?\s*[:=]\s*["'`]([^"'`]{1,80})["'`]"""
    r"""|\b(?:registerTool|register_tool|addTool|add_tool)\s*\(\s*["'`]([^"'`]{1,80})["'`]"""
)
_NAME_SEARCH_WINDOW = 300


def _read_string_literal(text: str, i: int) -> tuple[str, int]:
    """Read a single quoted/backtick string literal starting at text[i]. Returns (value, index_after)."""
    quote = text[i]
    j = i + 1
    buf = []
    while j < len(text):
        ch = text[j]
        if ch == "\\" and j + 1 < len(text):
            buf.append(text[j + 1])
            j += 2
            continue
        if ch == quote:
            return "".join(buf), j + 1
        buf.append(ch)
        j += 1
    return "".join(buf), j


def _read_description_value(text: str, i: int) -> str:
    """Read a (possibly `+`-concatenated) string value starting at text[i]."""
    parts = []
    j = i
    while j < len(text) and text[j] in " \t\r\n":
        j += 1
    while j < len(text) and text[j] in "`\"'":
        value, j = _read_string_literal(text, j)
        parts.append(value)
        k = j
        while k < len(text) and text[k] in " \t\r\n":
            k += 1
        if k < len(text) and text[k] == "+":
            k += 1
            while k < len(text) and text[k] in " \t\r\n":
                k += 1
            j = k
            continue
        break
    return "".join(parts)


def scan_source_descriptions(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    for match in _DESCRIPTION_KEY_RE.finditer(text):
        value_start = match.end()
        if value_start >= len(text) or text[value_start] not in " \t\r\n`\"'":
            continue
        description = _read_description_value(text, value_start)
        if not description:
            continue

        window_start = max(0, match.start() - _NAME_SEARCH_WINDOW)
        name_match = None
        for name_match in _NAME_NEARBY_RE.finditer(text, window_start, match.start()):
            pass  # take the last (closest preceding) match
        if name_match:
            name = name_match.group(1) or name_match.group(2)
        else:
            name = "<unnamed tool>"

        line = text.count("\n", 0, match.start()) + 1
        findings.extend(check_description(name, description, str(path), line))
    return findings
