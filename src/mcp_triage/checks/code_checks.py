"""Lightweight, regex-based static checks for dangerous patterns in MCP server
source code. This is intentionally not a full AST/taint analysis — it is a
fast first pass that flags lines worth a human look.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from mcp_triage.models import Finding, Severity

# (rule_id, severity, message, compiled pattern, file suffixes it applies to)
#
# The human-readable messages below necessarily contain the very constructs
# they describe, so several of them trip their own rules when mcp-triage is
# pointed at itself. Suppressed inline rather than excluded wholesale, so the
# rest of this file stays covered.
_CHECKS = [
    (
        # The negative lookbehind is load-bearing. `\b(eval|exec)\(` also matches
        # `pattern.exec(line)` — the ordinary JavaScript RegExp API — which
        # accounted for 77% of this rule's hits across 141 surveyed repositories.
        # A method call on an object is not the global eval/exec.
        "MCP101", Severity.HIGH, "Use of eval()/exec() on dynamic input",  # mcp-triage: ignore[MCP101]
        re.compile(r"(?<![.\w])(eval|exec)\s*\("), {".py", ".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP101", Severity.HIGH, "Dynamic Function construction (JS eval equivalent)",
        re.compile(r"\bnew\s+Function\s*\("), {".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP102", Severity.HIGH, "subprocess call with shell=True",
        re.compile(r"subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
        {".py"},
    ),
    (
        "MCP102", Severity.HIGH, "os.system() call",  # mcp-triage: ignore[MCP102]
        re.compile(r"\bos\.system\s*\("), {".py"},
    ),
    (
        # Same story: only a bare `exec(` (a destructured child_process import)
        # or an explicit child_process member call counts. `re.exec(s)` does not.
        "MCP102", Severity.HIGH, "child_process exec()/execSync() call",  # mcp-triage: ignore[MCP101]
        re.compile(
            r"(?<![.\w])execSync\s*\("
            r"|(?<![.\w])exec\s*\("
            r"|child_process[\"'\)\]]*\s*\.\s*exec"
            r"|\b(?:cp|childProcess|child)\s*\.\s*execSync?\s*\("
        ),
        {".js", ".ts", ".mjs", ".cjs"},
    ),
    (
        "MCP103", Severity.HIGH, "pickle.loads() on potentially untrusted data",  # mcp-triage: ignore[MCP103]
        re.compile(r"\bpickle\.loads?\s*\("), {".py"},
    ),
    (
        "MCP103", Severity.MEDIUM, "yaml.load() without a safe loader",  # mcp-triage: ignore[MCP103]
        re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"), {".py"},
    ),
]


def _ast_alias_shell_findings(path: Path, source: str, lines: list[str]) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    dangerous_functions = {"run", "call", "Popen", "check_call", "check_output"}

    class ScopeBindings(ast.NodeVisitor):
        def __init__(self):
            self.imports = {}
            self.other_bindings = set()

        def visit_Import(self, node):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                if alias.name == "subprocess":
                    self.imports[bound_name] = ("module", "subprocess")
                else:
                    self.other_bindings.add(bound_name)

        def visit_ImportFrom(self, node):
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if node.module == "subprocess" and alias.name in dangerous_functions:
                    self.imports[bound_name] = ("function", alias.name)
                else:
                    self.other_bindings.add(bound_name)

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                self.other_bindings.add(node.id)

        def visit_FunctionDef(self, node):
            self.other_bindings.add(node.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            self.other_bindings.add(node.name)

        def visit_Lambda(self, node):
            return

    class ScopedCallVisitor(ast.NodeVisitor):
        def __init__(self):
            self.scopes = []
            self.scope_kinds = []
            self.findings = []

        def _push_scope(self, bindings, kind):
            self.scopes.append(bindings)
            self.scope_kinds.append(kind)

        def _pop_scope(self):
            self.scopes.pop()
            self.scope_kinds.pop()

        def _bindings_for(self, nodes, arguments=()):
            collector = ScopeBindings()
            for node in nodes:
                collector.visit(node)
            bindings = dict(collector.imports)
            for name in collector.other_bindings | set(arguments):
                bindings[name] = None
            return bindings

        def _resolve(self, name):
            for bindings in reversed(self.scopes):
                if name in bindings:
                    return bindings[name]
            return None

        def visit_Module(self, node):
            self._push_scope(self._bindings_for(node.body), "module")
            for statement in node.body:
                self.visit(statement)
            self._pop_scope()

        def visit_FunctionDef(self, node):
            for expression in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
                if expression is not None:
                    self.visit(expression)
            arguments = {
                arg.arg
                for arg in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
            }
            if node.args.vararg:
                arguments.add(node.args.vararg.arg)
            if node.args.kwarg:
                arguments.add(node.args.kwarg.arg)
            if self.scope_kinds and self.scope_kinds[-1] == "class":
                class_bindings = self.scopes.pop()
                class_kind = self.scope_kinds.pop()
                dropped_class_scope = True
            else:
                dropped_class_scope = False
            self._push_scope(self._bindings_for(node.body, arguments), "function")
            for statement in node.body:
                self.visit(statement)
            self._pop_scope()
            if dropped_class_scope:
                self._push_scope(class_bindings, class_kind)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            for expression in (*node.decorator_list, *node.bases, *node.keywords):
                self.visit(expression)
            self._push_scope(self._bindings_for(node.body), "class")
            for statement in node.body:
                self.visit(statement)
            self._pop_scope()

        def visit_Lambda(self, node):
            for expression in (*node.args.defaults, *node.args.kw_defaults):
                if expression is not None:
                    self.visit(expression)
            arguments = {
                arg.arg
                for arg in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
            }
            if node.args.vararg:
                arguments.add(node.args.vararg.arg)
            if node.args.kwarg:
                arguments.add(node.args.kwarg.arg)
            self._push_scope(self._bindings_for([node.body], arguments), "lambda")
            self.visit(node.body)
            self._pop_scope()

        def visit_Call(self, node):
            function_name = None
            is_alias_call = False
            if isinstance(node.func, ast.Name):
                resolved = self._resolve(node.func.id)
                if resolved and resolved[0] == "function":
                    function_name = resolved[1]
                    is_alias_call = True
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                resolved = self._resolve(node.func.value.id)
                if resolved == ("module", "subprocess"):
                    function_name = node.func.attr
                    is_alias_call = node.func.value.id != "subprocess"

            if (
                is_alias_call
                and function_name in dangerous_functions
                and any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
            ):
                line = node.lineno
                snippet = lines[line - 1].strip()[:160] if 1 <= line <= len(lines) else ""
                self.findings.append(Finding(
                    rule_id="MCP104",
                    severity=Severity.HIGH,
                    file=str(path),
                    line=line,
                    message=(
                        f"Aliased subprocess.{function_name} call sets shell=True "
                        "(command may be interpreted by a shell)"
                    ),
                    snippet=snippet,
                ))
            self.generic_visit(node)

    visitor = ScopedCallVisitor()
    visitor.visit(tree)
    return visitor.findings


def scan_source_file(path: Path) -> list[Finding]:
    suffix = path.suffix
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    lines = source.splitlines()

    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule_id, severity, message, pattern, suffixes in _CHECKS:
            if suffix not in suffixes:
                continue
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    file=str(path),
                    line=lineno,
                    message=message,
                    snippet=stripped[:160],
                ))
    if suffix == ".py":
        findings.extend(_ast_alias_shell_findings(path, source, lines))
    return findings
