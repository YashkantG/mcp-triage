from __future__ import annotations

import os
from pathlib import Path

MANIFEST_NAMES = {"mcp.json", "claude_desktop_config.json", "mcp_config.json"}
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs"}

# Never scanned: not the project's own code.
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    "vendor", "third_party", "site-packages", ".tox", ".mypy_cache",
}

# Skipped by default, re-included with --include-tests.
#
# Surveying 143 public MCP servers showed the overwhelming majority of findings
# came from here rather than from shipped server code: fake credentials in
# redaction tests, `eval` in benchmark harnesses, deliberately-unsafe example
# snippets. Scanning them by default buries the findings that matter.
NON_PRODUCTION_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "e2e",
    "bench", "benchmark", "benchmarks",
    "example", "examples", "sample", "samples", "demo", "demos",
    "fixture", "fixtures", "testdata", "mocks", "__mocks__",
}


def _skipped(path: Path, include_tests: bool) -> bool:
    parts = set(path.parts)
    if parts & SKIP_DIRS:
        return True
    if not include_tests and parts & NON_PRODUCTION_DIRS:
        return True
    return False


def iter_files(target: Path, include_tests: bool = False):
    if target.is_file():
        yield target
        return
    for current_root, directories, filenames in os.walk(target, topdown=True):
        current_path = Path(current_root)
        relative_root = current_path.relative_to(target)
        directories[:] = sorted(
            name for name in directories
            if not _skipped(relative_root / name, include_tests)
        )
        for filename in sorted(filenames):
            relative_path = relative_root / filename
            path = current_path / filename
            if not _skipped(relative_path, include_tests) and path.is_file():
                yield path


def find_manifests(target: Path, include_tests: bool = False) -> list[Path]:
    return [p for p in iter_files(target, include_tests) if p.name in MANIFEST_NAMES]


def find_source_files(target: Path, include_tests: bool = False) -> list[Path]:
    return [p for p in iter_files(target, include_tests) if p.suffix in SOURCE_SUFFIXES]
