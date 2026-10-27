# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — plus
the additional rule-stability guarantees below, which matter if you pin rule
IDs in CI.

## Rule stability policy

Teams pin things like `--ignore-rule MCP004` and `--fail-on high` in their
pipelines, so rule identity is part of the public API, not an implementation
detail:

- **Rule IDs are never reused or renumbered.** If a rule is retired, its ID is
  retired with it.
- **A rule's default severity will not change in a patch release.** Severity
  changes ship in a minor release at the earliest, and are always listed here.
- **New rules may be added in a minor release.** This can surface new findings
  in an existing codebase, which is why `--fail-on`, `--ignore-rule` and
  `.mcptriage.toml` exist. Use `--baseline` to fail only on new findings while
  adopting the scanner into a project with existing findings.
- **Removing a rule, or making an existing rule meaningfully broader, is a
  breaking change** and waits for a major version.

---

## [Unreleased]

### Added
- **MCP202** reports AI and cloud provider key formats — Anthropic, OpenAI,
  GitHub fine-grained, Stripe live, Google, Hugging Face, GitLab, and npm —
  wherever they appear, including bare values in `args`, headers, and URLs.
  Lines already reported as MCP201 keep that rule ID, so existing baselines and
  ignores are unaffected.
- CI now also runs on Windows and macOS.

### Fixed
- **MCP201 missed env-var style credential names**, which is how MCP client
  configs pass secrets: `\bAPI_KEY\b` never matched inside `BRAVE_API_KEY`, so
  `"ANTHROPIC_API_KEY": "…"`, `"STRIPE_SECRET_KEY": "…"` or
  `"GITHUB_PERSONAL_ACCESS_TOKEN": "…"` in an `mcp.json` went unreported by
  `scan`. Names like `max_tokens` and `token_count` are still not treated as
  credentials.
- MCP201 skipped every line containing `<`, which hid secrets on lines with
  TypeScript generics or comparisons (`Record<string, string>`).
- **MCP306 never fired on Windows**: home-directory mounts such as
  `C:\Users\me:/host` were split on the drive colon and compared with
  mismatched slashes. Drive roots (`C:\`) are now treated like `/`, and
  Windows paths compare case-insensitively.
- `audit-local` credential findings now name the offending key
  (`env.GITHUB_TOKEN`) so it can be found and moved; the value stays redacted.
- `[severity]` overrides in `.mcptriage.toml` now accept lower-case rule IDs,
  as `[ignore] rules` already did, instead of silently doing nothing.

## [0.5.0] - 2026-10-20

### Added
- **`audit-local`** checks supported Claude Desktop/Code, Cursor, VS Code,
  Windsurf, Gemini, and workspace MCP configs locally. It redacts credential
  values, lists configured servers and checked paths, reports read errors,
  supports table/JSON/Markdown output, repeatable explicit config paths, and
  case-insensitive severity thresholds.
- **MCP303–MCP306** identify unpinned `npx`/`uvx` launches, download-to-shell
  commands, non-local plain HTTP endpoints, and `sudo` or whole-root/home
  directory access in locally configured MCP servers. Docker image tags are
  explicitly outside the check's scope.
- **MCP006** flags narrowly defined concealed-access and sensitive-data
  exfiltration language in JSON MCP prompt, resource, and resource-template
  descriptions. It does not inspect prompt bodies or infer runtime behavior.
- **MCP007** detects explicit `additionalProperties: true` in nested tool input
  schemas, including properties and composition branches, without duplicating
  the existing top-level MCP005 finding.
- **MCP104** uses Python's standard-library AST to detect `shell=True` calls
  through aliased `subprocess` imports and multiline calls not covered by the
  existing qualified-call pattern. It does not claim that the command is
  attacker-controlled.
- **Baseline mode** (`--write-baseline` / `--baseline`) to adopt the scanner on
  existing projects and fail CI only on newly introduced findings. The
  versioned baseline stores fingerprints rather than source snippets, is
  tolerant of line-number shifts, and reports malformed data explicitly.
- **Markdown reports** (`--format markdown`) for sharing scan results in pull
  requests, issue discussions, and security reviews.
- The GitHub Action installs the code from the selected action ref by default,
  keeping its CLI features in sync; `version` remains available as a PyPI
  package override.

### Fixed
- Relative `ignore.paths` globs now resolve from the scan root, including when
  the config file is supplied separately.
- Scanning a project no longer accidentally skips it because an ancestor
  directory is named `tests`, `examples`, or another excluded directory.
- Excluded directories are pruned during discovery instead of traversed and
  filtered afterward, and source files are classified from the same walk.
- The GitHub Action passes inputs through environment variables rather than
  interpolating them into shell source. It now preserves the scanner's exit
  status while still publishing SARIF output from scans that find issues.
- Invalid output formats and malformed custom rules/severity config now fail
  with actionable errors rather than silently changing output or crashing
  during scanning.
- Repeated scans in the same process now observe edits to inline suppression
  comments instead of reusing stale cached file contents.

## [0.4.1] - 2026-09-06

### Fixed
- **MCP001 was firing almost entirely on false positives in 0.4.0.** Running the
  survey against the pinned release produced 32 hits across 4 servers, and
  inspection showed essentially all were benign — including descriptions being
  *more* careful than average about consent:

  > "show the user the exact text and who it goes to, get a yes, then send"
  > "resolve a video without asking the user for an id"
  > "Use this instead of calling the REST API directly"

  The patterns treated any concealment language as hostile, but "never log the
  access token" and "do not show raw JSON" are good advice. They now require the
  concealed thing to be *the tool's own call*, and require a consequential verb
  before "without asking the user". The negative test cases are now taken
  verbatim from real servers rather than written from imagination — which is why
  the originals missed this.

- **Tool descriptions written as `"description":` were never scanned.** The
  extractor matched only the bare `description:` form, so every tool defined in
  a Python dict or a JSON-style JS object literal was invisible to MCP001–MCP004.
  Found by an end-to-end check on an obviously-poisoned description that
  returned nothing.

  This also means the 0.4.0 survey understated description-rule coverage, and
  any figure quoted from it should be treated as a floor.


## [0.4.0] - 2026-09-06

### Renamed
- **The project is now `mcp-triage`** (was `mcp-sentinel`, briefly `mcp-audit`).
  "Sentinel" collided with Microsoft Sentinel, which had just shipped its own
  MCP server; "audit" was rejected by PyPI as too similar to the existing
  `mcpaudit`. Rule IDs are unchanged and remain the stable public API.
- Config file is `.mcptriage.toml`; suppression comments are
  `# mcp-triage: ignore[MCP102]`.

### Added
- **`--format badge`** — emits a shields.io endpoint payload a project can
  commit and display, showing an A–F posture grade.
- **`--include-tests`** — opts test/example/benchmark directories back into a
  scan (they are skipped by default, see below).
- **GitHub Pages site** at https://yashkantg.github.io/mcp-triage/.
- **`research/ecosystem_scan.py`** — reproducible survey harness for the public
  MCP server ecosystem, plus the results it produced in the README.

### Changed — detection accuracy
Surveying 141 public MCP servers exposed three classes of false positive, all
now fixed and covered by regression tests:

- **Test, fixture, example, benchmark and mock directories are skipped by
  default.** Most raw findings came from fake credentials in redaction tests
  and deliberately-unsafe example snippets. `vendor/` and `third_party/` are
  never scanned.
- **The secrets check recognises mock/placeholder values** (`local-mock-key`,
  `dummy-token`, ...). Cut MCP201 findings by 85% across the survey.
- **`MCP101`/`MCP102` no longer match `pattern.exec(line)`** — the ordinary
  JavaScript RegExp API, which accounted for **77%** of all code-execution
  findings. Now requires a bare call or an explicit `child_process` member.
- **A JSON object needs more than a `description` field to count as a tool.**
  npm manifests and OpenAPI documents were being scanned as tool definitions.

### Changed — MCP001
- **Prompt-injection detection now covers real tool poisoning**, not just
  literal "ignore previous instructions": pseudo-tag payloads
  (`<IMPORTANT>`, `<instructions>`), notes addressed to the assistant,
  read-a-sensitive-path-and-return-it-via-parameter, and tool shadowing. Half
  the new tests are negative cases — ordinary documentation must stay clean.

  Worth stating plainly: across 141 surveyed repositories, MCP001 fired **once**
  under the old patterns. Deliberate tool poisoning is rare in public code.

## [0.3.0] - 2026-09-05

### Added
- **SARIF 2.1.0 output** (`--format sarif`), validated against the official
  schema — findings can be uploaded to GitHub Code Scanning, GitLab, or any
  SARIF-consuming dashboard.
- **Badge output** (`--format badge`) producing a shields.io endpoint payload,
  so a scanned project can display its own posture grade.
- **Inline suppression comments**: `# mcp-triage: ignore[MCP102]` suppresses
  a specific rule on that line; a bare `# mcp-triage: ignore` suppresses all.
- **Project configuration** via `.mcptriage.toml`: repo-wide rule and path
  ignores, per-rule severity overrides, and `[[custom_rules]]` for
  organisation-specific checks without forking.
- `--ignore-rule` (repeatable) and `--config` CLI options.
- **GitHub Action** (`action.yml`) with an `upload-sarif` path straight into
  Code Scanning.
- **pre-commit hook** definition (`.pre-commit-hooks.yaml`).
- `CONTRIBUTING.md`, `SECURITY.md`, issue forms, and a pull request template.

### Fixed
- `__version__` was still reporting `0.1.0` after the 0.2.0 release.

## [0.2.0] - 2026-09-05

### Added
- Tool descriptions are now extracted from **source code** (JS/TS/Python string
  literals, including `+`-concatenated multi-line strings), not just static
  JSON manifests. This was the flagship prompt-injection check's biggest blind
  spot: scanning the official `modelcontextprotocol/servers` reference
  implementations produced zero findings before this, because none of them ship
  a static manifest.

### Fixed
- False positive where the MCP004 broad-capability check matched `exec` as a
  substring of ordinary words like "executes". Keyword matching is now
  word-boundary aware.

## [0.1.0] - 2026-09-03

### Added
- Initial release: 11 rules across tool-description analysis (prompt injection,
  hidden unicode, over-broad capability, unvalidated schemas), dangerous code
  sinks, hardcoded secrets, and unsafe server defaults.
- `table` and `json` output, `--fail-on` severity gating for CI.

[Unreleased]: https://github.com/YashkantG/mcp-triage/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/YashkantG/mcp-triage/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/YashkantG/mcp-triage/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/YashkantG/mcp-triage/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/YashkantG/mcp-triage/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/YashkantG/mcp-triage/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/YashkantG/mcp-triage/releases/tag/v0.1.0
