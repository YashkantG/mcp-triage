# mcp-triage

[![CI](https://github.com/YashkantG/mcp-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/YashkantG/mcp-triage/actions/workflows/ci.yml)
[![MCP security](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/YashkantG/mcp-triage/main/.github/badges/self-scan.json)](#show-your-posture)
[![PyPI](https://img.shields.io/pypi/v/mcp-triage)](https://pypi.org/project/mcp-triage/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](pyproject.toml)

**An MCP security scanner. Audit an MCP server before you let an agent near it.**

`mcp-triage` is a command-line security scanner for MCP (Model Context Protocol)
servers. It scans a server for prompt injection in tool descriptions, hardcoded
secrets, dangerous code execution paths, and unsafe defaults — locally, with no
account and no network calls.

![mcp-triage demo](docs/demo.gif)

Connecting an agent to a Model Context Protocol server hands that server two
things at once: **code execution on your machine**, and **a direct line to the
model's context**. The second one is what makes MCP different from an ordinary
dependency.

A tool's `description` field isn't documentation for humans — it's fed
straight to the LLM as instructions. A server author (or someone who
compromised one) can write a description that tells your agent to do something
you never asked for, and you'd never see it in a code review that only looked
at the implementation. That's a new class of supply-chain risk, and there are
now [20,000+ MCP servers](https://mcp.so) in public directories with almost no
security review between them and your agent.

`mcp-triage` is a fast, local, dependency-light first pass over any MCP
server — one you didn't write, or one you're about to publish.

---

## Quick start

Audit a server you're thinking about trusting:

```bash
pip install mcp-triage

git clone https://github.com/some-org/some-mcp-server
mcp-triage scan ./some-mcp-server
```

That's the whole workflow. No account, no config file, no network calls — see
[Runs entirely on your machine](#runs-entirely-on-your-machine).

### Try the latest security rules and community improvements

The latest rule additions (MCP006, MCP007, and MCP104), baseline scanning, and
Markdown reports are available from the GitHub repository. Until the next
PyPI release, install the current source directly:

```bash
python -m pip install --upgrade "git+https://github.com/YashkantG/mcp-triage.git"
mcp-triage scan ./some-mcp-server --write-baseline .mcp-triage-baseline.json
mcp-triage scan ./some-mcp-server --baseline .mcp-triage-baseline.json --format markdown
```

The ordinary `pip install mcp-triage` command installs the latest published
PyPI version, which may not yet include changes on `main`. The GitHub Action
examples below use `@main` to access those repository features.

## What it catches

- 🧠 **Prompt-injection-prone tool descriptions** — phrasing aimed at the
  calling model rather than at a human reader ("ignore previous instructions",
  "do not tell the user"), hidden zero-width unicode, and descriptions long
  enough to bury instructions in. Checked in static JSON manifests **and** in
  the source-embedded string literals where real servers actually keep them.
- 🗂️ **Prompt and resource metadata** in JSON protocol manifests — checks
  descriptions for concealed access and sensitive-data exfiltration patterns.
- 🧩 **Nested tool input schemas** — finds explicitly open object schemas
  inside nested properties and composition keywords, not only at the root.
- 🔓 **Over-broad capabilities** — tools advertising shell/exec/arbitrary file
  access, or accepting unvalidated free-form input (`additionalProperties: true`).
- 💣 **Dangerous code paths** in the implementation — `eval`,
  `subprocess(..., shell=True)` (including imported aliases in Python),
  `os.system`, `pickle.loads`, unsafe `yaml.load`.
- 🔑 **Hardcoded secrets** — API keys, AWS keys, GitHub/Slack tokens committed
  into source or config.
- 🌐 **Unsafe defaults** — binding to `0.0.0.0`, `trust` / `skip_auth` flags
  left on.

Full [rule reference](#rules) below. Every rule ID is stable — see the
[rule stability policy](CHANGELOG.md#rule-stability-policy) before you pin one
in CI.

## Use it in CI

**GitHub Action** — no `pip install` boilerplate:

```yaml
- uses: YashkantG/mcp-triage@main
  with:
    path: ./my-mcp-server
    fail-on: high
```

**SARIF → GitHub Code Scanning**, so findings land in the Security tab instead
of scrolling past in a build log:

```yaml
- uses: YashkantG/mcp-triage@main
  with:
    path: ./my-mcp-server
    format: sarif
    upload-sarif: "true"
```

To adopt the scanner in a repository with existing findings, generate a
baseline once, check that JSON file into the repository, and pass it on later
scans:

```yaml
- uses: YashkantG/mcp-triage@main
  with:
    path: ./my-mcp-server
    baseline: .mcp-triage-baseline.json
    format: sarif
    upload-sarif: "true"
```

Generate or intentionally refresh the baseline with
`write-baseline: .mcp-triage-baseline.json`. Baseline generation does not fail
the step for existing findings. The baseline scan then fails only when it finds
a new issue at or above the configured `fail-on` severity.

**pre-commit**:

```yaml
repos:
  - repo: https://github.com/YashkantG/mcp-triage
    rev: v0.4.1
    hooks:
      - id: mcp-triage
```

**Any other CI** — `mcp-triage scan . --fail-on high` exits non-zero when it
finds something at or above that severity. `--format json` for machine-readable
output.

### Adopt it without blocking on old findings

For a project adding security checks to an existing codebase, save the current
findings once and fail future scans only when they introduce a new finding:

```bash
mcp-triage scan . --write-baseline .mcp-triage-baseline.json
mcp-triage scan . --baseline .mcp-triage-baseline.json --format sarif
```

Check the baseline file into version control and refresh it intentionally
after reviewing existing findings. Baselines use a versioned JSON format and
store finding fingerprints only (not code snippets); line-number shifts alone
do not make an otherwise unchanged finding new. Invalid or unsupported
baseline files fail with an explicit error.

### Shareable scan reports

Use `--format markdown` to generate a readable report for a pull request,
issue, or security review:

```bash
mcp-triage scan . --format markdown > security-report.md
```

JSON and SARIF remain available for automation and code-scanning integrations.

## Show your posture

If you publish an MCP server, `--format badge` emits a
[shields.io endpoint](https://shields.io/badges/endpoint-badge) payload you can
commit and display, so the people evaluating your server can see it was
checked:

```bash
mcp-triage scan . --format badge > .github/badges/mcp-security.json
```

```markdown
[![MCP security](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/.github/badges/mcp-security.json)](https://github.com/YashkantG/mcp-triage)
```

Grades are deliberately blunt: **A** clean, **B/C** medium findings, **D/F**
high findings. The badge at the top of this README is this repo scanning
itself, regenerated and verified on every CI run.

## Tuning it

A pattern-based scanner will flag things you've already reviewed. Three levers,
narrowest first:

**Inline**, on the offending line:

```python
subprocess.run(cmd, shell=True)  # mcp-triage: ignore[MCP102]
subprocess.run(cmd, shell=True)  # mcp-triage: ignore        ← all rules, this line
```

**Project config** — `.mcptriage.toml` at the scan root:

```toml
[ignore]
rules = ["MCP004"]              # repo-wide
paths = ["tests/fixtures/**"]

[severity]
MCP003 = "LOW"                  # downgrade rather than silence

[[custom_rules]]                # your own checks, no fork required
id = "CUSTOM001"
pattern = "InternalOnlyApi\\.execute"
message = "Internal-only API called from an MCP tool handler"
severity = "HIGH"
```

`ignore.paths` patterns are matched against paths relative to the scan root
(for example, `tests/fixtures/**`) as well as absolute paths. When `--config`
points to a separate config file, path patterns still use the target being
scanned as their root.

**CLI**, for one-offs: `mcp-triage scan . --ignore-rule MCP004`

This repo's own [`.mcptriage.toml`](.mcptriage.toml) is a worked example.

## Runs entirely on your machine

`mcp-triage` makes **zero network calls**. It doesn't phone home, doesn't
upload your code, and has no telemetry. Runtime dependencies are `typer`,
`rich`, and `tomli` (Python < 3.11 only).

Releases publish through
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC — no
long-lived tokens), so every release traces back to the GitHub Actions run that
built it. If your security team needs to approve a new tool: read the source,
then run it with no network access at all. It doesn't need any.

Reporting a vulnerability — in this tool, or one you found *with* it — see
[SECURITY.md](SECURITY.md).

## What the MCP ecosystem actually looks like

`research/ecosystem_scan.py` surveys public MCP servers harvested from the
curated awesome-lists. Against a pinned release, over a seeded sample of
**139 successfully scanned repositories** (pool of 3,701):

| | |
|---|---|
| Repositories with at least one finding | **35%** |
| Long tool descriptions (MCP003) | 25 repos |
| Shell/exec sinks (MCP102 / MCP101) | 17 and 12 repos |
| Over-broad capability (MCP004) | 14 repos |
| Hardcoded secrets (MCP201) | 13 repos |

**Treat these as provisional, and as a floor.** The survey's real value so far
has been finding bugs in this scanner, not in other people's servers. In order:

- The first pass reported 37% and 931 HIGH findings. Inspection showed most
  were fake credentials in test fixtures, `eval` in benchmark harnesses, and
  `pattern.exec(line)` — the JavaScript RegExp API — which alone was **77%** of
  all code-execution hits.
- The harness itself recorded crashed scans as "0 findings", quietly turning
  scanner failures into clean bills of health.
- Re-running against the pinned v0.4.0 produced 32 prompt-injection hits which,
  on inspection, were **essentially all false positives** — including
  descriptions being *more* careful than average about user consent. Fixed in
  v0.4.1.
- That same check revealed the extractor never matched `"description":` (the
  quoted-key form used by Python dicts), so tools defined in dict literals were
  never scanned at all. Description-rule coverage in the numbers above is
  therefore **understated**.

Each of those became a [precision regression test](tests/test_precision.py)
rather than a headline. No repository is named here; if this tool finds
something real in someone else's server,
[disclose it to them privately](SECURITY.md).

Reproduce it yourself: `python research/ecosystem_scan.py --sample-size 150`.

## Rules

| ID | Check |
|----|-------|
| MCP001 | Prompt injection / tool poisoning in tool description |
| MCP002 | Hidden/invisible unicode characters in tool description |
| MCP003 | Suspiciously long tool description (payload smuggling risk) |
| MCP004 | Over-broad capability exposed by tool name/description |
| MCP005 | Tool schema accepts arbitrary/unvalidated input |
| MCP006 | Concealed or exfiltrative prompt/resource description |
| MCP007 | Nested tool schema accepts arbitrary fields |
| MCP101 | Dangerous code execution sink (`eval`, `exec`, `new Function`) |
| MCP102 | Shell command built from untrusted input |
| MCP103 | Unsafe deserialization (`pickle.loads`, unsafe `yaml.load`) |
| MCP104 | Aliased Python subprocess call with `shell=True` |
| MCP201 | Hardcoded secret or credential |
| MCP301 | Server bound to all network interfaces |
| MCP302 | Authentication / trust check disabled |

Plus any `[[custom_rules]]` you define.

## Design

Deliberately pattern/regex-based rather than a full taint-tracking analyser.
That's a real tradeoff, stated plainly:

- **You get**: sub-second scans, a rule set you can read end-to-end in one
  sitting, no compilation or language runtime per target, trivial extensibility.
- **You give up**: certainty. It cannot tell you whether attacker-controlled
  data actually reaches a `shell=True` call. It is a first pass that tells you
  where a human should look — not a proof of safety, and it makes no soundness
  claim.

Some Python execution-call recognition uses the standard-library AST to
resolve imported `subprocess` aliases and multiline calls. MCP104 confirms
`shell=True`, but does **not** prove that the command is attacker-controlled.
MCP006 currently analyzes descriptions in JSON protocol manifests; it does not
evaluate prompt bodies or dynamically generated content. MCP007 flags explicit
`additionalProperties: true` in nested schemas; it does not infer whether an
application validates the value elsewhere. MCP104 recognizes imported Python
`subprocess` aliases only; alias resolution does not cover arbitrary dynamic
references.

Anyone selling you a scanner that claims to be complete is selling you
something else.

## Contributing

Issues and PRs welcome, especially new rules, more language coverage (Python /
JS / TS today), and real-world servers that break it. See
[CONTRIBUTING.md](CONTRIBUTING.md) for setup and the fixture-pair pattern every
rule follows, or pick up a
[good first issue](https://github.com/YashkantG/mcp-triage/labels/good%20first%20issue).

False positives are treated as real bugs — [report them](https://github.com/YashkantG/mcp-triage/issues/new/choose).

## License

MIT — see [LICENSE](LICENSE).
