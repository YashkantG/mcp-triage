from pathlib import Path

from mcp_triage.checks.secrets_checks import scan_file_for_secrets

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_hardcoded_secrets():
    findings = scan_file_for_secrets(FIXTURES / "vulnerable_server" / "server.py")
    assert any(f.rule_id == "MCP201" for f in findings)

    findings = scan_file_for_secrets(FIXTURES / "vulnerable_server" / "mcp.json")
    assert any(f.rule_id == "MCP201" for f in findings)


def test_clean_files_have_no_secrets():
    findings = scan_file_for_secrets(FIXTURES / "clean_server" / "mcp.json")
    findings += scan_file_for_secrets(FIXTURES / "clean_server" / "server.py")
    assert findings == []


# Built at runtime so this file never contains a literal key-shaped string.
_ANTHROPIC = "sk-ant-" + "api03-" + "Zq8vR2mN4pL7tX1cB9dF3gH6jK0wE5yU2iO8aS4dF7gH1jK3lZ9x"
_GITHUB_FINE_GRAINED = "github_pat_" + "11ABCDEFG0" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ" * 3
_GOOGLE = "AIza" + "SyD3x8vR2mN4pL7tX1cB9dF3gH6jK0wE5yU"


def _scan_text(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return scan_file_for_secrets(path)


def test_env_var_style_credential_names_in_mcp_config(tmp_path):
    # How MCP client configs actually pass credentials. `\bAPI_KEY\b` never
    # matched inside `BRAVE_API_KEY`, so none of these used to be reported.
    config = (
        '{"mcpServers": {"s": {"env": {\n'
        '  "BRAVE_API_KEY": "BSAqz8vR2mN4pL7tX1cB9dF3gH6jK0w",\n'
        '  "STRIPE_SECRET_KEY": "q8vR2mN4pL7tX1cB9dF3gH6jK0wE5",\n'
        '  "AWS_SECRET_ACCESS_KEY": "q8vR2mN4pL7tX1cB9dF3gH6jK0wE5yU2iO8aS4d",\n'
        '  "GITHUB_PERSONAL_ACCESS_TOKEN": "q8vR2mN4pL7tX1cB9dF3gH6jK0wE5"\n'
        '}}}}\n'
    )
    findings = _scan_text(tmp_path, "mcp.json", config)
    assert [(f.rule_id, f.line) for f in findings] == [
        ("MCP201", 2), ("MCP201", 3), ("MCP201", 4), ("MCP201", 5),
    ]


def test_counter_and_config_names_containing_token_are_not_credentials(tmp_path):
    source = (
        'max_tokens = "4096000000000"\n'
        'token_count = "123456789012345"\n'
        'SECRET_NAME = "prod-database-creds"\n'
    )
    assert _scan_text(tmp_path, "server.py", source) == []


def test_typescript_generics_no_longer_hide_secrets(tmp_path):
    token = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    source = f'const headers: Record<string, string> = {{ Authorization: "{token}" }};\n'
    findings = _scan_text(tmp_path, "server.ts", source)
    assert [f.rule_id for f in findings] == ["MCP201"]


def test_provider_key_formats_are_reported_as_mcp202(tmp_path):
    config = (
        '{"args": [\n'
        f'  "--api-key", "{_ANTHROPIC}",\n'
        f'  "--token={_GITHUB_FINE_GRAINED}",\n'
        f'  "https://maps.googleapis.com/maps/api/geocode/json?key={_GOOGLE}"\n'
        ']}\n'
    )
    findings = _scan_text(tmp_path, "mcp.json", config)
    assert [(f.rule_id, f.message) for f in findings] == [
        ("MCP202", "Possible hardcoded secret: Anthropic API key"),
        ("MCP202", "Possible hardcoded secret: GitHub fine-grained token"),
        ("MCP202", "Possible hardcoded secret: Google API key"),
    ]


def test_assignments_keep_mcp201_even_for_provider_keys(tmp_path):
    # Lines MCP201 already caught keep their rule ID so existing baselines,
    # ignores, and severity overrides still apply to them.
    findings = _scan_text(tmp_path, "server.py", f'api_key = "{_ANTHROPIC}"\n')
    assert [f.rule_id for f in findings] == ["MCP201"]


def test_placeholder_provider_keys_are_ignored(tmp_path):
    findings = _scan_text(tmp_path, "README.md", f'Set it like `--api-key {_ANTHROPIC}` (example only)\n')
    assert findings == []
