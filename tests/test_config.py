import pytest

from mcp_triage.config import ConfigError
from mcp_triage.scanner import scan


def _write(path, content):
    path.write_text(content)
    return path


def test_ignored_rules_are_dropped(tmp_path):
    _write(tmp_path / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcptriage.toml", '[ignore]\nrules = ["MCP102"]\n')
    findings = scan(tmp_path)
    assert findings == []


def test_ignored_paths_are_dropped(tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    _write(vendor / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcptriage.toml", '[ignore]\npaths = ["*/vendor/*"]\n')
    findings = scan(tmp_path)
    assert findings == []


def test_relative_ignored_paths_are_resolved_from_scan_root(tmp_path):
    fixture = tmp_path / "tests" / "fixtures"
    fixture.mkdir(parents=True)
    _write(fixture / "server.py", "subprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcptriage.toml", '[ignore]\npaths = ["tests/fixtures/**"]\n')

    assert scan(tmp_path, include_tests=True) == []


def test_explicit_config_file_keeps_ignore_paths_relative_to_target(tmp_path):
    target = tmp_path / "project"
    source = target / "vendor"
    source.mkdir(parents=True)
    _write(source / "server.py", "subprocess.run('x', shell=True)\n")
    config = tmp_path / "shared.toml"
    _write(config, '[ignore]\npaths = ["vendor/**"]\n')

    assert scan(target, config_path=config) == []


def test_severity_override(tmp_path):
    _write(tmp_path / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    _write(tmp_path / ".mcptriage.toml", '[severity]\nMCP102 = "LOW"\n')
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "LOW"


def test_custom_rule_fires(tmp_path):
    _write(tmp_path / "server.py", "InternalOnlyApi.execute('x')\n")
    _write(
        tmp_path / ".mcptriage.toml",
        '[[custom_rules]]\n'
        'id = "CUSTOM001"\n'
        'pattern = "InternalOnlyApi\\\\.execute"\n'
        'message = "Banned internal API"\n'
        'severity = "HIGH"\n',
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM001"
    assert findings[0].severity.value == "HIGH"


def test_no_config_file_is_a_noop(tmp_path):
    _write(tmp_path / "server.py", "import subprocess\nsubprocess.run('x', shell=True)\n")
    findings = scan(tmp_path)
    assert len(findings) == 1


def test_invalid_custom_rule_regex_is_reported_as_a_config_error(tmp_path):
    _write(tmp_path / "server.py", "pass\n")
    _write(
        tmp_path / ".mcptriage.toml",
        '[[custom_rules]]\nid = "CUSTOM001"\npattern = "("\nmessage = "invalid"\n',
    )

    with pytest.raises(ConfigError, match="invalid regex"):
        scan(tmp_path)


def test_invalid_severity_override_is_reported_as_a_config_error(tmp_path):
    _write(tmp_path / "server.py", "pass\n")
    _write(tmp_path / ".mcptriage.toml", '[severity]\nMCP102 = "urgent"\n')

    with pytest.raises(ConfigError, match="HIGH, MEDIUM, or LOW"):
        scan(tmp_path)


def test_extra_ignored_rules_param_combines_with_config(tmp_path):
    _write(
        tmp_path / "server.py",
        "import subprocess, os\n"
        "subprocess.run('x', shell=True)\n"
        "os.system('y')\n",
    )
    _write(tmp_path / ".mcptriage.toml", '[ignore]\nrules = ["MCP102"]\n')
    findings = scan(tmp_path, extra_ignored_rules={"MCP102"})
    rule_ids = {f.rule_id for f in findings}
    assert "MCP102" not in rule_ids
