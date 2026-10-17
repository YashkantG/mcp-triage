from pathlib import Path

from mcp_triage.checks.code_checks import scan_source_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_dangerous_sinks():
    findings = scan_source_file(FIXTURES / "vulnerable_server" / "server.py")
    rule_ids = {f.rule_id for f in findings}
    assert "MCP101" in rule_ids  # eval()
    assert "MCP102" in rule_ids  # subprocess shell=True / os.system
    assert "MCP103" in rule_ids  # pickle.loads()
    assert "MCP104" in rule_ids  # aliased subprocess shell=True


def test_clean_source_has_no_findings():
    findings = scan_source_file(FIXTURES / "clean_server" / "server.py")
    assert findings == []
    assert not any(f.rule_id == "MCP104" for f in findings)


def test_flags_subprocess_import_alias_with_shell_true(tmp_path):
    source = tmp_path / "server.py"
    source.write_text(
        "from subprocess import run as execute\n"
        "execute(\n"
        "    user_command,\n"
        "    shell=True,\n"
        ")\n",
        encoding="utf-8",
    )

    findings = scan_source_file(source)

    assert len([f for f in findings if f.rule_id == "MCP104"]) == 1
    assert next(f for f in findings if f.rule_id == "MCP104").line == 2


def test_flags_aliased_subprocess_module_with_shell_true(tmp_path):
    source = tmp_path / "server.py"
    source.write_text(
        "import subprocess as sp\n"
        "sp.Popen(command, shell=True)\n",
        encoding="utf-8",
    )

    assert any(f.rule_id == "MCP104" for f in scan_source_file(source))


def test_does_not_flag_unrelated_or_shell_false_calls(tmp_path):
    source = tmp_path / "server.py"
    source.write_text(
        "from subprocess import run as execute\n"
        "execute(command, shell=False)\n"
        "runner.run(command, shell=True)\n",
        encoding="utf-8",
    )

    assert not any(f.rule_id == "MCP104" for f in scan_source_file(source))


def test_imported_alias_shadowed_by_function_parameter_is_not_flagged(tmp_path):
    source = tmp_path / "server.py"
    source.write_text(
        "from subprocess import run as execute\n"
        "def helper(execute):\n"
        "    execute(command, shell=True)\n",
        encoding="utf-8",
    )

    assert not any(f.rule_id == "MCP104" for f in scan_source_file(source))


def test_imported_alias_shadowed_by_local_assignment_is_not_flagged(tmp_path):
    source = tmp_path / "server.py"
    source.write_text(
        "from subprocess import run as execute\n"
        "def helper():\n"
        "    execute = custom_runner\n"
        "    execute(command, shell=True)\n",
        encoding="utf-8",
    )

    assert not any(f.rule_id == "MCP104" for f in scan_source_file(source))
