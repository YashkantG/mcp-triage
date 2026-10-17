from mcp_triage.scanner import scan


def test_excluded_ancestor_name_does_not_hide_scan_target(tmp_path):
    target = tmp_path / "tests" / "project"
    target.mkdir(parents=True)
    (target / "server.py").write_text(
        "subprocess.run('x', shell=True)\n",
        encoding="utf-8",
    )

    findings = scan(target)

    assert any(f.rule_id == "MCP102" for f in findings)


def test_test_directories_are_skipped_but_can_be_included(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "server.py").write_text(
        "subprocess.run('x', shell=True)\n",
        encoding="utf-8",
    )

    assert scan(tmp_path) == []
    assert any(f.rule_id == "MCP102" for f in scan(tmp_path, include_tests=True))
