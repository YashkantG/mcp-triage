from pathlib import Path

from mcp_triage.checks.manifest_checks import scan_manifest_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_prompt_injection_and_broad_capability_and_open_schema():
    findings = scan_manifest_file(FIXTURES / "vulnerable_server" / "mcp.json")
    rule_ids = {f.rule_id for f in findings}
    assert "MCP001" in rule_ids  # prompt injection phrasing
    assert "MCP004" in rule_ids  # broad capability keyword ("shell")
    assert "MCP005" in rule_ids  # additionalProperties: true


def test_flags_prompt_and_resource_exfiltration_in_protocol_manifest():
    findings = scan_manifest_file(FIXTURES / "vulnerable_server" / "mcp.json")
    rule_findings = [f for f in findings if f.rule_id == "MCP006"]

    assert len(rule_findings) == 2
    assert any("private_context" in f.message for f in rule_findings)
    assert any("hidden_action" in f.message for f in rule_findings)


def test_flags_nested_open_schema_but_not_top_level_duplicate():
    findings = scan_manifest_file(FIXTURES / "vulnerable_server" / "mcp.json")

    assert sum(f.rule_id == "MCP005" for f in findings) == 1
    assert sum(f.rule_id == "MCP007" for f in findings) == 1


def test_clean_manifest_has_no_manifest_findings():
    findings = scan_manifest_file(FIXTURES / "clean_server" / "mcp.json")
    assert findings == []


def test_benign_prompt_and_resource_descriptions_are_not_flagged():
    findings = scan_manifest_file(FIXTURES / "clean_server" / "mcp.json")

    assert not any(f.rule_id == "MCP006" for f in findings)
    assert not any(f.rule_id == "MCP007" for f in findings)


def test_nested_open_schema_inside_composition_is_detected(tmp_path):
    manifest = tmp_path / "tools.json"
    manifest.write_text(
        '{"tools":[{"name":"search","description":"Search records.",'
        '"inputSchema":{"type":"object","properties":{"filter":{"anyOf":['
        '{"type":"object","properties":{"field":{"type":"string"}},'
        '"additionalProperties":true}]}}}}]}',
        encoding="utf-8",
    )

    findings = scan_manifest_file(manifest)

    assert sum(f.rule_id == "MCP007" for f in findings) == 1
