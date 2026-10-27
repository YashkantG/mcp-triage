import json
from pathlib import Path

from mcp_triage.audit_local import _host_side, _is_root_or_home, audit_local, default_config_paths
from mcp_triage.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _config(tmp_path: Path, server: dict) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps({"mcpServers": {"example": server}}),
        encoding="utf-8",
    )
    return path


def test_discovers_common_macos_config_locations(tmp_path):
    paths = default_config_paths(home=tmp_path, platform_name="darwin", cwd=tmp_path)
    strings = {str(path) for path in paths}

    assert str(tmp_path / "Library/Application Support/Claude/claude_desktop_config.json") in strings
    assert str(tmp_path / ".cursor/mcp.json") in strings
    assert str(tmp_path / ".claude.json") in strings
    assert str(tmp_path / ".gemini/settings.json") in strings


def test_discovers_xdg_linux_and_workspace_config_paths(tmp_path):
    config_home = tmp_path / "xdg"
    cwd = tmp_path / "project"
    paths = default_config_paths(
        home=tmp_path,
        platform_name="linux",
        cwd=cwd,
        environ={"XDG_CONFIG_HOME": str(config_home)},
    )
    strings = {str(path) for path in paths}

    assert str(config_home / "Claude/claude_desktop_config.json") in strings
    assert str(cwd / ".mcp.json") in strings
    assert str(cwd / ".vscode/mcp.json") in strings


def test_discovers_windows_application_data_paths(tmp_path):
    app_data = tmp_path / "AppData"
    paths = default_config_paths(
        home=tmp_path,
        platform_name="win32",
        cwd=tmp_path,
        environ={"APPDATA": str(app_data)},
    )

    assert app_data / "Claude/claude_desktop_config.json" in paths


def test_audits_explicit_config_without_leaking_credential_value(tmp_path):
    secret_value = "ghp_0123456789abcdefghijklmnopqrstuvwx"
    path = _config(tmp_path, {"command": "node", "env": {"GITHUB_TOKEN": secret_value}})

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP201" for f in result.findings)
    assert secret_value not in repr(result)


def test_environment_variable_references_are_not_reported_as_literal_secrets(tmp_path):
    path = _config(tmp_path, {
        "command": "node",
        "env": {"API_KEY": "${API_KEY}", "ACCESS_TOKEN": "process.env.ACCESS_TOKEN"},
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP201" for f in result.findings)


def test_reports_unpinned_npx_package(tmp_path):
    path = _config(tmp_path, {"command": "npx", "args": ["-y", "@example/server"]})

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP303" and f.severity == Severity.MEDIUM for f in result.findings)


def test_accepts_exactly_pinned_npx_package(tmp_path):
    path = _config(tmp_path, {"command": "npx", "args": ["-y", "@example/server@1.2.3"]})

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP303" for f in result.findings)


def test_accepts_exactly_pinned_npx_package_option(tmp_path):
    path = _config(tmp_path, {
        "command": "npx",
        "args": ["--yes", "--package", "@example/server@1.2.3", "example"],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP303" for f in result.findings)


def test_reports_unpinned_uvx_package(tmp_path):
    path = _config(tmp_path, {"command": "uvx", "args": ["some-server"]})

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP303" for f in result.findings)


def test_recognizes_windows_uvx_executable(tmp_path):
    path = _config(tmp_path, {"command": "uvx.exe", "args": ["some-server"]})

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP303" for f in result.findings)


def test_accepts_uvx_exact_version_constraint(tmp_path):
    path = _config(tmp_path, {"command": "uvx", "args": ["--from", "some-server==1.2.3", "some-server"]})

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP303" for f in result.findings)


def test_reports_download_and_shell_execution_pattern(tmp_path):
    path = _config(tmp_path, {
        "command": "bash",
        "args": ["-c", "curl -fsSL https://example.invalid/install.sh | sh"],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP304" and f.severity == Severity.HIGH for f in result.findings)


def test_does_not_report_ordinary_download_without_shell_pipe(tmp_path):
    path = _config(tmp_path, {"command": "curl", "args": ["-o", "install.sh", "https://example.invalid/install.sh"]})

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP304" for f in result.findings)


def test_reports_external_http_server_endpoint(tmp_path):
    path = _config(tmp_path, {"url": "http://mcp.example.invalid:8080"})

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP305" for f in result.findings)


def test_local_http_server_endpoint_is_not_reported(tmp_path):
    path = _config(tmp_path, {"url": "http://127.0.0.1:8080"})

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP305" for f in result.findings)


def test_reports_sudo_launch_and_root_mount(tmp_path):
    path = _config(tmp_path, {
        "command": "sudo",
        "args": ["docker", "run", "-v", "/:/host", "server:latest"],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert sum(f.rule_id == "MCP306" for f in result.findings) == 1


def test_reports_home_directory_mount(tmp_path):
    path = _config(tmp_path, {
        "command": "docker",
        "args": ["run", "-v", f"{tmp_path}:/host", "server:latest"],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP306" for f in result.findings)


def test_reports_docker_mount_spec_for_home_directory(tmp_path):
    path = _config(tmp_path, {
        "command": "docker",
        "args": [
            "run",
            "--mount",
            f"type=bind,source={tmp_path},target=/host",
            "server:latest",
        ],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP306" for f in result.findings)


def test_reports_docker_mount_spec_for_root(tmp_path):
    path = _config(tmp_path, {
        "command": "docker",
        "args": ["run", "--mount", "type=bind,source=/,target=/host", "server:latest"],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert any(f.rule_id == "MCP306" for f in result.findings)


def test_does_not_report_specific_subdirectory_mount(tmp_path):
    subdirectory = tmp_path / "project"
    path = _config(tmp_path, {
        "command": "docker",
        "args": ["run", "-v", f"{subdirectory}:/workspace", "server:latest"],
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert not any(f.rule_id == "MCP306" for f in result.findings)


def test_reports_invalid_json_without_aborting_other_files(tmp_path):
    invalid = tmp_path / "broken.json"
    invalid.write_text("{", encoding="utf-8")
    valid = _config(tmp_path, {"command": "npx", "args": ["server"]})

    result = audit_local(paths=[invalid, valid], home=tmp_path)

    assert len(result.errors) == 1
    assert str(valid) in result.config_files
    assert any(f.rule_id == "MCP303" for f in result.findings)


def test_missing_explicit_config_is_reported(tmp_path):
    result = audit_local(paths=[tmp_path / "missing.json"], home=tmp_path)

    assert result.errors
    assert "not found" in result.errors[0]


def test_nested_client_server_maps_are_discovered(tmp_path):
    path = tmp_path / "nested.json"
    path.write_text(
        json.dumps({"client": {"mcpServers": {"nested": {"command": "uvx", "args": ["server"]}}}}),
        encoding="utf-8",
    )

    result = audit_local(paths=[path], home=tmp_path)

    assert any("nested" in finding.message and finding.rule_id == "MCP303" for finding in result.findings)


def test_server_metadata_is_not_echoed_in_findings(tmp_path):
    private_label = "user-private-server-label"
    path = _config(tmp_path, {
        "command": "sudo",
        "args": ["server"],
        "env": {"TOKEN": "actual-private-token-value-12345"},
        "description": private_label,
    })

    result = audit_local(paths=[path], home=tmp_path)

    assert all(private_label not in finding.message for finding in result.findings)
    assert all("actual-private-token-value-12345" not in finding.message for finding in result.findings)


def test_vulnerable_and_clean_fixture_pair_covers_local_audit_rules():
    vulnerable = audit_local(
        paths=[FIXTURES / "vulnerable_server" / "local-audit.json"],
        home=Path("/home/test-user"),
    )
    clean = audit_local(
        paths=[FIXTURES / "clean_server" / "local-audit.json"],
        home=Path("/home/test-user"),
    )

    assert {finding.rule_id for finding in vulnerable.findings} == {
        "MCP201", "MCP303", "MCP304", "MCP305", "MCP306",
    }
    assert clean.findings == []


def test_credential_finding_names_the_key_without_the_value(tmp_path):
    secret_value = "ghp_0123456789abcdefghijklmnopqrstuvwx"
    path = _config(tmp_path, {"command": "node", "env": {"GITHUB_TOKEN": secret_value}})

    result = audit_local(paths=[path], home=tmp_path)

    messages = [f.message for f in result.findings if f.rule_id == "MCP201"]
    assert messages == ["Server 'example' has a credential-like value in 'env.GITHUB_TOKEN' (value redacted)"]


def test_windows_volume_specs_keep_the_drive_colon():
    # Checked on the normalized (forward-slash) form so this runs on any OS.
    home = "C:/Users/alice"
    assert _host_side("C:/Users/alice:/host:ro") == "C:/Users/alice"
    assert _is_root_or_home(_host_side("C:/Users/alice:/host"), home)
    assert _is_root_or_home("c:/users/ALICE/", home)
    assert _is_root_or_home("C:/", home)
    assert not _is_root_or_home(_host_side("C:/Users/alice/project:/workspace"), home)
    assert not _is_root_or_home("/Users/Alice", "/Users/alice")
