# tests/unit/cli/test_cmd_mcp.py
"""Unit-тесты для CLI-подкоманды ``uniconn mcp``."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from uniconn.cli.app import create_cli_app
from uniconn.cli.cmd_mcp import build_mcp_client_config


def test_build_mcp_client_config_generates_valid_mcp_servers_dict(tmp_path: Path) -> None:
    """build_mcp_client_config формирует корректный блок mcpServers для Claude Desktop / Cursor."""
    inv_file = tmp_path / "fleet.yaml"
    inv_file.write_text("hosts: {}\n", encoding="utf-8")

    cfg = build_mcp_client_config(
        inventory=str(inv_file),
        group="web",
        allow_write=True,
        dry_run=True,
        allowlist="df,uptime",
        max_read_bytes=131072,
    )
    assert "mcpServers" in cfg
    srv = cfg["mcpServers"]["uniconn"]
    assert srv["command"] == "uvx"
    assert "--inventory" in srv["args"]
    assert "--group" in srv["args"]
    assert "--allow-write" in srv["args"]
    assert "--dry-run" in srv["args"]
    assert "--allowlist" in srv["args"]
    assert "--max-read-bytes" in srv["args"]
    assert "131072" in srv["args"]


def test_cli_mcp_print_config_outputs_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Флаг ``uniconn mcp --print-config`` выводит JSON-конфигурацию клиента и завершает работу."""
    app = create_cli_app()
    with pytest.raises(SystemExit) as exc_info:
        app.meta(["mcp", "--local", "--allow-write", "--print-config"])
    assert exc_info.value.code == 0

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["mcpServers"]["uniconn"]["command"] == "uvx"
    assert "--local" in parsed["mcpServers"]["uniconn"]["args"]
    assert "--allow-write" in parsed["mcpServers"]["uniconn"]["args"]


def test_cli_mcp_missing_inventory_exits_with_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """При указании несуществующего файла инвентаря ``uniconn mcp`` завершается с кодом 1."""
    app = create_cli_app()
    missing = tmp_path / "missing_hosts.yaml"
    with pytest.raises(SystemExit) as exc_info:
        app.meta(["mcp", "--inventory", str(missing)])
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Inventory file not found" in captured.err


def test_cli_mcp_launches_stdio_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """Команда ``uniconn mcp --local`` инициализирует MCPServer и вызывает serve_stdio()."""
    mock_serve = AsyncMock(return_value=None)
    monkeypatch.setattr("uniconn.mcp.server.MCPServer.serve_stdio", mock_serve)

    app = create_cli_app()
    with pytest.raises(SystemExit) as exc_info:
        app.meta(["mcp", "--local", "--dry-run"])
    assert exc_info.value.code == 0
    mock_serve.assert_awaited_once()


def test_build_mcp_client_config_http_mode() -> None:
    """build_mcp_client_config в режиме transport='http' формирует streamable-http конфиг."""
    cfg = build_mcp_client_config(
        transport="http",
        bind="0.0.0.0",
        port=8443,
        mcp_path="/mcp",
        auth_mode="oauth2",
        resource_url="https://mcp.corp.internal/mcp",
    )
    srv = cfg["mcpServers"]["uniconn"]
    assert srv["type"] == "streamable-http"
    assert srv["url"] == "https://mcp.corp.internal/mcp"
    assert srv["headers"] == {"Authorization": "Bearer ${UNICONN_MCP_TOKEN}"}


def test_cli_mcp_http_print_config_and_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI ``uniconn mcp --transport http`` печатает HTTP-конфиг и запускает serve_http с multi-tenant инвентарём."""
    app = create_cli_app()
    with pytest.raises(SystemExit) as exc_info:
        app.meta(
            [
                "mcp",
                "--transport",
                "http",
                "--bind",
                "127.0.0.1",
                "--port",
                "9090",
                "--auth-mode",
                "oauth2",
                "--print-config",
            ]
        )
    assert exc_info.value.code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["mcpServers"]["uniconn"]["type"] == "streamable-http"
    assert parsed["mcpServers"]["uniconn"]["url"] == "http://127.0.0.1:9090/mcp"

    acme_inv = tmp_path / "acme.yaml"
    acme_inv.write_text("hosts:\n  acme-1:\n    transport: local\n", encoding="utf-8")

    captured_calls: list[dict[str, object]] = []

    async def _fake_serve_http(self: object, *, auth_config: object = None, http_config: object = None) -> None:
        captured_calls.append(
            {
                "server": self,
                "auth_config": auth_config,
                "http_config": http_config,
            }
        )

    monkeypatch.setattr("uniconn.mcp.server.MCPServer.serve_http", _fake_serve_http)
    with pytest.raises(SystemExit) as exc_info2:
        app.meta(
            [
                "mcp",
                "--transport",
                "http",
                "--bind",
                "127.0.0.1",
                "--port",
                "9091",
                "--auth-mode",
                "oauth2",
                "--oidc-issuer",
                "https://idp.corp.internal",
                "--oidc-audience",
                "https://mcp.corp.internal/mcp",
                "--tenant-inventory",
                f"acme={acme_inv}",
            ]
        )
    assert exc_info2.value.code == 0
    assert len(captured_calls) == 1
    from uniconn.mcp.server import MCPServer

    srv_obj = captured_calls[0]["server"]
    assert isinstance(srv_obj, MCPServer)
    assert "acme" in srv_obj._tenant_registries


def test_cli_mcp_http_mtls_keeps_default_role_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI ``--transport http --auth-mode mtls`` не должен пробрасывать --agent-role как fail-open default_role."""
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n", encoding="utf-8")

    captured: list[dict[str, object]] = []

    async def _fake_serve_http(self: object, *, auth_config: object = None, http_config: object = None) -> None:
        captured.append({"auth_config": auth_config, "http_config": http_config})

    monkeypatch.setattr("uniconn.mcp.server.MCPServer.serve_http", _fake_serve_http)
    app = create_cli_app()
    with pytest.raises(SystemExit) as exc_info:
        app.meta(
            [
                "mcp",
                "--transport",
                "http",
                "--auth-mode",
                "mtls",
                "--tls-client-ca",
                str(ca_file),
                "--trusted-proxy-cidrs",
                "10.0.0.0/8",
                "--local",
            ]
        )
    assert exc_info.value.code == 0
    assert len(captured) == 1
    from uniconn.mcp.auth import MCPAuthConfig, MCPHttpConfig

    auth_cfg = captured[0]["auth_config"]
    http_cfg = captured[0]["http_config"]
    assert isinstance(auth_cfg, MCPAuthConfig)
    assert auth_cfg.default_role is None
    assert auth_cfg.mtls is not None and auth_cfg.mtls.ca_cert_path == str(ca_file)
    assert isinstance(http_cfg, MCPHttpConfig)
    assert http_cfg.tls_client_ca_path is None


