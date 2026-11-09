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
