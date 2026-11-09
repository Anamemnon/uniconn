# tests/unit/mcp/test_mcp_server.py
"""Unit-тесты встроенного MCP-сервера (Model Context Protocol) uniconn."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    MCPHostEntry,
    MCPHostRegistry,
    MCPSecurityPolicy,
    MCPServer,
    mask_uri_secrets,
)
from uniconn.mcp.server import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    SUPPORTED_PROTOCOL_VERSION,
)


def _extract_tool_payload(response: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Распаковать JSON-payload из ответа ``tools/call``."""
    result = response["result"]
    is_error = bool(result.get("isError", False))
    text = result["content"][0]["text"]
    return json.loads(text), is_error


def test_mask_uri_secrets_redacts_credentials_and_tokens() -> None:
    """mask_uri_secrets скрывает пароли в userinfo и секретные параметры query."""
    raw = "ssh://admin:MySuperSecret123@10.0.0.5:22?sudo_password=RootPass99&keepalive=30"
    masked = mask_uri_secrets(raw)
    assert "MySuperSecret123" not in masked
    assert "RootPass99" not in masked
    assert "admin:***REDACTED***@10.0.0.5:22" in masked
    assert "sudo_password=***REDACTED***" in masked
    assert "keepalive=30" in masked


def test_registry_loads_inventory_top_level_groups_and_masks_dict_secrets(tmp_path: Path) -> None:
    """MCPHostRegistry загружает YAML-инвентарь (включая секцию groups) и скрывает raw_config."""
    inv_file = tmp_path / "hosts.yaml"
    inv_file.write_text(
        """
groups:
  cluster: ["local-1", "ssh-prod"]
hosts:
  local-1:
    uri: "local://"
    groups: ["dev", "edge"]
  ssh-prod:
    transport: "ssh"
    host: "192.168.1.10"
    port: 2222
    username: "deploy"
    password: "TopSecretPass"
""",
        encoding="utf-8",
    )

    reg = MCPHostRegistry.from_sources(inventory=inv_file)
    entries = reg.list_entries()
    assert len(entries) == 2

    prod_entry = reg.get_entry("ssh-prod")
    assert prod_entry.transport == "ssh"
    assert prod_entry.masked_uri == "ssh://deploy:***REDACTED***@192.168.1.10:2222"
    assert "TopSecretPass" not in prod_entry.masked_uri
    assert "TopSecretPass" not in repr(prod_entry)
    assert "raw_config" not in prod_entry.model_dump()
    assert "TopSecretPass" not in json.dumps(prod_entry.to_public_dict())

    # Top-level group 'cluster' is merged with inline groups
    assert set(prod_entry.groups) == {"cluster"}
    assert set(reg.get_entry("local-1").groups) == {"dev", "edge", "cluster"}

    # Intersection of group and targets in resolve_targets
    intersected = reg.resolve_targets(["local-1"], group="cluster")
    assert [e.name for e in intersected] == ["local-1"]

    with pytest.raises(KeyError, match="None of the requested targets belong to group"):
        reg.resolve_targets(["ssh-prod"], group="dev")


def test_registry_dynamic_uri_guardrail() -> None:
    """По умолчанию незарегистрированные URI блокируются, а с allow_dynamic_uri=True разрешаются."""
    strict_reg = MCPHostRegistry.from_sources(include_local=True)
    with pytest.raises(PermissionError, match="dynamic URIs are disabled"):
        strict_reg.get_entry("local://?timeout=10")

    with pytest.raises(KeyError, match="not found in MCP registry"):
        strict_reg.get_entry("nonexistent-host")

    dyn_policy = MCPSecurityPolicy(allow_dynamic_uri=True)
    dyn_reg = MCPHostRegistry.from_sources(include_local=True, policy=dyn_policy)
    entry = dyn_reg.get_entry("local://?timeout=10")
    assert entry.transport == "local"


@pytest.mark.asyncio
async def test_mcp_initialize_ping_and_notifications() -> None:
    """Проверка JSON-RPC рукопожатия initialize, уведомлений и метода ping."""
    server = MCPServer()

    init_resp = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": SUPPORTED_PROTOCOL_VERSION},
        }
    )
    assert isinstance(init_resp, dict)
    assert init_resp["id"] == 1
    assert init_resp["result"]["protocolVersion"] == SUPPORTED_PROTOCOL_VERSION
    assert "tools" in init_resp["result"]["capabilities"]
    assert "resources" in init_resp["result"]["capabilities"]
    assert init_resp["result"]["serverInfo"]["name"] == "uniconn-mcp"

    # Notification without id returns None
    notif_resp = await server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert notif_resp is None

    ping_resp = await server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}


@pytest.mark.asyncio
async def test_mcp_tools_list_and_resources_discovery() -> None:
    """Проверка tools/list, resources/list, resources/templates/list и resources/read."""
    server = MCPServer()

    tools_resp = await server.handle_message({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
    assert isinstance(tools_resp, dict)
    tools = tools_resp["result"]["tools"]
    tool_names = {t["name"] for t in tools}
    assert {
        "uniconn_list_hosts",
        "uniconn_ping",
        "uniconn_run",
        "uniconn_gather_facts",
        "uniconn_diff_facts",
        "uniconn_read_file",
        "uniconn_stat_path",
        "uniconn_checksum",
        "uniconn_write_file",
    } <= tool_names

    res_list = await server.handle_message({"jsonrpc": "2.0", "id": 11, "method": "resources/list"})
    assert isinstance(res_list, dict)
    assert res_list["result"]["resources"][0]["uri"] == "uniconn://inventory/hosts"

    tpl_list = await server.handle_message(
        {"jsonrpc": "2.0", "id": 12, "method": "resources/templates/list"}
    )
    assert isinstance(tpl_list, dict)
    assert tpl_list["result"]["resourceTemplates"][0]["uriTemplate"] == "uniconn://hosts/{host}/facts"

    read_inv = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "resources/read",
            "params": {"uri": "uniconn://inventory/hosts"},
        }
    )
    assert isinstance(read_inv, dict)
    inv_payload = json.loads(read_inv["result"]["contents"][0]["text"])
    assert inv_payload["hosts"][0]["name"] == "local"

    read_facts = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "resources/read",
            "params": {"uri": "uniconn://hosts/local/facts"},
        }
    )
    assert isinstance(read_facts, dict)
    facts_payload = json.loads(read_facts["result"]["contents"][0]["text"])
    assert facts_payload["target"] == "local"
    assert "os_family" in facts_payload["facts"]


@pytest.mark.asyncio
async def test_mcp_execution_and_facts_tools(tmp_path: Path) -> None:
    """Проверка инструментов uniconn_list_hosts, uniconn_ping, uniconn_run, gather_facts и diff_facts."""
    entries = [
        MCPHostEntry(
            name="node-a",
            uri="local://",
            masked_uri="local://",
            transport="local",
            host="localhost",
            groups=("cluster",),
            raw_config={"uri": "local://", "name": "node-a"},
        ),
        MCPHostEntry(
            name="node-b",
            uri="local://",
            masked_uri="local://",
            transport="local",
            host="localhost",
            groups=("cluster",),
            raw_config={"uri": "local://", "name": "node-b"},
        ),
        MCPHostEntry(
            name="broken-node",
            uri="replay://broken?cassette=/nonexistent/cassette.yaml",
            masked_uri="replay://broken?cassette=/nonexistent/cassette.yaml",
            transport="replay",
            host="broken",
            groups=(),
            raw_config={"uri": "replay://broken?cassette=/nonexistent/cassette.yaml"},
        ),
    ]
    registry = MCPHostRegistry(entries=entries)
    server = MCPServer(registry=registry)

    # 1. uniconn_list_hosts
    resp_hosts = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "uniconn_list_hosts", "arguments": {"group": "cluster"}},
        }
    )
    assert isinstance(resp_hosts, dict)
    payload_hosts, is_err = _extract_tool_payload(resp_hosts)
    assert not is_err
    assert len(payload_hosts["hosts"]) == 2

    # 2. uniconn_ping (concurrent across healthy and broken nodes without crashing)
    resp_ping = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "uniconn_ping",
                "arguments": {"targets": ["node-a", "node-b", "broken-node"]},
            },
        }
    )
    assert isinstance(resp_ping, dict)
    payload_ping, is_err = _extract_tool_payload(resp_ping)
    assert not is_err
    assert payload_ping["results"]["node-a"]["reachable"] is True
    assert payload_ping["results"]["node-b"]["reachable"] is True
    assert payload_ping["results"]["broken-node"]["reachable"] is False

    # 3. uniconn_run with JSON auto-parsing
    resp_run = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "uniconn_run",
                "arguments": {
                    "target": "node-a",
                    "command": 'echo \'{"status": "healthy", "workers": 4}\'',
                    "parse": True,
                },
            },
        }
    )
    assert isinstance(resp_run, dict)
    payload_run, is_err = _extract_tool_payload(resp_run)
    assert not is_err
    assert payload_run["ok"] is True
    assert payload_run["parsed"] == {"status": "healthy", "workers": 4}

    # 4. uniconn_diff_facts across group
    resp_diff = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "uniconn_diff_facts", "arguments": {"group": "cluster"}},
        }
    )
    assert isinstance(resp_diff, dict)
    payload_diff, is_err = _extract_tool_payload(resp_diff)
    assert not is_err
    assert payload_diff["hosts"] == ["node-a", "node-b"]
    assert isinstance(payload_diff["is_identical"], bool)


@pytest.mark.asyncio
async def test_mcp_file_tools_and_security_guardrails(tmp_path: Path) -> None:
    """Проверка файловых инструментов (read, stat, checksum, write) и политик безопасности."""
    sample = tmp_path / "config.txt"
    sample.write_text("service_port=8080\n", encoding="utf-8")

    # 1. Safe Mode by Default (allow_write=False, allow_sudo=False)
    safe_server = MCPServer()

    # Write blocked by default
    write_blocked = await safe_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "uniconn_write_file",
                "arguments": {
                    "target": "local",
                    "path": str(tmp_path / "forbidden.txt"),
                    "content": "hacked",
                },
            },
        }
    )
    assert isinstance(write_blocked, dict)
    err_payload, is_err = _extract_tool_payload(write_blocked)
    assert is_err is True
    assert "disabled by default MCP security" in err_payload["message"]

    # Sudo blocked by default
    sudo_blocked = await safe_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "uniconn_run",
                "arguments": {"target": "local", "command": "id", "sudo": True},
            },
        }
    )
    assert isinstance(sudo_blocked, dict)
    sudo_payload, is_err = _extract_tool_payload(sudo_blocked)
    assert is_err is True
    assert "sudo=True" in sudo_payload["message"]

    # Destructive command blocked by default blocklist_hook
    rm_blocked = await safe_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "uniconn_run",
                "arguments": {"target": "local", "command": "rm -rf /"},
            },
        }
    )
    assert isinstance(rm_blocked, dict)
    rm_payload, is_err = _extract_tool_payload(rm_blocked)
    assert is_err is True
    assert rm_payload["error"] == "PermissionError"

    # Read, stat, checksum work in Safe Mode (including max_bytes=None default fallback)
    stat_resp = await safe_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "uniconn_stat_path",
                "arguments": {"target": "local", "path": str(sample)},
            },
        }
    )
    assert isinstance(stat_resp, dict)
    stat_payload, is_err = _extract_tool_payload(stat_resp)
    assert not is_err
    assert stat_payload["exists"] is True
    assert stat_payload["stat"]["size"] == 18

    read_resp = await safe_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "uniconn_read_file",
                "arguments": {"target": "local", "path": str(sample), "max_bytes": 12},
            },
        }
    )
    assert isinstance(read_resp, dict)
    read_payload, is_err = _extract_tool_payload(read_resp)
    assert not is_err
    assert read_payload["content"] == "service_port"
    assert read_payload["truncated"] is True

    csum_resp = await safe_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "uniconn_checksum",
                "arguments": {"targets": "local", "path": str(sample), "algorithm": "sha256"},
            },
        }
    )
    assert isinstance(csum_resp, dict)
    csum_payload, is_err = _extract_tool_payload(csum_resp)
    assert not is_err
    assert csum_payload["all_match"] is True
    assert len(csum_payload["checksums"]["local"]) == 64

    # 2. Server with allow_write=True, allowlist, and audit_log_path
    audit_file = tmp_path / "audit.jsonl"
    write_policy = MCPSecurityPolicy(
        allow_write=True,
        allowlist=("echo",),
        audit_log_path=str(audit_file),
    )
    write_reg = MCPHostRegistry.from_sources(include_local=True, policy=write_policy)
    write_server = MCPServer(registry=write_reg)

    dest_file = tmp_path / "written.txt"
    write_ok = await write_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "uniconn_write_file",
                "arguments": {
                    "target": "local",
                    "path": str(dest_file),
                    "content": "updated_by_mcp\n",
                },
            },
        }
    )
    assert isinstance(write_ok, dict)
    write_ok_payload, is_err = _extract_tool_payload(write_ok)
    assert not is_err
    assert write_ok_payload["bytes_written"] == 15
    assert dest_file.read_text(encoding="utf-8") == "updated_by_mcp\n"

    # Command not in allowlist is rejected
    disallowed = await write_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "uniconn_run",
                "arguments": {"target": "local", "command": "uname -a"},
            },
        }
    )
    assert isinstance(disallowed, dict)
    disallowed_payload, is_err = _extract_tool_payload(disallowed)
    assert is_err is True
    assert "not permitted by allowlist" in disallowed_payload["message"]

    # Command in allowlist succeeds and writes to audit log
    allowed = await write_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "uniconn_run",
                "arguments": {"target": "local", "command": "echo allowed_ok"},
            },
        }
    )
    assert isinstance(allowed, dict)
    allowed_payload, is_err = _extract_tool_payload(allowed)
    assert not is_err
    assert allowed_payload["stdout"].strip() == "allowed_ok"
    assert audit_file.is_file()
    assert "echo allowed_ok" in audit_file.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_mcp_jsonrpc_batch_error_handling_and_stream_loop() -> None:
    """Проверка батчей JSON-RPC 2.0, строгой валидации params и потокового цикла serve_streams."""
    server = MCPServer()

    # Parse error
    bad_json = await server.handle_json_line("{not valid json")
    assert bad_json is not None
    assert json.loads(bad_json)["error"]["code"] == JSONRPC_PARSE_ERROR

    # Empty batch is invalid request
    empty_batch = await server.handle_message([])
    assert isinstance(empty_batch, dict)
    assert empty_batch["error"]["code"] == JSONRPC_INVALID_REQUEST

    # Valid batch mixing requests and notifications
    batch_resp = await server.handle_message(
        [
            {"jsonrpc": "2.0", "id": 10, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 11, "method": "tools/list"},
        ]
    )
    assert isinstance(batch_resp, list)
    assert len(batch_resp) == 2
    assert batch_resp[0]["id"] == 10
    assert batch_resp[1]["id"] == 11

    # Invalid request version
    inv_req = await server.handle_message({"jsonrpc": "1.0", "id": 1, "method": "ping"})
    assert isinstance(inv_req, dict)
    assert inv_req["error"]["code"] == JSONRPC_INVALID_REQUEST

    # Missing method even without id returns invalid request
    missing_method = await server.handle_message({"jsonrpc": "2.0"})
    assert isinstance(missing_method, dict)
    assert missing_method["error"]["code"] == JSONRPC_INVALID_REQUEST

    # Non-dict params (e.g. empty list []) rejected as invalid params
    list_params = await server.handle_message(
        {"jsonrpc": "2.0", "id": 99, "method": "ping", "params": []}
    )
    assert isinstance(list_params, dict)
    assert list_params["error"]["code"] == JSONRPC_INVALID_PARAMS

    # Method not found
    not_found = await server.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "nonexistent/method"}
    )
    assert isinstance(not_found, dict)
    assert not_found["error"]["code"] == JSONRPC_METHOD_NOT_FOUND

    # Invalid params inside tools/call
    inv_params = await server.handle_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"arguments": {}}}
    )
    assert isinstance(inv_params, dict)
    assert inv_params["error"]["code"] == JSONRPC_INVALID_PARAMS

    # Stream reader / writer test
    written_lines: list[str] = []

    class _DummyWriter:
        def write(self, data: str) -> None:
            written_lines.append(data)

        def flush(self) -> None:
            pass

    async def _input_lines():
        yield json.dumps({"jsonrpc": "2.0", "id": 100, "method": "ping"}) + "\n"
        yield json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"

    await server.serve_streams(_input_lines(), _DummyWriter())
    assert len(written_lines) == 1
    assert json.loads(written_lines[0]) == {"jsonrpc": "2.0", "id": 100, "result": {}}
    await asyncio.sleep(0)
