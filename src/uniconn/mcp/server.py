# src/uniconn/mcp/server.py
"""Реализация сервера Model Context Protocol (MCP) поверх JSON-RPC 2.0 (stdio)."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterable, Callable, Coroutine
from typing import Any, Literal

from .._logging import SecretMaskingFilter
from ..parsing import ParseSpec
from ..result import _serialize_parsed_value
from ..services.facts_models import HostFacts, diff_facts
from .models import MCPHostEntry, MCPSecurityPolicy
from .registry import MCPHostRegistry
from .schemas import (
    build_default_resource_templates,
    build_default_resources,
    build_default_tools,
)

SUPPORTED_PROTOCOL_VERSION = "2024-11-05"

# Коды ошибок JSON-RPC 2.0
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603


def _sanitize_json_value(val: Any) -> Any:
    """Преобразовать значение в JSON-совместимый тип и замаскировать секреты в строках."""
    serialized = _serialize_parsed_value(val)
    if isinstance(serialized, str):
        return SecretMaskingFilter._mask_string(serialized)
    if isinstance(serialized, list):
        return [_sanitize_json_value(item) for item in serialized]
    if isinstance(serialized, dict):
        return {str(k): _sanitize_json_value(v) for k, v in serialized.items()}
    return serialized


class MCPServer:
    """Асинхронный сервер протокола Model Context Protocol (MCP) для ``uniconn``."""

    def __init__(
        self,
        registry: MCPHostRegistry | None = None,
        *,
        server_name: str = "uniconn-mcp",
        server_version: str | None = None,
    ) -> None:
        """Создать экземпляр MCP-сервера с реестром хостов и политикой безопасности."""
        from .. import __version__

        self.registry = registry or MCPHostRegistry.from_sources()
        self.server_name = server_name
        self.server_version = server_version or __version__
        self._tools = build_default_tools(self.registry.policy)
        self._resources = build_default_resources()
        self._resource_templates = build_default_resource_templates()
        self._tool_handlers: dict[str, Callable[[dict[str, Any]], Coroutine[Any, Any, dict[str, Any]]]] = {
            "uniconn_list_hosts": self._tool_list_hosts,
            "uniconn_ping": self._tool_ping,
            "uniconn_run": self._tool_run,
            "uniconn_gather_facts": self._tool_gather_facts,
            "uniconn_diff_facts": self._tool_diff_facts,
            "uniconn_read_file": self._tool_read_file,
            "uniconn_stat_path": self._tool_stat_path,
            "uniconn_checksum": self._tool_checksum,
            "uniconn_write_file": self._tool_write_file,
        }

    @property
    def policy(self) -> MCPSecurityPolicy:
        """Активная политика безопасности сервера."""
        return self.registry.policy

    async def handle_message(self, message: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
        """Обработать сообщение или батч JSON-RPC 2.0 и вернуть ответ (или ``None`` для уведомлений)."""
        if isinstance(message, list):
            if not message:
                return self._error_response(None, JSONRPC_INVALID_REQUEST, "Empty JSON-RPC batch")
            responses = await asyncio.gather(*(self._handle_single_message(item) for item in message))
            valid_responses = [r for r in responses if r is not None]
            return valid_responses if valid_responses else None

        return await self._handle_single_message(message)

    async def _handle_single_message(self, message: Any) -> dict[str, Any] | None:
        """Обработать одиночный объект запроса или уведомления JSON-RPC 2.0."""
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self._error_response(
                message.get("id") if isinstance(message, dict) else None,
                JSONRPC_INVALID_REQUEST,
                "Invalid JSON-RPC 2.0 request payload",
            )

        method = message.get("method")
        has_id = "id" in message
        msg_id = message.get("id")

        if not isinstance(method, str) or not method:
            return self._error_response(
                msg_id if has_id else None,
                JSONRPC_INVALID_REQUEST,
                "Missing or invalid method name",
            )

        raw_params = message.get("params")
        if raw_params is None:
            params: dict[str, Any] = {}
        elif isinstance(raw_params, dict):
            params = raw_params
        else:
            if not has_id:
                return None
            return self._error_response(msg_id, JSONRPC_INVALID_PARAMS, "Params must be an object")

        # Уведомления JSON-RPC (без id) не требуют ответа
        if not has_id:
            return None

        try:
            result = await self._dispatch_method(method, params)
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
        except (KeyError, ValueError) as exc:
            return self._error_response(msg_id, JSONRPC_INVALID_PARAMS, str(exc))
        except NotImplementedError as exc:
            return self._error_response(msg_id, JSONRPC_METHOD_NOT_FOUND, str(exc))
        except Exception as exc:
            return self._error_response(msg_id, JSONRPC_INTERNAL_ERROR, str(exc))

    async def handle_json_line(self, line: str) -> str | None:
        """Распарсить строку JSON-RPC 2.0, выполнить запрос и вернуть сериализованный JSON-ответ."""
        stripped = line.strip()
        if not stripped:
            return None
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            err = self._error_response(None, JSONRPC_PARSE_ERROR, f"Parse error: {exc.msg}")
            return json.dumps(err, ensure_ascii=False)

        response = await self.handle_message(payload)
        if response is None:
            return None
        return json.dumps(response, ensure_ascii=False)

    async def serve_streams(
        self,
        reader: AsyncIterable[bytes | str],
        writer: Any,
    ) -> None:
        """Запустить цикл обработки сообщений JSON-RPC 2.0 из входного потока в выходной."""
        async for raw_line in reader:
            line = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, bytes) else raw_line
            resp_str = await self.handle_json_line(line)
            if resp_str is not None:
                out_data = resp_str + "\n"
                if hasattr(writer, "write"):
                    res = writer.write(out_data.encode("utf-8") if getattr(writer, "is_binary", False) else out_data)
                    if asyncio.iscoroutine(res):
                        await res
                if hasattr(writer, "drain"):
                    drain_res = writer.drain()
                    if asyncio.iscoroutine(drain_res):
                        await drain_res
                elif hasattr(writer, "flush"):
                    flush_res = writer.flush()
                    if asyncio.iscoroutine(flush_res):
                        await flush_res

    async def serve_stdio(self) -> None:
        """Запустить MCP-сервер в стандартном режиме ``stdio`` (чтение из ``stdin``, запись в ``stdout``)."""
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            resp_str = await self.handle_json_line(line)
            if resp_str is not None:
                sys.stdout.write(resp_str + "\n")
                sys.stdout.flush()

    async def _dispatch_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Маршрутизировать метод протокола MCP к соответствующему обработчику."""
        if method == "initialize":
            client_proto = params.get("protocolVersion")
            proto_ver = (
                str(client_proto)
                if isinstance(client_proto, str) and client_proto
                else SUPPORTED_PROTOCOL_VERSION
            )
            return {
                "protocolVersion": proto_ver,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version,
                },
            }

        if method == "ping":
            return {}

        if method == "tools/list":
            return {"tools": [t.to_mcp_dict() for t in self._tools]}

        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                raise ValueError("Missing required parameter 'name' for tools/call")
            raw_args = params.get("arguments")
            if raw_args is None:
                arguments: dict[str, Any] = {}
            elif isinstance(raw_args, dict):
                arguments = raw_args
            else:
                raise ValueError("Tool 'arguments' must be an object")
            return await self._call_tool(tool_name, arguments)

        if method == "resources/list":
            return {"resources": [r.to_mcp_dict() for r in self._resources]}

        if method == "resources/templates/list":
            return {"resourceTemplates": [rt.to_mcp_dict() for rt in self._resource_templates]}

        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri:
                raise ValueError("Missing required parameter 'uri' for resources/read")
            return await self._read_resource(uri)

        raise NotImplementedError(f"MCP method {method!r} is not supported")

    async def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Выполнить MCP-инструмент и обернуть результат в формат ``CallToolResult``."""
        handler = self._tool_handlers.get(name)
        if handler is None:
            return self._tool_response(
                {
                    "error": f"Unknown tool: {name!r}",
                    "available_tools": sorted(self._tool_handlers.keys()),
                },
                is_error=True,
            )

        try:
            payload = await handler(arguments)
            return self._tool_response(payload, is_error=False)
        except Exception as exc:
            return self._tool_response(
                {
                    "error": type(exc).__name__,
                    "message": SecretMaskingFilter._mask_string(str(exc)),
                },
                is_error=True,
            )

    async def _tool_list_hosts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        group = arguments.get("group")
        entries = self.registry.list_entries(group=str(group) if group else None)
        return {
            "hosts": [e.to_public_dict() for e in entries],
            "groups": self.registry.list_groups(),
            "security_policy": self.policy.to_summary_dict(),
        }

    async def _tool_ping(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_targets = arguments.get("targets")
        if not raw_targets:
            raise ValueError("Parameter 'targets' is required")
        timeout = float(arguments.get("timeout", 5.0))
        entries = self.registry.resolve_targets(raw_targets)

        async def _ping_one(entry: MCPHostEntry) -> tuple[str, dict[str, Any]]:
            try:
                async with self.registry.create_connection(entry) as conn:
                    ping_res = await conn.ping(timeout=timeout)
                    return entry.name, {
                        "alive": ping_res.alive,
                        "reachable": ping_res.alive,
                        "latency_ms": round(ping_res.latency_ms, 3),
                        "transport": ping_res.transport,
                        "error": SecretMaskingFilter._mask_string(ping_res.error)
                        if ping_res.error
                        else None,
                    }
            except Exception as exc:
                return entry.name, {
                    "alive": False,
                    "reachable": False,
                    "latency_ms": 0.0,
                    "transport": entry.transport,
                    "error": SecretMaskingFilter._mask_string(str(exc)),
                }

        pairs = await asyncio.gather(*(_ping_one(e) for e in entries))
        return {"results": dict(pairs)}

    async def _tool_run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        command = arguments.get("command")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("Parameter 'command' must be a non-empty string")

        sudo = bool(arguments.get("sudo", False))
        if sudo and not self.policy.allow_sudo:
            raise PermissionError(
                "Privileged execution (sudo=True) is disabled by MCP security policy "
                "(start server with --allow-sudo to enable)."
            )

        timeout = float(arguments.get("timeout", 30.0))
        cwd = arguments.get("cwd")
        raw_parse = arguments.get("parse", True)
        parse_spec: ParseSpec
        if raw_parse is True:
            parse_spec = "auto"
        elif raw_parse is False or raw_parse is None:
            parse_spec = None
        else:
            parse_spec = str(raw_parse)

        run_kwargs: dict[str, Any] = {}
        if isinstance(cwd, str) and cwd.strip():
            run_kwargs["cwd"] = cwd.strip()

        async with self.registry.create_connection(target) as conn:
            res = await conn.run(
                command,
                timeout=timeout,
                sudo=sudo,
                parse=parse_spec,
                raise_on_error=False,
                **run_kwargs,
            )
            parsed_data: Any = None
            if parse_spec is not None:
                try:
                    parsed_data = _sanitize_json_value(res.parsed)
                except Exception:
                    parsed_data = None

            return {
                "host": res.host or target,
                "command": SecretMaskingFilter._mask_string(res.command),
                "ok": res.ok,
                "exit_code": res.exit_code,
                "duration_ms": round(res.duration * 1000, 3),
                "stdout": SecretMaskingFilter._mask_string(res.stdout),
                "stderr": SecretMaskingFilter._mask_string(res.stderr),
                "parsed": parsed_data,
                "dry_run": self.policy.dry_run,
            }

    async def _tool_gather_facts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        timeout = float(arguments.get("timeout", 15.0))

        async with self.registry.create_connection(target) as conn:
            facts = await conn.gather_facts(refresh=True, timeout=timeout)
            return {
                "target": target,
                "facts": _sanitize_json_value(facts.to_dict()),
            }

    async def _tool_diff_facts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_targets = arguments.get("targets")
        group = arguments.get("group")
        entries = self.registry.resolve_targets(
            raw_targets,
            group=str(group) if group else None,
        )
        if len(entries) < 2:
            raise ValueError("uniconn_diff_facts requires at least 2 target hosts to compare")

        async def _gather_one(entry: MCPHostEntry) -> tuple[str, HostFacts]:
            async with self.registry.create_connection(entry) as conn:
                return entry.name, await conn.gather_facts(refresh=True)

        gathered_pairs = await asyncio.gather(*(_gather_one(e) for e in entries))
        facts_by_host: dict[str, HostFacts] = dict(gathered_pairs)

        report = diff_facts(facts_by_host)
        return _sanitize_json_value(
            {
                "hosts": list(facts_by_host.keys()),
                "is_identical": not report.has_drift,
                **report.to_dict(),
            }
        )

    async def _tool_read_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        path = arguments.get("path")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")

        raw_max = arguments.get("max_bytes")
        req_max = self.policy.max_read_bytes if raw_max is None else int(raw_max)
        limit = max(1, min(req_max, self.policy.max_read_bytes))

        async with self.registry.create_connection(target) as conn:
            raw_content = await conn.files.read_file(path, encoding=None)
            encoded = (
                raw_content
                if isinstance(raw_content, bytes)
                else str(raw_content).encode("utf-8")
            )
            truncated = len(encoded) > limit
            sliced = encoded[:limit] if truncated else encoded
            text = sliced.decode("utf-8", errors="replace")

            return {
                "target": target,
                "path": path,
                "content": SecretMaskingFilter._mask_string(text),
                "total_bytes": len(encoded),
                "truncated": truncated,
            }

    async def _tool_stat_path(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        path = arguments.get("path")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")

        async with self.registry.create_connection(target) as conn:
            exists = await conn.files.exists(path)
            if not exists:
                return {"target": target, "path": path, "exists": False, "stat": None}
            st = await conn.files.stat(path)
            return {
                "target": target,
                "path": path,
                "exists": True,
                "stat": _sanitize_json_value(dict(st)),
            }

    async def _tool_checksum(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_targets = arguments.get("targets")
        path = arguments.get("path")
        if not raw_targets:
            raise ValueError("Parameter 'targets' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")
        raw_algo = str(arguments.get("algorithm") or "sha256").lower()
        algo: Literal["sha256", "sha1", "md5"]
        if raw_algo == "md5":
            algo = "md5"
        elif raw_algo == "sha1":
            algo = "sha1"
        elif raw_algo == "sha256":
            algo = "sha256"
        else:
            raise ValueError(f"Unsupported checksum algorithm: {raw_algo!r}")

        entries = self.registry.resolve_targets(raw_targets)

        async def _hash_one(entry: MCPHostEntry) -> tuple[str, str | None]:
            async with self.registry.create_connection(entry) as conn:
                return entry.name, await conn.files.checksum(path, algorithm=algo)

        pairs = await asyncio.gather(*(_hash_one(e) for e in entries))
        checksums: dict[str, str | None] = dict(pairs)

        unique_hashes = {h for h in checksums.values() if h is not None}
        return {
            "path": path,
            "algorithm": algo,
            "checksums": checksums,
            "all_match": len(unique_hashes) == 1 and None not in checksums.values(),
        }

    async def _tool_write_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.policy.allow_write:
            raise PermissionError(
                "File modification (uniconn_write_file) is disabled by default MCP security "
                "policy (start server with --allow-write to enable)."
            )

        target = arguments.get("target")
        path = arguments.get("path")
        content = arguments.get("content")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("Parameter 'path' is required")
        if not isinstance(content, str):
            raise ValueError("Parameter 'content' must be a string")

        atomic = bool(arguments.get("atomic", True))
        async with self.registry.create_connection(target) as conn:
            await conn.files.write_file(path, content, atomic=atomic)
            return {
                "target": target,
                "path": path,
                "bytes_written": len(content.encode("utf-8")),
                "atomic": atomic,
                "dry_run": self.policy.dry_run,
            }

    async def _read_resource(self, uri: str) -> dict[str, Any]:
        """Прочитать MCP-ресурс по URI."""
        if uri == "uniconn://inventory/hosts":
            data = await self._tool_list_hosts({})
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(data, ensure_ascii=False, indent=2),
                    }
                ]
            }

        prefix = "uniconn://hosts/"
        suffix = "/facts"
        if uri.startswith(prefix) and uri.endswith(suffix):
            host_name = uri[len(prefix) : -len(suffix)].strip("/")
            if not host_name:
                raise ValueError(f"Invalid host resource URI: {uri!r}")
            facts_payload = await self._tool_gather_facts({"target": host_name})
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(facts_payload, ensure_ascii=False, indent=2),
                    }
                ]
            }

        raise KeyError(f"Resource URI not found: {uri!r}")

    @staticmethod
    def _tool_response(payload: dict[str, Any], *, is_error: bool) -> dict[str, Any]:
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(_sanitize_json_value(payload), ensure_ascii=False),
                }
            ],
            "isError": is_error,
        }

    @staticmethod
    def _error_response(
        msg_id: Any,
        code: int,
        message: str,
    ) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": SecretMaskingFilter._mask_string(message),
            },
        }


__all__ = [
    "JSONRPC_INTERNAL_ERROR",
    "JSONRPC_INVALID_PARAMS",
    "JSONRPC_INVALID_REQUEST",
    "JSONRPC_METHOD_NOT_FOUND",
    "JSONRPC_PARSE_ERROR",
    "SUPPORTED_PROTOCOL_VERSION",
    "MCPServer",
]
