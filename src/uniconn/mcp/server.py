# src/uniconn/mcp/server.py
"""Реализация сервера Model Context Protocol (MCP) поверх JSON-RPC 2.0 (stdio)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from collections.abc import AsyncIterable, Callable, Coroutine, Mapping, Sequence
from pathlib import Path
from typing import Any, Self

from .._logging import SecretMaskingFilter
from ..orchestration.flow import Flow, SyncFlow
from ..security.engine import PolicyEngine, create_policy_engine
from ._server_gates import (
    _build_pending_approval_payload as _build_pending_approval_payload,
)
from ._server_gates import (
    _sanitize_json_value as _sanitize_json_value,
)
from ._server_tools import MCPServerToolsMixin
from .auth import JsonFetcher, MCPAuthConfig, MCPHttpConfig
from .flows import FlowCheckpointStore, MCPFlowRegistry
from .hitl import ApprovalManager
from .models import MCPSecurityPolicy
from .registry import MCPHostRegistry
from .schemas import (
    build_default_resource_templates,
    build_default_resources,
    build_default_tools,
)
from .storage import StateStore, resolve_state_store

SUPPORTED_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2025-03-26", "2024-11-05")

# Коды ошибок JSON-RPC 2.0
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603


class MCPServer(MCPServerToolsMixin):
    """Асинхронный сервер протокола Model Context Protocol (MCP) для ``uniconn``."""

    def __init__(
        self,
        registry: MCPHostRegistry | None = None,
        *,
        tenant_registries: Mapping[str, MCPHostRegistry] | None = None,
        tenant_policy_engines: Mapping[str, PolicyEngine] | None = None,
        allow_shared_hosts: bool = False,
        auth_config: MCPAuthConfig | None = None,
        http_config: MCPHttpConfig | None = None,
        state_store: StateStore | None = None,
        approval_manager: ApprovalManager | None = None,
        policy_engine: PolicyEngine | None = None,
        flow_registry: MCPFlowRegistry | None = None,
        flows: Sequence[Flow | SyncFlow] = (),
        flow_specs: Sequence[str | Path] = (),
        checkpoint_store: FlowCheckpointStore | None = None,
        checkpoint_secret: str | bytes | None = None,
        server_name: str = "uniconn-mcp",
        server_version: str | None = None,
    ) -> None:
        """Создать экземпляр MCP-сервера с реестром хостов, тенантами, Flow, политикой, HITL и StateStore."""
        from .. import __version__

        self.registry = registry or MCPHostRegistry.from_sources()
        self._tenant_registries: dict[str, MCPHostRegistry] = (
            {str(k).strip(): v for k, v in tenant_registries.items() if str(k).strip()}
            if tenant_registries
            else {}
        )
        self._tenant_policy_engines: dict[str, PolicyEngine] = (
            {str(k).strip(): v for k, v in tenant_policy_engines.items() if str(k).strip()}
            if tenant_policy_engines
            else {}
        )
        self.allow_shared_hosts = bool(allow_shared_hosts)
        self.auth_config = auth_config
        self.http_config = http_config
        self.server_name = server_name
        self.server_version = server_version or __version__
        hitl_pol = self.registry.policy.hitl
        if hitl_pol.audit_log_path is None and self.registry.policy.audit_log_path:
            hitl_pol = hitl_pol.model_copy(
                update={"audit_log_path": self.registry.policy.audit_log_path}
            )

        self._owns_state_store = False
        if state_store is not None:
            self.state_store: StateStore = state_store
        elif approval_manager is not None:
            self.state_store = approval_manager.store
        else:
            raw_state_path = (
                hitl_pol.store_path
                or os.environ.get("UNICONN_STATE_DB")
                or os.environ.get("UNICONN_APPROVAL_STORE")
            )
            self.state_store, _ = resolve_state_store(raw_state_path)
            self._owns_state_store = True

        self.approval_manager = approval_manager or ApprovalManager(
            policy=hitl_pol,
            store=self.state_store,
        )
        self.policy_engine: PolicyEngine = policy_engine or create_policy_engine(
            self.registry.policy.guardrails
        )
        self.flow_registry = flow_registry or MCPFlowRegistry.from_sources(
            specs=flow_specs,
            flows=flows,
        )
        if checkpoint_store is not None:
            self.checkpoint_store = checkpoint_store
        else:
            env_cp_path = os.environ.get("UNICONN_FLOW_CHECKPOINT_STORE")
            if (
                state_store is None
                and approval_manager is None
                and env_cp_path
                and env_cp_path.strip()
                and env_cp_path.strip() != ":memory:"
            ):
                self.checkpoint_store = FlowCheckpointStore(
                    store_path=env_cp_path.strip(),
                    signing_secret=checkpoint_secret,
                )
            else:
                self.checkpoint_store = FlowCheckpointStore(
                    store=self.state_store,
                    signing_secret=checkpoint_secret,
                )
        self._tools = build_default_tools(self.registry.policy)
        self._resources = build_default_resources()
        self._resource_templates = build_default_resource_templates()
        self._tool_handlers: dict[
            str, Callable[[dict[str, Any]], Coroutine[Any, Any, dict[str, Any]]]
        ] = {
            "uniconn_list_hosts": self._tool_list_hosts,
            "uniconn_ping": self._tool_ping,
            "uniconn_run": self._tool_run,
            "uniconn_gather_facts": self._tool_gather_facts,
            "uniconn_diff_facts": self._tool_diff_facts,
            "uniconn_read_file": self._tool_read_file,
            "uniconn_stat_path": self._tool_stat_path,
            "uniconn_checksum": self._tool_checksum,
            "uniconn_write_file": self._tool_write_file,
            "uniconn_propose_action": self._tool_propose_action,
            "uniconn_evaluate_policy": self._tool_evaluate_policy,
            "uniconn_check_approval": self._tool_check_approval,
            "uniconn_wait_approval": self._tool_wait_approval,
            "uniconn_list_flows": self._tool_list_flows,
            "uniconn_inspect_flow": self._tool_inspect_flow,
            "uniconn_run_flow": self._tool_run_flow,
            "uniconn_resume_flow": self._tool_resume_flow,
        }

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Закрыть внутренние хранилища состояния, созданные экземпляром ``MCPServer``."""
        await self.approval_manager.close()
        await self.checkpoint_store.close()
        if self._owns_state_store:
            await self.state_store.close()

    def register_flow(
        self,
        flow: Flow | SyncFlow,
        *,
        tool_name: str | None = None,
    ) -> Flow:
        """Зарегистрировать сценарий ``Flow`` для динамического экспорта как MCP-инструмент."""
        return self.flow_registry.register(flow, tool_name=tool_name)

    def register_tenant(
        self,
        tenant_id: str,
        registry: MCPHostRegistry,
        *,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        """Зарегистрировать выделенный реестр хостов и политику безопасности для тенанта."""
        key = tenant_id.strip()
        if not key:
            raise ValueError("tenant_id must not be empty")
        self._tenant_registries[key] = registry
        if policy_engine is not None:
            self._tenant_policy_engines[key] = policy_engine
        else:
            self._tenant_policy_engines.pop(key, None)

    def _active_registry(self) -> MCPHostRegistry:
        """Вернуть реестр хостов, изолированный для активного верифицированного тенанта."""
        caller = self._active_caller()
        if caller is None or not caller.verified:
            return self.registry
        tenant_id = caller.tenant_id
        if tenant_id is not None:
            if tenant_id in self._tenant_registries:
                return self._tenant_registries[tenant_id]
            return self.registry.for_tenant(
                tenant_id,
                allow_shared_hosts=self.allow_shared_hosts,
            )
        if self._tenant_registries:
            return MCPHostRegistry(
                policy=self.registry.policy.model_copy(update={"allow_dynamic_uri": False}),
                entries=(),
            )
        all_entries = self.registry.list_entries()
        if any(entry.tenant is not None for entry in all_entries):
            untagged = [entry for entry in all_entries if entry.tenant is None]
            return MCPHostRegistry(
                policy=self.registry.policy.model_copy(update={"allow_dynamic_uri": False}),
                entries=untagged if self.allow_shared_hosts else (),
            )
        return self.registry

    def _active_policy_engine(self) -> PolicyEngine:
        """Вернуть движок Policy-as-Code для активного тенанта (или базовый движок сервера)."""
        tenant_id = self._active_tenant_id()
        if tenant_id is not None:
            if tenant_id in self._tenant_policy_engines:
                return self._tenant_policy_engines[tenant_id]
            if tenant_id in self._tenant_registries:
                engine = create_policy_engine(self._tenant_registries[tenant_id].policy.guardrails)
                self._tenant_policy_engines[tenant_id] = engine
                return engine
        return self.policy_engine

    @property
    def policy(self) -> MCPSecurityPolicy:
        """Активная политика безопасности сервера (с учётом выделенной политики тенанта)."""
        return self._active_registry().policy

    def build_http_app(
        self,
        *,
        auth_config: MCPAuthConfig | None = None,
        http_config: MCPHttpConfig | None = None,
        jwks_fetcher: JsonFetcher | None = None,
    ) -> Any:
        """Создать ASGI-приложение Starlette для сетевого MCP Streamable HTTP / SSE шлюза."""
        from .http_transport import build_mcp_http_app

        eff_auth = auth_config or self.auth_config
        if eff_auth is None:
            raise ValueError("MCPAuthConfig must be provided to build_http_app() (fail-closed)")
        eff_http = http_config or self.http_config or MCPHttpConfig()
        return build_mcp_http_app(
            self,
            auth_config=eff_auth,
            http_config=eff_http,
            jwks_fetcher=jwks_fetcher,
        )

    async def serve_http(
        self,
        *,
        auth_config: MCPAuthConfig | None = None,
        http_config: MCPHttpConfig | None = None,
        jwks_fetcher: JsonFetcher | None = None,
    ) -> None:
        """Запустить сетевой MCP Streamable HTTP / SSE сервер поверх Uvicorn."""
        from .http_transport import serve_mcp_http

        eff_auth = auth_config or self.auth_config
        if eff_auth is None:
            raise ValueError("MCPAuthConfig must be provided to serve_http() (fail-closed)")
        eff_http = http_config or self.http_config or MCPHttpConfig()
        await serve_mcp_http(
            self,
            auth_config=eff_auth,
            http_config=eff_http,
            jwks_fetcher=jwks_fetcher,
        )

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
            if isinstance(client_proto, str) and client_proto.strip():
                norm_proto = client_proto.strip()
                proto_ver = (
                    norm_proto
                    if norm_proto in SUPPORTED_PROTOCOL_VERSIONS
                    else SUPPORTED_PROTOCOL_VERSIONS[0]
                )
            else:
                proto_ver = SUPPORTED_PROTOCOL_VERSION
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
            active_pol = self.policy
            base_tools = (
                self._tools
                if active_pol == self.registry.policy
                else build_default_tools(active_pol)
            )
            all_tools = (*base_tools, *self.flow_registry.build_dynamic_tools())
            return {"tools": [t.to_mcp_dict() for t in all_tools]}

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
        dynamic_flow: Flow | None = None
        if handler is None:
            with contextlib.suppress(KeyError):
                dynamic_flow = self.flow_registry.get_flow(name)

        if handler is None and dynamic_flow is None:
            dyn_names = [t.name for t in self.flow_registry.build_dynamic_tools()]
            return self._tool_response(
                {
                    "error": f"Unknown tool: {name!r}",
                    "available_tools": sorted([*self._tool_handlers.keys(), *dyn_names]),
                },
                is_error=True,
            )

        try:
            if handler is not None:
                payload = await handler(arguments)
            else:
                if dynamic_flow is None:
                    raise RuntimeError(f"Dynamic flow handler missing for tool {name!r}")
                payload = await self._execute_flow_by_object(
                    dynamic_flow,
                    tool_name=self.flow_registry.get_tool_name(dynamic_flow.name),
                    arguments=arguments,
                )
            return self._tool_response(payload, is_error=False)
        except Exception as exc:
            err_dict: dict[str, Any] = {
                "error": type(exc).__name__,
                "message": SecretMaskingFilter._mask_string(str(exc)),
            }
            appr_id = getattr(exc, "approval_id", None)
            if appr_id:
                err_dict["approval_id"] = appr_id
            violations = getattr(exc, "violations", None)
            if violations:
                err_dict["decision"] = getattr(exc, "decision", "DENY")
                ser_fn = getattr(exc, "serialized_violations", None)
                err_dict["violations"] = (
                    ser_fn()
                    if callable(ser_fn)
                    else [v.to_dict() if hasattr(v, "to_dict") else v for v in violations]
                )
                err_dict["rule_names"] = list(getattr(exc, "rule_names", ()))
                err_dict["remediation_hint"] = getattr(exc, "remediation_hint", None)
            return self._tool_response(err_dict, is_error=True)

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
    "SUPPORTED_PROTOCOL_VERSIONS",
    "MCPServer",
]
