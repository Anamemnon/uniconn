# src/uniconn/mcp/server.py
"""Реализация сервера Model Context Protocol (MCP) поверх JSON-RPC 2.0 (stdio)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import uuid
from collections.abc import AsyncIterable, Callable, Coroutine, Sequence
from pathlib import Path
from typing import Any, Literal

from .._logging import SecretMaskingFilter
from ..exceptions import ApprovalRejectedError
from ..orchestration.flow import Flow, SyncFlow
from ..orchestration.scheduler import coerce_to_flow
from ..parsing import ParseSpec
from ..result import _serialize_parsed_value
from ..services.facts_models import HostFacts, diff_facts
from .flows import (
    FlowCheckpointStore,
    FlowRiskEvaluator,
    FlowSchemaGenerator,
    MCPFlowRegistry,
)
from .hitl import ActionRiskClassifier, ApprovalManager, build_unified_diff
from .models import (
    ActionRiskTier,
    ApprovalRequest,
    ApprovalStatus,
    MCPHostEntry,
    MCPSecurityPolicy,
)
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


def _build_pending_approval_payload(
    req: ApprovalRequest,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Сформировать ответ со статусом PENDING_APPROVAL для двухфазного протокола MCP."""
    payload: dict[str, Any] = {
        "status": "PENDING_APPROVAL",
        "ok": False,
        "requires_approval": True,
        "approval_id": req.approval_id,
        "target_host": req.target_host,
        "tool_name": req.tool_name,
        "risk_tier": req.risk_tier.value,
        "risk_reasons": list(req.risk_reasons),
        "diff": req.diff,
        "expires_at": req.expires_at.isoformat(),
        "approval": req.to_public_dict(),
        "next_step": (
            f"Action requires human operator approval (id={req.approval_id}). "
            f"Operator can run 'uniconn approval approve {req.approval_id}' or approve in the Dashboard. "
            f"Then call 'uniconn_wait_approval' or re-invoke {req.tool_name!r} with approval_id={req.approval_id!r}."
        ),
    }
    if extra:
        payload.update(extra)
    return payload


class MCPServer:
    """Асинхронный сервер протокола Model Context Protocol (MCP) для ``uniconn``."""

    def __init__(
        self,
        registry: MCPHostRegistry | None = None,
        *,
        approval_manager: ApprovalManager | None = None,
        flow_registry: MCPFlowRegistry | None = None,
        flows: Sequence[Flow | SyncFlow] = (),
        flow_specs: Sequence[str | Path] = (),
        checkpoint_store: FlowCheckpointStore | None = None,
        server_name: str = "uniconn-mcp",
        server_version: str | None = None,
    ) -> None:
        """Создать экземпляр MCP-сервера с реестром хостов, сценариев Flow, политикой и HITL."""
        from .. import __version__

        self.registry = registry or MCPHostRegistry.from_sources()
        self.server_name = server_name
        self.server_version = server_version or __version__
        hitl_pol = self.registry.policy.hitl
        if hitl_pol.audit_log_path is None and self.registry.policy.audit_log_path:
            hitl_pol = hitl_pol.model_copy(
                update={"audit_log_path": self.registry.policy.audit_log_path}
            )
        self.approval_manager = approval_manager or ApprovalManager(policy=hitl_pol)
        self.flow_registry = flow_registry or MCPFlowRegistry.from_sources(
            specs=flow_specs,
            flows=flows,
        )
        default_cp_path: str | Path | None = os.environ.get(
            "UNICONN_FLOW_CHECKPOINT_STORE"
        )
        if default_cp_path is None and hitl_pol.store_path:
            default_cp_path = Path(hitl_pol.store_path).with_name(
                "flow_checkpoints.json"
            )
        self.checkpoint_store = checkpoint_store or FlowCheckpointStore(
            store_path=default_cp_path
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
            "uniconn_check_approval": self._tool_check_approval,
            "uniconn_wait_approval": self._tool_wait_approval,
            "uniconn_list_flows": self._tool_list_flows,
            "uniconn_inspect_flow": self._tool_inspect_flow,
            "uniconn_run_flow": self._tool_run_flow,
            "uniconn_resume_flow": self._tool_resume_flow,
        }

    def register_flow(
        self,
        flow: Flow | SyncFlow,
        *,
        tool_name: str | None = None,
    ) -> Flow:
        """Зарегистрировать сценарий ``Flow`` для динамического экспорта как MCP-инструмент."""
        return self.flow_registry.register(flow, tool_name=tool_name)

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
            all_tools = (*self._tools, *self.flow_registry.build_dynamic_tools())
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
                assert dynamic_flow is not None
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
            return self._tool_response(err_dict, is_error=True)

    async def _resolve_hitl_gate(
        self,
        *,
        entry: MCPHostEntry | None = None,
        target_host: str | None = None,
        tool_name: str,
        allowed_tool_names: Sequence[str] = (),
        risk_tier: ActionRiskTier,
        risk_reasons: tuple[str, ...],
        requires_approval: bool,
        approval_id: str | None,
        wait_for_approval: bool,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: dict[str, Any] | None = None,
        diff: str | None = None,
        agent_id: str | None = None,
        pending_extra: dict[str, Any] | None = None,
    ) -> tuple[ApprovalRequest | None, dict[str, Any] | None]:
        """Выполнить проверку HITL-шлюза: вернуть (consumed_request, pending_payload)."""
        host_label = target_host or (entry.name if entry is not None else "fleet")
        if approval_id is not None and str(approval_id).strip():
            appr_key = str(approval_id).strip()
            effective_tool = tool_name
            if allowed_tool_names:
                with contextlib.suppress(KeyError):
                    existing_req = await self.approval_manager.get_request(appr_key)
                    if existing_req.tool_name in allowed_tool_names:
                        effective_tool = existing_req.tool_name
            consumed = await self.approval_manager.verify_and_consume(
                appr_key,
                target_host=host_label,
                tool_name=effective_tool,
                command=command,
                sudo=sudo,
                cwd=cwd,
                parameters=parameters,
            )
            return consumed, None

        if not requires_approval:
            return None, None

        req = await self.approval_manager.create_request(
            target_host=host_label,
            tool_name=tool_name,
            risk_tier=risk_tier,
            risk_reasons=risk_reasons,
            command=command,
            sudo=sudo,
            cwd=cwd,
            parameters=parameters,
            diff=diff,
            agent_id=agent_id,
        )
        if req.status == ApprovalStatus.APPROVED:
            consumed = await self.approval_manager.verify_and_consume(
                req.approval_id,
                target_host=host_label,
                tool_name=tool_name,
                command=command,
                sudo=sudo,
                cwd=cwd,
                parameters=parameters,
            )
            return consumed, None
        if req.status == ApprovalStatus.REJECTED:
            raise ApprovalRejectedError(
                f"Action rejected by operator ({req.decided_by or 'operator'}): "
                f"{req.decision_reason or 'Rejected'}",
                approval_id=req.approval_id,
                decided_by=req.decided_by,
                decision_reason=req.decision_reason,
                approval_request=req,
                command=command,
                host=host_label,
            )

        if wait_for_approval:
            decided = await self.approval_manager.wait_for_decision(
                req.approval_id,
                timeout=self.policy.hitl.wait_timeout_seconds,
            )
            if decided.status == ApprovalStatus.APPROVED:
                consumed = await self.approval_manager.verify_and_consume(
                    decided.approval_id,
                    target_host=host_label,
                    tool_name=tool_name,
                    command=command,
                    sudo=sudo,
                    cwd=cwd,
                    parameters=parameters,
                )
                return consumed, None
            if decided.status == ApprovalStatus.REJECTED:
                raise ApprovalRejectedError(
                    f"Action rejected by operator ({decided.decided_by or 'operator'}): "
                    f"{decided.decision_reason or 'Rejected'}",
                    approval_id=decided.approval_id,
                    decided_by=decided.decided_by,
                    decision_reason=decided.decision_reason,
                    approval_request=decided,
                    command=command,
                    host=host_label,
                )
            return None, _build_pending_approval_payload(decided, extra=pending_extra)

        return None, _build_pending_approval_payload(req, extra=pending_extra)

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
        hitl_override_ok = self.policy.hitl.enabled and self.policy.hitl.allow_operator_override
        if sudo and not self.policy.allow_sudo and not hitl_override_ok:
            raise PermissionError(
                "Privileged execution (sudo=True) is disabled by MCP security policy "
                "(start server with --allow-sudo to enable)."
            )

        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
            raise PermissionError(
                f"Command {command!r} on host {entry.name!r} is forbidden by security policy: "
                f"{'; '.join(assessment.reasons)}"
            )

        timeout = float(arguments.get("timeout", 30.0))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        diagnose = bool(arguments.get("diagnose", True))
        raw_parse = arguments.get("parse", True)
        parse_spec: ParseSpec
        if raw_parse is True:
            parse_spec = "auto"
        elif raw_parse is False or raw_parse is None:
            parse_spec = None
        else:
            parse_spec = str(raw_parse)

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        needs_approval = self.policy.hitl.enabled and (
            assessment.requires_approval or (sudo and not self.policy.allow_sudo)
        )
        hmac_params = {"command": command, "sudo": sudo, "cwd": cwd_str or ""}

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            command=command,
            sudo=sudo,
            cwd=cwd_str,
            parameters=hmac_params,
        )
        if pending_payload is not None:
            return pending_payload

        run_kwargs: dict[str, Any] = {}
        if cwd_str:
            run_kwargs["cwd"] = cwd_str

        async with self.registry.create_connection(entry) as conn:
            res = await conn.run(
                command,
                timeout=timeout,
                sudo=sudo,
                parse=parse_spec,
                diagnose=diagnose,
                raise_on_error=False,
                **run_kwargs,
            )
            parsed_data: Any = None
            if parse_spec is not None:
                try:
                    parsed_data = _sanitize_json_value(res.parsed)
                except Exception:
                    parsed_data = None

            payload: dict[str, Any] = {
                "host": res.host or entry.name,
                "command": SecretMaskingFilter._mask_string(res.command),
                "ok": res.ok,
                "exit_code": res.exit_code,
                "duration_ms": round(res.duration * 1000, 3),
                "stdout": SecretMaskingFilter._mask_string(res.stdout),
                "stderr": SecretMaskingFilter._mask_string(res.stderr),
                "parsed": parsed_data,
                "risk_tier": assessment.risk_tier.value,
                "dry_run": self.policy.dry_run,
            }
            if res.diagnostic is not None:
                payload["diagnostic"] = _sanitize_json_value(res.diagnostic.to_dict())
            if consumed_req is not None:
                payload["approval"] = {
                    "approval_id": consumed_req.approval_id,
                    "status": consumed_req.status.value,
                    "approved_by": consumed_req.decided_by,
                    "approved_at": consumed_req.decided_at.isoformat() if consumed_req.decided_at else None,
                    "decision_reason": consumed_req.decision_reason,
                }
            return payload

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

    async def _inspect_remote_file_for_diff(
        self,
        entry: MCPHostEntry,
        path: str,
        new_content: str,
    ) -> tuple[bool, str]:
        """Проверить существование целевого файла и вычислить unified diff."""
        old_text: str | None = None
        exists = False
        with contextlib.suppress(Exception):
            async with self.registry.create_connection(entry) as conn:
                exists = await conn.files.exists(path)
                if exists:
                    raw = await conn.files.read_file(path, encoding=None)
                    raw_bytes = raw if isinstance(raw, bytes) else str(raw).encode("utf-8")
                    old_text = raw_bytes[: self.policy.max_read_bytes].decode("utf-8", errors="replace")
        return exists, build_unified_diff(path, old_text, new_content)

    async def _tool_write_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        hitl_override_ok = self.policy.hitl.enabled and self.policy.hitl.allow_operator_override
        if not self.policy.allow_write and not hitl_override_ok:
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
        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)

        file_exists = False
        diff_str: str | None = None
        if self.policy.hitl.enabled:
            file_exists, diff_str = await self._inspect_remote_file_for_diff(entry, path, content)

        assessment = ActionRiskClassifier.classify_file_write(
            path,
            file_exists=file_exists,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
            raise PermissionError(
                f"Writing to {path!r} on host {entry.name!r} is forbidden by security policy: "
                f"{'; '.join(assessment.reasons)}"
            )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        needs_approval = self.policy.hitl.enabled and (
            assessment.requires_approval or not self.policy.allow_write
        )
        hmac_params = {"path": path, "content": content, "atomic": atomic}

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            entry=entry,
            tool_name="uniconn_write_file",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            parameters=hmac_params,
            diff=diff_str,
        )
        if pending_payload is not None:
            return pending_payload

        async with self.registry.create_connection(entry) as conn:
            await conn.files.write_file(path, content, atomic=atomic)
            result_payload: dict[str, Any] = {
                "target": entry.name,
                "path": path,
                "bytes_written": len(content.encode("utf-8")),
                "atomic": atomic,
                "risk_tier": assessment.risk_tier.value,
                "dry_run": self.policy.dry_run,
            }
            if consumed_req is not None:
                result_payload["approval"] = {
                    "approval_id": consumed_req.approval_id,
                    "status": consumed_req.status.value,
                    "approved_by": consumed_req.decided_by,
                    "approved_at": consumed_req.decided_at.isoformat() if consumed_req.decided_at else None,
                    "decision_reason": consumed_req.decision_reason,
                }
            return result_payload

    async def _tool_propose_action(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(arguments.get("tool_name") or "uniconn_run").strip()
        agent_id = arguments.get("agent_id")

        if tool_name == "uniconn_run_flow" or tool_name.startswith("flow_"):
            flow_key = str(arguments.get("flow_name") or tool_name).strip()
            flow_obj = self.flow_registry.get_flow(flow_key)
            canonical_tool = self.flow_registry.get_tool_name(flow_obj.name)
            eff_tool = tool_name if tool_name == "uniconn_run_flow" else canonical_tool
            raw_targets = arguments.get("targets") or arguments.get("target")
            if isinstance(raw_targets, str) and "," in raw_targets:
                raw_targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
            raw_group = arguments.get("group")
            group_str = str(raw_group).strip() if raw_group else None
            entries = self.registry.resolve_targets(raw_targets, group=group_str)
            raw_tags = arguments.get("tags")
            tags_list: list[str] | None = None
            if isinstance(raw_tags, str) and raw_tags.strip():
                tags_list = [t.strip() for t in raw_tags.split(",") if t.strip()]
            elif isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str):
                tags_list = [str(t).strip() for t in raw_tags if str(t).strip()]
            validated_vars = FlowSchemaGenerator.extract_and_validate_vars(
                flow_obj,
                arguments,
                tags=tags_list,
            )
            eff_mode = str(arguments.get("mode") or flow_obj.mode)
            assessment, plan_preview = FlowRiskEvaluator.evaluate(
                flow_obj,
                entries=entries,
                vars=validated_vars,
                tags=tags_list,
                mode=eff_mode,
                dry_run=False,
                policy=self.policy.hitl,
            )
            if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
                raise PermissionError(
                    f"Proposed flow {flow_obj.name!r} is forbidden: {'; '.join(assessment.reasons)}"
                )
            host_label = ",".join(e.name for e in entries)
            hmac_params = {
                "flow_name": flow_obj.name,
                "targets": [e.name for e in entries],
                "group": group_str or "",
                "vars": validated_vars,
                "tags": list(tags_list or ()),
                "mode": eff_mode,
            }
            req = await self.approval_manager.create_request(
                target_host=host_label,
                tool_name=eff_tool,
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                command=f"flow:{flow_obj.name}",
                parameters=hmac_params,
                diff=plan_preview,
                agent_id=str(agent_id) if agent_id else None,
            )
            return {
                "assessment": assessment.to_dict(),
                "plan_preview": plan_preview,
                "approval": req.to_public_dict(),
            }

        target = arguments.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)

        if tool_name == "uniconn_write_file":
            path = str(arguments.get("path") or "").strip()
            content = arguments.get("content")
            if not path or not isinstance(content, str):
                raise ValueError("Parameters 'path' and 'content' are required when proposing 'uniconn_write_file'")
            atomic = bool(arguments.get("atomic", True))
            file_exists, diff_str = await self._inspect_remote_file_for_diff(entry, path, content)
            assessment = ActionRiskClassifier.classify_file_write(
                path,
                file_exists=file_exists,
                is_production=is_prod,
                policy=self.policy.hitl,
            )
            if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
                raise PermissionError(
                    f"Proposed file write to {path!r} is forbidden: {'; '.join(assessment.reasons)}"
                )
            req = await self.approval_manager.create_request(
                target_host=entry.name,
                tool_name="uniconn_write_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                parameters={"path": path, "content": content, "atomic": atomic},
                diff=diff_str,
                agent_id=str(agent_id) if agent_id else None,
            )
            return {
                "assessment": assessment.to_dict(),
                "approval": req.to_public_dict(),
            }

        command = str(arguments.get("command") or "").strip()
        if not command:
            raise ValueError("Parameter 'command' is required when proposing 'uniconn_run'")
        sudo = bool(arguments.get("sudo", False))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
            raise PermissionError(
                f"Proposed command {command!r} is forbidden: {'; '.join(assessment.reasons)}"
            )
        req = await self.approval_manager.create_request(
            target_host=entry.name,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            sudo=sudo,
            cwd=cwd_str,
            parameters={"command": command, "sudo": sudo, "cwd": cwd_str or ""},
            agent_id=str(agent_id) if agent_id else None,
        )
        return {
            "assessment": assessment.to_dict(),
            "approval": req.to_public_dict(),
        }

    async def _tool_check_approval(self, arguments: dict[str, Any]) -> dict[str, Any]:
        approval_id = arguments.get("approval_id")
        if isinstance(approval_id, str) and approval_id.strip():
            req = await self.approval_manager.get_request(approval_id.strip())
            return {"approval": req.to_public_dict()}

        status_filter = arguments.get("status")
        reqs = await self.approval_manager.list_requests(
            status=str(status_filter) if status_filter else None
        )
        return {
            "approvals": [r.to_public_dict() for r in reqs],
            "count": len(reqs),
        }

    async def _tool_wait_approval(self, arguments: dict[str, Any]) -> dict[str, Any]:
        approval_id = arguments.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("Parameter 'approval_id' is required")
        timeout = float(arguments.get("timeout", self.policy.hitl.wait_timeout_seconds))
        req = await self.approval_manager.wait_for_decision(approval_id.strip(), timeout=timeout)
        return {
            "approval_id": req.approval_id,
            "status": req.status.value,
            "approved": req.status == ApprovalStatus.APPROVED,
            "approval": req.to_public_dict(),
        }

    async def _tool_list_flows(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_cp = bool(arguments.get("include_checkpoints", True))
        flows_list = self.flow_registry.to_summary_list(policy=self.policy.hitl)
        out: dict[str, Any] = {
            "flows": flows_list,
            "count": len(flows_list),
        }
        if include_cp:
            records = self.checkpoint_store.list_records(only_resumable=True)
            out["resumable_checkpoints"] = [r.to_dict() for r in records]
        return out

    async def _tool_inspect_flow(self, arguments: dict[str, Any]) -> dict[str, Any]:
        flow_name = arguments.get("flow_name")
        if not isinstance(flow_name, str) or not flow_name.strip():
            raise ValueError("Parameter 'flow_name' is required")
        flow_obj = self.flow_registry.get_flow(flow_name.strip())
        raw_targets = arguments.get("targets")
        group = arguments.get("group")
        entries: list[MCPHostEntry] = []
        if raw_targets or group:
            entries = self.registry.resolve_targets(
                raw_targets,
                group=str(group) if group else None,
            )
        else:
            with contextlib.suppress(Exception):
                entries = self.registry.list_entries()

        raw_tags = arguments.get("tags")
        tags_list = (
            [str(t) for t in raw_tags]
            if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str)
            else None
        )
        raw_vars = arguments.get("vars")
        vars_dict = dict(raw_vars) if isinstance(raw_vars, dict) else {}
        assessment, plan_preview = FlowRiskEvaluator.evaluate(
            flow_obj,
            entries=entries,
            vars=vars_dict,
            tags=tags_list,
            policy=self.policy.hitl,
        )
        tool_def = FlowSchemaGenerator.generate_tool_definition(
            flow_obj,
            tool_name=self.flow_registry.get_tool_name(flow_obj.name),
        )
        return {
            "flow_name": flow_obj.name,
            "tool_name": tool_def.name,
            "description": tool_def.description,
            "mode": flow_obj.mode,
            "fail_fast": flow_obj.fail_fast,
            "risk_assessment": assessment.to_dict(),
            "plan_preview": plan_preview,
            "input_schema": tool_def.input_schema,
            "waves": [[t.name for t in layer] for layer in flow_obj.get_layers()],
        }

    async def _tool_run_flow(self, arguments: dict[str, Any]) -> dict[str, Any]:
        flow_name = arguments.get("flow_name")
        if not isinstance(flow_name, str) or not flow_name.strip():
            raise ValueError("Parameter 'flow_name' is required")
        flow_obj = self.flow_registry.get_flow(flow_name.strip())
        return await self._execute_flow_by_object(
            flow_obj,
            tool_name="uniconn_run_flow",
            arguments=arguments,
        )

    async def _tool_resume_flow(self, arguments: dict[str, Any]) -> dict[str, Any]:
        run_id = arguments.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("Parameter 'run_id' is required")
        cp_record = self.checkpoint_store.get(run_id.strip())
        flow_obj = self.flow_registry.get_flow(cp_record.flow_name)
        merged_args: dict[str, Any] = {
            "resume_run_id": cp_record.run_id,
            "targets": cp_record.targets,
            "group": cp_record.group,
            "tags": cp_record.tags,
            "mode": cp_record.mode,
            "vars": dict(cp_record.vars),
        }
        override_vars = arguments.get("vars")
        if isinstance(override_vars, dict):
            merged_args["vars"].update(override_vars)
        if "approval_id" in arguments:
            merged_args["approval_id"] = arguments["approval_id"]
        if "wait_for_approval" in arguments:
            merged_args["wait_for_approval"] = arguments["wait_for_approval"]
        return await self._execute_flow_by_object(
            flow_obj,
            tool_name=self.flow_registry.get_tool_name(flow_obj.name),
            arguments=merged_args,
        )

    async def _execute_flow_by_object(
        self,
        flow_obj: Flow,
        *,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Единый конвейер запуска ``Flow`` с поддержкой HITL 4.2, диагностики 4.1 и чекпоинтов."""
        resume_id_raw = arguments.get("resume_run_id") or arguments.get("run_id")
        resume_run_id = (
            str(resume_id_raw).strip()
            if isinstance(resume_id_raw, str) and str(resume_id_raw).strip()
            else None
        )
        prior_completed: dict[str, list[str]] = {}
        prior_outputs: dict[str, dict[str, Any]] = {}
        base_vars: dict[str, Any] = {}
        default_targets: Any = None
        default_group: str | None = None
        default_tags: list[str] | None = None
        default_mode: str | None = None

        if resume_run_id is not None:
            cp = self.checkpoint_store.get(resume_run_id)
            if cp.flow_name != flow_obj.name:
                raise ValueError(
                    f"Checkpoint {resume_run_id!r} belongs to flow {cp.flow_name!r}, "
                    f"cannot resume flow {flow_obj.name!r}"
                )
            prior_completed = {h: list(t_list) for h, t_list in cp.completed_by_host.items()}
            prior_outputs = {
                h: dict(out_dict) for h, out_dict in cp.task_outputs_by_host.items()
            }
            base_vars = dict(cp.vars)
            default_targets = cp.targets
            default_group = cp.group
            default_tags = cp.tags or None
            default_mode = cp.mode

        raw_targets = arguments.get("targets") or arguments.get("target") or default_targets
        if isinstance(raw_targets, str) and "," in raw_targets:
            raw_targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
        raw_group = arguments.get("group") if "group" in arguments else default_group
        group_str = str(raw_group).strip() if raw_group else None
        entries = self.registry.resolve_targets(raw_targets, group=group_str)

        raw_tags = arguments.get("tags") if "tags" in arguments else default_tags
        tags_list: list[str] | None = None
        if isinstance(raw_tags, str) and raw_tags.strip():
            tags_list = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str):
            tags_list = [str(t).strip() for t in raw_tags if str(t).strip()]

        validated_vars = FlowSchemaGenerator.extract_and_validate_vars(
            flow_obj,
            arguments,
            base_vars=base_vars,
            tags=tags_list,
        )

        raw_mode = arguments.get("mode") or default_mode or flow_obj.mode
        eff_mode: Literal["barrier", "independent"] = (
            "independent" if str(raw_mode) == "independent" else "barrier"
        )
        req_dry_run = bool(arguments.get("dry_run", False))
        eff_dry_run = self.policy.dry_run or req_dry_run

        assessment, plan_preview = FlowRiskEvaluator.evaluate(
            flow_obj,
            entries=entries,
            vars=validated_vars,
            tags=tags_list,
            mode=eff_mode,
            dry_run=eff_dry_run,
            policy=self.policy.hitl,
        )
        if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
            raise PermissionError(
                f"Flow {flow_obj.name!r} is forbidden by security policy: "
                f"{'; '.join(assessment.reasons)}"
            )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(
            arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval)
        )
        needs_approval = self.policy.hitl.enabled and assessment.requires_approval
        target_names = [e.name for e in entries]
        host_label = ",".join(target_names)
        hmac_params = {
            "flow_name": flow_obj.name,
            "targets": target_names,
            "group": group_str or "",
            "vars": validated_vars,
            "tags": list(tags_list or ()),
            "mode": eff_mode,
        }
        canonical_flow_tool = self.flow_registry.get_tool_name(flow_obj.name)
        allowed_tools = (tool_name, canonical_flow_tool, "uniconn_run_flow")

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            target_host=host_label,
            tool_name=tool_name,
            allowed_tool_names=allowed_tools,
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            command=f"flow:{flow_obj.name}",
            parameters=hmac_params,
            diff=plan_preview,
            pending_extra={
                "flow_name": flow_obj.name,
                "targets": target_names,
                "plan_preview": plan_preview,
            },
        )
        if pending_payload is not None:
            return pending_payload

        active_flow = coerce_to_flow(flow_obj, mode=eff_mode)
        run_id = resume_run_id or f"run_{uuid.uuid4().hex[:12]}"

        if len(entries) == 1:
            async with self.registry.create_connection(
                entries[0],
                dry_run=eff_dry_run,
                auto_diagnostics=True,
            ) as conn:
                report = await active_flow.run(
                    conn,
                    vars=validated_vars,
                    tags=tags_list,
                    dry_run=eff_dry_run,
                    completed_tasks_by_host=prior_completed,
                    checkpoint_outputs_by_host=prior_outputs,
                    run_id=run_id,
                    resumed_from=resume_run_id,
                )
        else:
            pool = self.registry.create_pool(
                entries,
                dry_run=eff_dry_run,
                auto_diagnostics=True,
            )
            async with pool:
                report = await active_flow.run(
                    pool,
                    vars=validated_vars,
                    tags=tags_list,
                    dry_run=eff_dry_run,
                    completed_tasks_by_host=prior_completed,
                    checkpoint_outputs_by_host=prior_outputs,
                    run_id=run_id,
                    resumed_from=resume_run_id,
                )

        cp_record = self.checkpoint_store.record_from_report(
            report,
            targets=target_names,
            group=group_str,
            vars=validated_vars,
            tags=tags_list,
            mode=eff_mode,
            prior_completed=prior_completed,
            prior_outputs=prior_outputs,
            run_id=run_id,
        )

        report_dict = report.to_dict()
        payload: dict[str, Any] = {
            "status": "COMPLETED" if report.ok else "FAILED",
            "ok": report.ok,
            "flow_name": flow_obj.name,
            "tool_name": canonical_flow_tool,
            "mode": report.mode,
            "run_id": cp_record.run_id,
            "can_resume": not report.ok,
            "resumed_from": resume_run_id,
            "duration_ms": round(report.duration * 1000, 3),
            "dry_run": eff_dry_run,
            "risk_tier": assessment.risk_tier.value,
            "targets": target_names,
            "summary": {
                "total_tasks": report.total_tasks,
                "succeeded_count": report.succeeded_count,
                "failed_count": report.failed_count,
                "skipped_count": report.skipped_count,
                "changed_count": report.changed_count,
                "failed_hosts": report.failed_hosts,
            },
            "failed_tasks": cp_record.failed_tasks,
            "completed_by_host": cp_record.completed_by_host,
            "results": report_dict["results"],
        }
        if consumed_req is not None:
            payload["approval"] = {
                "approval_id": consumed_req.approval_id,
                "status": consumed_req.status.value,
                "approved_by": consumed_req.decided_by,
                "approved_at": (
                    consumed_req.decided_at.isoformat()
                    if consumed_req.decided_at
                    else None
                ),
                "decision_reason": consumed_req.decision_reason,
            }
        return payload

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

        if uri == "uniconn://approvals/pending":
            pending = await self.approval_manager.list_requests(status=ApprovalStatus.PENDING)
            data = {
                "pending_approvals": [r.to_public_dict() for r in pending],
                "count": len(pending),
            }
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(data, ensure_ascii=False, indent=2),
                    }
                ]
            }

        if uri == "uniconn://flows":
            data = await self._tool_list_flows({"include_checkpoints": True})
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

