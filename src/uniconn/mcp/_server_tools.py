# src/uniconn/mcp/_server_tools.py
"""Реализация MCP-инструментов (tools) и чтения ресурсов (resources) для MCPServer."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shlex
import uuid
from typing import TYPE_CHECKING, Any, Literal

from .._logging import SecretMaskingFilter
from ..exceptions import (
    CapabilityNotSupportedError,
    ConnectionError,
    ExecutionError,
    FileTransferError,
    TimeoutError,
)
from ..orchestration.flow import Flow
from ..orchestration.scheduler import coerce_to_flow
from ..parsing import ParseSpec
from ..security.ast_parser import CommandASTParser
from ..security.models import PolicyDecision
from ..services.facts_models import HostFacts, diff_facts
from ._server_gates import MCPServerGatesMixin, _parse_tags_list, _sanitize_json_value
from .flows import (
    FlowCheckpointStore,
    FlowRiskEvaluator,
    FlowSchemaGenerator,
    MCPFlowRegistry,
)
from .hitl import ActionRiskClassifier, ApprovalManager, build_unified_diff
from .models import ApprovalStatus, MCPHostEntry, MCPSecurityPolicy

if TYPE_CHECKING:
    from .registry import MCPHostRegistry

_logger = logging.getLogger("uniconn.mcp.server")


class MCPServerToolsMixin(MCPServerGatesMixin):
    """Миксин обработчиков MCP tools и resources для ``MCPServer``."""

    if TYPE_CHECKING:
        registry: MCPHostRegistry
        approval_manager: ApprovalManager
        flow_registry: MCPFlowRegistry
        checkpoint_store: FlowCheckpointStore

        @property
        def policy(self) -> MCPSecurityPolicy: ...

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
        parsed_ast = CommandASTParser.parse(
            command,
            max_depth=self.policy.guardrails.max_ast_depth,
            max_pipeline_length=self.policy.guardrails.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
            ast=parsed_ast,
        )
        timeout = float(arguments.get("timeout", 30.0))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")

        self._assert_not_forbidden(assessment, f"Command {command!r} on host {entry.name!r}")

        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd_str,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

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
        policy_requires_appr = policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled
            and (assessment.requires_approval or (sudo and not self.policy.allow_sudo))
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        hmac_params = {"command": command, "sudo": sudo, "cwd": cwd_str or ""}

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            command=command,
            sudo=sudo,
            cwd=cwd_str,
            parameters=hmac_params,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
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
                except (ValueError, KeyError, TypeError, RuntimeError) as parse_exc:
                    _logger.debug("Ignoring output parse failure in uniconn_run: %s", parse_exc)
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
                "policy_decision": policy_eval.decision.value,
                "dry_run": self.policy.dry_run,
            }
            if res.diagnostic is not None:
                payload["diagnostic"] = _sanitize_json_value(res.diagnostic.to_dict())
            if consumed_req is not None:
                payload["approval"] = self._serialize_approval(consumed_req)
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

        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)
        assessment = ActionRiskClassifier.classify_file_read(
            path,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Reading {path!r} on host {entry.name!r}")

        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_read_file",
            action_type="file_read",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        policy_requires_appr = policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled and assessment.requires_approval
        )
        if needs_approval:
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            _, pending_payload = await self._resolve_hitl_gate(
                entry=entry,
                tool_name="uniconn_read_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                requires_approval=True,
                approval_id=str(approval_id) if approval_id is not None else None,
                wait_for_approval=wait_for_appr,
                parameters={"path": path},
                agent_id=str(raw_agent_id) if raw_agent_id else None,
            )
            if pending_payload is not None:
                return pending_payload

        raw_max = arguments.get("max_bytes")
        req_max = self.policy.max_read_bytes if raw_max is None else int(raw_max)
        limit = max(1, min(req_max, self.policy.max_read_bytes))

        async with self.registry.create_connection(entry) as conn:
            st: Any = None
            with contextlib.suppress(Exception):
                st = await conn.files.stat(path)

            file_size: int | None = None
            if st is not None:
                if st.get("is_dir"):
                    raise IsADirectoryError(f"Path {path!r} is a directory, not a regular file")
                if not st.get("is_file", True) and not st.get("is_symlink", False):
                    raise PermissionError(f"Reading non-regular file or device {path!r} is forbidden")
                raw_sz = st.get("size")
                if isinstance(raw_sz, int) and raw_sz >= 0:
                    file_size = raw_sz

            max_preload_bytes = max(limit * 4, self.policy.max_read_bytes)
            if file_size is not None and file_size > max_preload_bytes:
                if entry.transport != "winrm":
                    head_res = await conn.run(
                        f"head -c {limit + 1} -- {shlex.quote(path)}",
                        raise_on_error=False,
                    )
                    if head_res.ok:
                        encoded = head_res.stdout.encode("utf-8", errors="replace")
                        truncated = len(encoded) > limit or file_size > limit
                        sliced = encoded[:limit]
                        text = sliced.decode("utf-8", errors="replace")
                        return {
                            "target": entry.name,
                            "path": path,
                            "content": SecretMaskingFilter._mask_string(text),
                            "total_bytes": file_size,
                            "truncated": truncated,
                        }
                raise PermissionError(
                    f"File {path!r} ({file_size} bytes) exceeds safe read limit ({max_preload_bytes} bytes)"
                )

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
                "target": entry.name,
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

        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)
        assessment = ActionRiskClassifier.classify_file_read(
            path,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Inspecting {path!r} on host {entry.name!r}")

        raw_agent_id = arguments.get("agent_id")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_stat_path",
            action_type="file_read",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            enforce_deny=True,
        )
        if policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval_id = arguments.get("approval_id")
            wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            _, pending_payload = await self._resolve_hitl_gate(
                entry=entry,
                tool_name="uniconn_stat_path",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                requires_approval=True,
                approval_id=str(approval_id) if approval_id is not None else None,
                wait_for_approval=wait_for_appr,
                parameters={"path": path},
                agent_id=str(raw_agent_id) if raw_agent_id else None,
            )
            if pending_payload is not None:
                return pending_payload

        async with self.registry.create_connection(entry) as conn:
            exists = await conn.files.exists(path)
            if not exists:
                return {"target": entry.name, "path": path, "exists": False, "stat": None}
            st = await conn.files.stat(path)
            return {
                "target": entry.name,
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
        is_prod = any(e.is_production(self.policy.hitl.prod_groups) for e in entries)
        assessment = ActionRiskClassifier.classify_file_read(
            path,
            is_production=is_prod,
            policy=self.policy.hitl,
        )
        self._assert_not_forbidden(assessment, f"Hashing {path!r}")

        raw_agent_id = arguments.get("agent_id")
        _, policy_eval = await self._evaluate_policy_gate(
            entries=entries,
            tool_name="uniconn_checksum",
            action_type="file_read",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            enforce_deny=True,
        )
        if policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval_id = arguments.get("approval_id")
            wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            target_label = entries[0].name if len(entries) == 1 else ",".join(e.name for e in entries)
            _, pending_payload = await self._resolve_hitl_gate(
                entry=entries[0],
                target_host=target_label,
                tool_name="uniconn_checksum",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                requires_approval=True,
                approval_id=str(approval_id) if approval_id is not None else None,
                wait_for_approval=wait_for_appr,
                parameters={"path": path, "algorithm": algo},
                agent_id=str(raw_agent_id) if raw_agent_id else None,
            )
            if pending_payload is not None:
                return pending_payload

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
        try:
            async with self.registry.create_connection(entry) as conn:
                exists = await conn.files.exists(path)
                if exists:
                    raw = await conn.files.read_file(path, encoding=None)
                    raw_bytes = raw if isinstance(raw, bytes) else str(raw).encode("utf-8")
                    old_text = raw_bytes[: self.policy.max_read_bytes].decode("utf-8", errors="replace")
        except (
            OSError,
            ExecutionError,
            FileTransferError,
            CapabilityNotSupportedError,
            TimeoutError,
            ConnectionError,
            RuntimeError,
            ValueError,
        ) as exc:
            _logger.debug(
                "Remote diff inspection fallback to empty baseline for %s:%s (%s)",
                entry.name,
                path,
                exc,
            )
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
        self._assert_not_forbidden(assessment, f"Writing to {path!r} on host {entry.name!r}")
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_write_file",
            action_type="file_write",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            path=path,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        policy_requires_appr = policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        if policy_requires_appr and diff_str is None:
            _, diff_str = await self._inspect_remote_file_for_diff(entry, path, content)
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled
            and (assessment.requires_approval or not self.policy.allow_write)
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        hmac_params = {"path": path, "content": content, "atomic": atomic}

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            entry=entry,
            tool_name="uniconn_write_file",
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            parameters=hmac_params,
            diff=diff_str,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
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
                "policy_decision": policy_eval.decision.value,
                "dry_run": self.policy.dry_run,
            }
            if consumed_req is not None:
                result_payload["approval"] = self._serialize_approval(consumed_req)
            return result_payload

    async def _propose_flow_action(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        flow_key = str(arguments.get("flow_name") or tool_name).strip()
        flow_obj = self.flow_registry.get_flow(flow_key)
        canonical_tool = self.flow_registry.get_tool_name(flow_obj.name)
        eff_tool = tool_name if tool_name == "uniconn_run_flow" else canonical_tool

        entries, group_str, tags_list = self._resolve_flow_targets_and_tags(arguments)
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
        self._assert_not_forbidden(assessment, f"Proposed flow {flow_obj.name!r}")
        _, policy_eval = await self._evaluate_policy_gate(
            entries=entries,
            tool_name=eff_tool,
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=f"flow:{flow_obj.name}",
            flow_name=flow_obj.name,
            flow_tasks=tuple(flow_obj.tasks.keys()),
            agent_id=str(agent_id) if agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
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
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        req = await self.approval_manager.create_request(
            target_host=host_label,
            tool_name=eff_tool,
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            command=f"flow:{flow_obj.name}",
            parameters=hmac_params,
            diff=plan_preview,
            agent_id=str(agent_id) if agent_id else None,
        )
        return {
            "assessment": assessment.to_dict(),
            "policy": policy_eval.to_dict(),
            "plan_preview": plan_preview,
            "approval": req.to_public_dict(),
        }

    async def _tool_propose_action(self, arguments: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(arguments.get("tool_name") or "uniconn_run").strip()
        if tool_name == "uniconn_run_flow" or tool_name.startswith("flow_"):
            return await self._propose_flow_action(tool_name, arguments)

        agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        target = arguments.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)

        if tool_name == "uniconn_read_file":
            path = str(arguments.get("path") or "").strip()
            if not path:
                raise ValueError("Parameter 'path' is required when proposing 'uniconn_read_file'")
            assessment = ActionRiskClassifier.classify_file_read(
                path,
                is_production=is_prod,
                policy=self.policy.hitl,
            )
            self._assert_not_forbidden(assessment, f"Proposed file read of {path!r}")
            _, policy_eval = await self._evaluate_policy_gate(
                entry=entry,
                tool_name="uniconn_read_file",
                action_type="file_read",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                path=path,
                agent_id=str(agent_id) if agent_id else None,
                role=str(raw_role) if raw_role else None,
                enforce_deny=True,
            )
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            req = await self.approval_manager.create_request(
                target_host=entry.name,
                tool_name="uniconn_read_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                parameters={"path": path},
                agent_id=str(agent_id) if agent_id else None,
            )
            return {
                "assessment": assessment.to_dict(),
                "policy": policy_eval.to_dict(),
                "approval": req.to_public_dict(),
            }

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
            self._assert_not_forbidden(assessment, f"Proposed file write to {path!r}")
            _, policy_eval = await self._evaluate_policy_gate(
                entry=entry,
                tool_name="uniconn_write_file",
                action_type="file_write",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                path=path,
                agent_id=str(agent_id) if agent_id else None,
                role=str(raw_role) if raw_role else None,
                enforce_deny=True,
            )
            merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
            req = await self.approval_manager.create_request(
                target_host=entry.name,
                tool_name="uniconn_write_file",
                risk_tier=assessment.risk_tier,
                risk_reasons=tuple(merged_reasons),
                parameters={"path": path, "content": content, "atomic": atomic},
                diff=diff_str,
                agent_id=str(agent_id) if agent_id else None,
            )
            return {
                "assessment": assessment.to_dict(),
                "policy": policy_eval.to_dict(),
                "approval": req.to_public_dict(),
            }

        command = str(arguments.get("command") or "").strip()
        if not command:
            raise ValueError("Parameter 'command' is required when proposing 'uniconn_run'")
        sudo = bool(arguments.get("sudo", False))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        parsed_ast = CommandASTParser.parse(
            command,
            max_depth=self.policy.guardrails.max_ast_depth,
            max_pipeline_length=self.policy.guardrails.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
            ast=parsed_ast,
        )
        self._assert_not_forbidden(assessment, f"Proposed command {command!r}")
        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd_str,
            agent_id=str(agent_id) if agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        req = await self.approval_manager.create_request(
            target_host=entry.name,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            command=command,
            sudo=sudo,
            cwd=cwd_str,
            parameters={"command": command, "sudo": sudo, "cwd": cwd_str or ""},
            agent_id=str(agent_id) if agent_id else None,
        )
        return {
            "assessment": assessment.to_dict(),
            "policy": policy_eval.to_dict(),
            "ast": parsed_ast.to_dict(),
            "approval": req.to_public_dict(),
        }

    async def _tool_evaluate_policy(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Сухая оценка AST-дерева и Policy-as-Code без исполнения действия."""
        tool_name = str(arguments.get("tool_name") or "uniconn_run").strip()
        raw_target = arguments.get("target")
        target_str = raw_target.strip() if isinstance(raw_target, str) and raw_target.strip() else None
        entry: MCPHostEntry | None = None
        if target_str:
            with contextlib.suppress(KeyError):
                entry = self.registry.get_entry(target_str)
        is_prod = (
            entry.is_production(self.policy.hitl.prod_groups)
            if entry is not None
            else bool(target_str and any(tok in target_str.lower() for tok in ("prod", "prd")))
        )
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        agent_val = str(raw_agent_id) if raw_agent_id else None
        role_val = str(raw_role) if raw_role else None

        if tool_name in ("uniconn_read_file", "uniconn_write_file"):
            path = str(arguments.get("path") or "").strip()
            if not path:
                raise ValueError(f"Parameter 'path' is required when evaluating {tool_name!r}")
            is_read = tool_name == "uniconn_read_file"
            assessment = (
                ActionRiskClassifier.classify_file_read(path, is_production=is_prod, policy=self.policy.hitl)
                if is_read
                else ActionRiskClassifier.classify_file_write(
                    path, file_exists=True, is_production=is_prod, policy=self.policy.hitl
                )
            )
            auth_ctx, policy_eval = await self._evaluate_policy_gate(
                entry=entry,
                target_host=target_str,
                tool_name=tool_name,
                action_type="file_read" if is_read else "file_write",
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                path=path,
                agent_id=agent_val,
                role=role_val,
                allow_role_override=True,
                enforce_deny=False,
            )
            return self._build_policy_eval_response(assessment, policy_eval, auth_ctx)

        if tool_name == "uniconn_run_flow" or tool_name.startswith("flow_"):
            flow_key = str(arguments.get("flow_name") or tool_name).strip()
            flow_obj = self.flow_registry.get_flow(flow_key)
            entries = [entry] if entry is not None else self.registry.list_entries()
            assessment, plan_preview = FlowRiskEvaluator.evaluate(
                flow_obj,
                entries=entries,
                policy=self.policy.hitl,
            )
            auth_ctx, policy_eval = await self._evaluate_policy_gate(
                entries=entries,
                target_host=target_str,
                tool_name=tool_name,
                risk_tier=assessment.risk_tier,
                risk_reasons=assessment.reasons,
                command=f"flow:{flow_obj.name}",
                flow_name=flow_obj.name,
                flow_tasks=tuple(flow_obj.tasks.keys()),
                agent_id=agent_val,
                role=role_val,
                allow_role_override=True,
                enforce_deny=False,
            )
            return self._build_policy_eval_response(
                assessment, policy_eval, auth_ctx, plan_preview=plan_preview
            )

        command = str(arguments.get("command") or "").strip()
        if not command:
            raise ValueError("Parameter 'command' is required when evaluating 'uniconn_run'")
        sudo = bool(arguments.get("sudo", False))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        parsed_ast = CommandASTParser.parse(
            command,
            max_depth=self.policy.guardrails.max_ast_depth,
            max_pipeline_length=self.policy.guardrails.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
            ast=parsed_ast,
        )
        auth_ctx, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            target_host=target_str,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd_str,
            agent_id=agent_val,
            role=role_val,
            allow_role_override=True,
            enforce_deny=False,
        )
        return self._build_policy_eval_response(
            assessment, policy_eval, auth_ctx, ast=parsed_ast.to_dict()
        )

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
        if raw_targets or group:
            entries = self.registry.resolve_targets(
                raw_targets,
                group=str(group) if group else None,
            )
        else:
            entries = self.registry.list_entries()

        tags_list = _parse_tags_list(arguments.get("tags"))
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
        for passthrough in ("approval_id", "wait_for_approval", "agent_id", "role"):
            if passthrough in arguments:
                merged_args[passthrough] = arguments[passthrough]
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

        entries, group_str, tags_list = self._resolve_flow_targets_and_tags(
            arguments,
            default_targets=default_targets,
            default_group=default_group,
            default_tags=default_tags,
        )
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
        self._assert_not_forbidden(assessment, f"Flow {flow_obj.name!r}")
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")
        _, policy_eval = await self._evaluate_policy_gate(
            entries=entries,
            tool_name=tool_name,
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=f"flow:{flow_obj.name}",
            flow_name=flow_obj.name,
            flow_tasks=tuple(flow_obj.tasks.keys()),
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(
            arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval)
        )
        policy_requires_appr = (
            not eff_dry_run and policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        )
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled and assessment.requires_approval
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
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
            risk_reasons=tuple(merged_reasons),
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            command=f"flow:{flow_obj.name}",
            parameters=hmac_params,
            diff=plan_preview,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
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
            payload["approval"] = self._serialize_approval(consumed_req)
        return payload

    async def _read_resource(self, uri: str) -> dict[str, Any]:
        """Прочитать MCP-ресурс по URI."""
        data: dict[str, Any] | None = None
        if uri == "uniconn://inventory/hosts":
            data = await self._tool_list_hosts({})
        elif uri == "uniconn://approvals/pending":
            pending = await self.approval_manager.list_requests(status=ApprovalStatus.PENDING)
            data = {
                "pending_approvals": [r.to_public_dict() for r in pending],
                "count": len(pending),
            }
        elif uri == "uniconn://flows":
            data = await self._tool_list_flows({"include_checkpoints": True})
        elif uri == "uniconn://security/guardrails":
            data = {
                "guardrails": self.policy.guardrails.to_summary_dict(),
                "security_policy": self.policy.to_summary_dict(),
            }
        else:
            prefix = "uniconn://hosts/"
            suffix = "/facts"
            if uri.startswith(prefix) and uri.endswith(suffix):
                host_name = uri[len(prefix) : -len(suffix)].strip("/")
                if not host_name:
                    raise ValueError(f"Invalid host resource URI: {uri!r}")
                data = await self._tool_gather_facts({"target": host_name})

        if data is None:
            raise KeyError(f"Resource URI not found: {uri!r}")

        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(data, ensure_ascii=False, indent=2),
                }
            ]
        }
